/// Pooling, failover and banlist.
use async_trait::async_trait;
use bb8::{ManageConnection, Pool, PooledConnection};
use bytes::BytesMut;
use chrono::naive::NaiveDateTime;
use log::{debug, error, info, warn};
use parking_lot::{Mutex, RwLock};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use crate::config::{get_config, Address, Role, User};
use crate::constants::DEFAULT_SEARCH_PATH;
use crate::errors::Error;
use crate::server::Server;
use crate::stats::Reporter;

pub type BanList = Arc<RwLock<Vec<HashMap<Address, NaiveDateTime>>>>;
pub type ClientServerMap = Arc<Mutex<HashMap<(i32, i32), (i32, i32, String, String)>>>;

/// The globally accessible connection pool.
#[derive(Clone, Debug)]
pub struct ConnectionPool {
    databases: Vec<Vec<Pool<ServerPool>>>,
    addresses: Vec<Vec<Address>>,
    round_robin: usize,
    banlist: BanList,
    stats: Reporter,
}

impl ConnectionPool {
    /// Construct the connection pool from the configuration.
    pub async fn from_config(
        client_server_map: ClientServerMap,
        stats: Reporter,
    ) -> ConnectionPool {
        let config = get_config();
        let mut shards = Vec::new();
        let mut addresses = Vec::new();
        let mut banlist = Vec::new();
        let mut address_id = 0;
        let mut shard_ids = config
            .shards
            .clone()
            .into_keys()
            .map(|x| x.to_string())
            .collect::<Vec<String>>();
        shard_ids.sort_by_key(|k| k.parse::<i64>().unwrap());

        for shard_idx in shard_ids {
            let shard = &config.shards[&shard_idx];
            let mut pools = Vec::new();
            let mut servers = Vec::new();
            let mut replica_number = 0;

            for server in shard.servers.iter() {
                let role = match server.2.as_ref() {
                    "primary" => Role::Primary,
                    "replica" => Role::Replica,
                    _ => {
                        error!("Config error: server role can be 'primary' or 'replica', have: '{}'. Defaulting to 'replica'.", server.2);
                        Role::Replica
                    }
                };

                let address = Address {
                    id: address_id,
                    host: server.0.clone(),
                    port: server.1.to_string(),
                    role: role,
                    replica_number,
                    shard: shard_idx.parse::<usize>().unwrap(),
                };

                address_id += 1;

                if role == Role::Replica {
                    replica_number += 1;
                }

                let manager = ServerPool::new(
                    address.clone(),
                    config.user.clone(),
                    &shard.database,
                    &shard.search_path,
                    client_server_map.clone(),
                    stats.clone(),
                );

                let pool = Pool::builder()
                    .max_size(config.general.pool_size)
                    .connection_timeout(std::time::Duration::from_millis(
                        config.general.connect_timeout,
                    ))
                    .test_on_check_out(false)
                    .build(manager)
                    .await
                    .unwrap();

                pools.push(pool);
                servers.push(address);
            }

            shards.push(pools);
            addresses.push(servers);
            banlist.push(HashMap::new());
        }

        assert_eq!(shards.len(), addresses.len());
        let address_len = addresses.len();

        ConnectionPool {
            databases: shards,
            addresses: addresses,
            round_robin: rand::random::<usize>() % address_len, // Start at a random replica
            banlist: Arc::new(RwLock::new(banlist)),
            stats: stats,
        }
    }

    /// Connect to all shards and grab server information.
    /// Return server information we will pass to the clients
    /// when they connect.
    /// This also warms up the pool for clients that connect when
    /// the pooler starts up.
    pub async fn validate(&mut self) -> Result<BytesMut, Error> {
        let mut server_infos = Vec::new();

        let stats = self.stats.clone();
        for shard in 0..self.shards() {
            for _ in 0..self.servers(shard) {
                // To keep stats consistent.
                let fake_process_id = 0;

                let connection = match self.get(shard, None, fake_process_id).await {
                    Ok(conn) => conn,
                    Err(err) => {
                        error!("Shard {} down or misconfigured: {:?}", shard, err);
                        continue;
                    }
                };

                let mut proxy = connection.0;
                let address = connection.1;
                let server = &mut *proxy;

                let server_info = server.server_info();

                stats.client_disconnecting(fake_process_id, address.id);

                if server_infos.len() > 0 {
                    // Compare against the last server checked.
                    if server_info != server_infos[server_infos.len() - 1] {
                        warn!(
                            "{:?} has different server configuration than the last server",
                            address
                        );
                    }
                }

                server_infos.push(server_info);
            }
        }

        // TODO: compare server information to make sure
        // all shards are running identical configurations.
        if server_infos.len() == 0 {
            return Err(Error::AllServersDown);
        }

        Ok(server_infos[0].clone())
    }

    /// Get a connection from the pool.
    pub async fn get(
        &mut self,
        shard: usize,
        role: Option<Role>,
        process_id: i32,
    ) -> Result<(PooledConnection<'_, ServerPool>, Address), Error> {
        let now = Instant::now();
        let addresses = &self.addresses[shard];

        let mut allowed_attempts = match role {
            // Primary-specific queries get one attempt, if the primary is down,
            // nothing we should do about it I think. It's dangerous to retry
            // write queries.
            Some(Role::Primary) => 1,

            // Replicas get to try as many times as there are replicas
            // and connections in the pool.
            _ => addresses.len(),
        };

        debug!("Allowed attempts for {:?}: {}", role, allowed_attempts);

        let exists = match role {
            Some(role) => addresses.iter().filter(|addr| addr.role == role).count() > 0,
            None => true,
        };

        if !exists {
            error!("Requested role {:?}, but none are configured", role);
            return Err(Error::BadConfig);
        }

        while allowed_attempts > 0 {
            // Round-robin replicas.
            self.round_robin += 1;

            let index = self.round_robin % addresses.len();
            let address = &addresses[index];

            // Make sure you're getting a primary or a replica
            // as per request. If no specific role is requested, the first
            // available will be chosen.
            if address.role != role {
                continue;
            }

            allowed_attempts -= 1;

            if self.is_banned(address, shard, role) {
                continue;
            }

            // Indicate we're waiting on a server connection from a pool.
            self.stats.client_waiting(process_id, address.id);

            // Check if we can connect
            let mut conn = match self.databases[shard][index].get().await {
                Ok(conn) => conn,
                Err(err) => {
                    error!("Banning replica {}, error: {:?}", index, err);
                    self.ban(address, shard);
                    self.stats.client_disconnecting(process_id, address.id);
                    self.stats
                        .checkout_time(now.elapsed().as_micros(), process_id, address.id);
                    continue;
                }
            };

            // // Check if this server is alive with a health check.
            let server = &mut *conn;
            let healthcheck_timeout = get_config().general.healthcheck_timeout;

            self.stats.server_tested(server.process_id(), address.id);

            match tokio::time::timeout(
                tokio::time::Duration::from_millis(healthcheck_timeout),
                server.query("SELECT 1"),
            )
            .await
            {
                // Check if health check succeeded.
                Ok(res) => match res {
                    Ok(_) => {
                        // Set search path
                        if server.search_path() != DEFAULT_SEARCH_PATH {
                            server.reset_search_path().await?;
                        }

                        self.stats
                            .checkout_time(now.elapsed().as_micros(), process_id, address.id);
                        self.stats.server_idle(conn.process_id(), address.id);
                        return Ok((conn, address.clone()));
                    }

                    // Health check failed.
                    Err(_) => {
                        error!("Banning replica {} because of failed health check", index);

                        // Don't leave a bad connection in the pool.
                        server.mark_bad();

                        self.ban(address, shard);
                        self.stats.client_disconnecting(process_id, address.id);
                        self.stats
                            .checkout_time(now.elapsed().as_micros(), process_id, address.id);
                        continue;
                    }
                },

                // Health check timed out.
                Err(_) => {
                    error!("Banning replica {} because of health check timeout", index);
                    // Don't leave a bad connection in the pool.
                    server.mark_bad();

                    self.ban(address, shard);
                    self.stats.client_disconnecting(process_id, address.id);
                    self.stats
                        .checkout_time(now.elapsed().as_micros(), process_id, address.id);
                    continue;
                }
            }
        }

        return Err(Error::AllServersDown);
    }

    /// Ban an address (i.e. replica). It no longer will serve
    /// traffic for any new transactions. Existing transactions on that replica
    /// will finish successfully or error out to the clients.
    pub fn ban(&self, address: &Address, shard: usize) {
        error!("Banning {:?}", address);
        let now = chrono::offset::Utc::now().naive_utc();
        let mut guard = self.banlist.write();
        guard[shard].insert(address.clone(), now);
    }

    /// Clear the replica to receive traffic again. Takes effect immediately
    /// for all new transactions.
    pub fn _unban(&self, address: &Address, shard: usize) {
        let mut guard = self.banlist.write();
        guard[shard].remove(address);
    }

    /// Check if a replica can serve traffic. If all replicas are banned,
    /// we unban all of them. Better to try then not to.
    pub fn is_banned(&self, address: &Address, shard: usize, role: Option<Role>) -> bool {
        let replicas_available = match role {
            Some(Role::Replica) => self.addresses[shard]
                .iter()
                .filter(|addr| addr.role == Role::Replica)
                .count(),
            None => self.addresses[shard].len(),
            Some(Role::Primary) => return false, // Primary cannot be banned.
        };

        debug!("Available targets for {:?}: {}", role, replicas_available);

        let guard = self.banlist.read();

        // Everything is banned = nothing is banned.
        if guard[shard].len() == replicas_available {
            drop(guard);
            let mut guard = self.banlist.write();
            guard[shard].clear();
            drop(guard);
            warn!("Unbanning all replicas.");
            return false;
        }

        // I expect this to miss 99.9999% of the time.
        match guard[shard].get(address) {
            Some(timestamp) => {
                let now = chrono::offset::Utc::now().naive_utc();
                let config = get_config();

                // Ban expired.
                if now.timestamp() - timestamp.timestamp() > config.general.ban_time {
                    drop(guard);
                    warn!("Unbanning {:?}", address);
                    let mut guard = self.banlist.write();
                    guard[shard].remove(address);
                    false
                } else {
                    debug!("{:?} is banned", address);
                    true
                }
            }

            None => {
                debug!("{:?} is ok", address);
                false
            }
        }
    }

    /// Get the number of configured shards.
    pub fn shards(&self) -> usize {
        self.databases.len()
    }

    /// Get the number of servers (primary and replicas)
    /// configured for a shard.
    pub fn servers(&self, shard: usize) -> usize {
        self.addresses[shard].len()
    }

    /// Get the total number of servers (databases) we are connected to.
    pub fn databases(&self) -> usize {
        let mut databases = 0;
        for shard in 0..self.shards() {
            databases += self.servers(shard);
        }
        databases
    }

    /// Get pool state for a particular shard server as reported by bb8.
    pub fn pool_state(&self, shard: usize, server: usize) -> bb8::State {
        self.databases[shard][server].state()
    }

    /// Get the address information for a shard server.
    pub fn address(&self, shard: usize, server: usize) -> &Address {
        &self.addresses[shard][server]
    }
}

/// Wrapper for the bb8 connection pool.
pub struct ServerPool {
    address: Address,
    user: User,
    database: String,
    schema: String,
    client_server_map: ClientServerMap,
    stats: Reporter,
}

impl ServerPool {
    pub fn new(
        address: Address,
        user: User,
        database: &str,
        schema: &str,
        client_server_map: ClientServerMap,
        stats: Reporter,
    ) -> ServerPool {
        ServerPool {
            address: address,
            user: user,
            database: database.to_string(),
            schema: schema.to_string(),
            client_server_map: client_server_map,
            stats: stats,
        }
    }
}

#[async_trait]
impl ManageConnection for ServerPool {
    type Connection = Server;
    type Error = Error;

    /// Attempts to create a new connection.
    async fn connect(&self) -> Result<Self::Connection, Self::Error> {
        info!(
            "Creating a new connection to {:?} using user {:?}",
            self.address.name(),
            self.user.name
        );

        // Put a temporary process_id into the stats
        // for server login.
        let process_id = rand::random::<i32>();
        self.stats.server_login(process_id, self.address.id);

        // Connect to the PostgreSQL server.
        match Server::startup(
            &self.address,
            &self.user,
            &self.database,
            &self.schema,
            self.client_server_map.clone(),
            self.stats.clone(),
        )
        .await
        {
            Ok(conn) => {
                // Remove the temporary process_id from the stats.
                self.stats.server_disconnecting(process_id, self.address.id);
                Ok(conn)
            }
            Err(err) => {
                // Remove the temporary process_id from the stats.
                self.stats.server_disconnecting(process_id, self.address.id);
                Err(err)
            }
        }
    }

    /// Determines if the connection is still connected to the database.
    async fn is_valid(&self, _conn: &mut PooledConnection<'_, Self>) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Synchronously determine if the connection is no longer usable, if possible.
    fn has_broken(&self, conn: &mut Self::Connection) -> bool {
        conn.is_bad()
    }
}
