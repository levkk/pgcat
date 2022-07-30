/// Handle clients by pretending to be a PostgreSQL server.
use bytes::{Buf, BufMut, BytesMut};
use log::{debug, error, info, trace};
use std::collections::HashMap;
use tokio::io::{split, AsyncReadExt, BufReader, ReadHalf, WriteHalf};
use tokio::net::TcpStream;

use crate::admin::handle_admin;
use crate::config::get_config;
use crate::constants::*;
use crate::errors::Error;
use crate::messages::*;
use crate::pool::{get_pool, ClientServerMap, ConnectionPool};
use crate::query_router::{Command, QueryRouter};
use crate::server::Server;
use crate::stats::{get_reporter, Reporter};
use crate::tls::Tls;

use tokio_rustls::server::TlsStream;

/// Type of connection received from client.
enum ClientConnectionType {
    Startup,
    Tls,
    CancelQuery,
}

#[derive(Clone, Copy, Debug)]
pub enum ClientRoutingMode {
    Default,
    Reader,
    Writer,
}

/// The client state. One of these is created per client.
pub struct Client<S, T> {
    /// The reads are buffered (8K by default).
    read: BufReader<S>,

    /// We buffer the writes ourselves because we know the protocol
    /// better than a stock buffer.
    write: T,

    /// Internal buffer, where we place messages until we have to flush
    /// them to the backend.
    buffer: BytesMut,

    /// Address
    addr: std::net::SocketAddr,

    /// The client was started with the sole reason to cancel another running query.
    cancel_mode: bool,

    /// In transaction mode, the connection is released after each transaction.
    /// Session mode has slightly higher throughput per client, but lower capacity.
    transaction_mode: bool,

    /// For query cancellation, the client is given a random process ID and secret on startup.
    process_id: i32,
    secret_key: i32,

    /// Clients are mapped to servers while they use them. This allows a client
    /// to connect and cancel a query.
    client_server_map: ClientServerMap,

    /// Client parameters, e.g. user, client_encoding, etc.
    #[allow(dead_code)]
    parameters: HashMap<String, String>,

    /// Statistics
    stats: Reporter,

    /// Clients want to talk to admin database.
    admin: bool,

    /// Last address the client talked to.
    last_address_id: Option<usize>,

    /// Last server process id we talked to.
    last_server_id: Option<i32>,

    target_pool: ConnectionPool,

    routing_mode: ClientRoutingMode,
}

/// Client entrypoint.
pub async fn client_entrypoint(
    mut stream: TcpStream,
    client_server_map: ClientServerMap,
) -> Result<(), Error> {
    // Figure out if the client wants TLS or not.
    let addr = stream.peer_addr().unwrap();

    match get_startup::<TcpStream>(&mut stream).await {
        // Client requested a TLS connection.
        Ok((ClientConnectionType::Tls, _)) => {
            let config = get_config();

            // TLS settings are configured, will setup TLS now.
            if config.general.tls_certificate != None {
                debug!("Accepting TLS request");

                let mut yes = BytesMut::new();
                yes.put_u8(b'S');
                write_all(&mut stream, yes).await?;

                // Negotiate TLS.
                match startup_tls(stream, client_server_map).await {
                    Ok(mut client) => {
                        info!("Client {:?} connected (TLS)", addr);

                        client.handle().await
                    }
                    Err(err) => Err(err),
                }
            }
            // TLS is not configured, we cannot offer it.
            else {
                // Rejecting client request for TLS.
                let mut no = BytesMut::new();
                no.put_u8(b'N');
                write_all(&mut stream, no).await?;

                // Attempting regular startup. Client can disconnect now
                // if they choose.
                match get_startup::<TcpStream>(&mut stream).await {
                    // Client accepted unencrypted connection.
                    Ok((ClientConnectionType::Startup, bytes)) => {
                        let (read, write) = split(stream);

                        // Continue with regular startup.
                        match Client::startup(read, write, addr, bytes, client_server_map).await {
                            Ok(mut client) => {
                                info!("Client {:?} connected (plain)", addr);

                                client.handle().await
                            }
                            Err(err) => Err(err),
                        }
                    }

                    // Client probably disconnected rejecting our plain text connection.
                    _ => Err(Error::ProtocolSyncError),
                }
            }
        }

        // Client wants to use plain connection without encryption.
        Ok((ClientConnectionType::Startup, bytes)) => {
            let (read, write) = split(stream);

            // Continue with regular startup.
            match Client::startup(read, write, addr, bytes, client_server_map).await {
                Ok(mut client) => {
                    info!("Client {:?} connected (plain)", addr);

                    client.handle().await
                }
                Err(err) => Err(err),
            }
        }

        // Client wants to cancel a query.
        Ok((ClientConnectionType::CancelQuery, bytes)) => {
            let (read, write) = split(stream);

            // Continue with cancel query request.
            match Client::cancel(read, write, addr, bytes, client_server_map).await {
                Ok(mut client) => {
                    info!("Client {:?} issued a cancel query request", addr);

                    client.handle().await
                }

                Err(err) => Err(err),
            }
        }

        // Something failed, probably the socket.
        Err(err) => Err(err),
    }
}

/// Handle the first message the client sends.
async fn get_startup<S>(stream: &mut S) -> Result<(ClientConnectionType, BytesMut), Error>
where
    S: tokio::io::AsyncRead + std::marker::Unpin + tokio::io::AsyncWrite,
{
    // Get startup message length.
    let len = match stream.read_i32().await {
        Ok(len) => len,
        Err(_) => return Err(Error::ClientBadStartup),
    };

    // Get the rest of the message.
    let mut startup = vec![0u8; len as usize - 4];
    match stream.read_exact(&mut startup).await {
        Ok(_) => (),
        Err(_) => return Err(Error::ClientBadStartup),
    };

    let mut bytes = BytesMut::from(&startup[..]);
    let code = bytes.get_i32();

    match code {
        // Client is requesting SSL (TLS).
        SSL_REQUEST_CODE => Ok((ClientConnectionType::Tls, bytes)),

        // Client wants to use plain text, requesting regular startup.
        PROTOCOL_VERSION_NUMBER => Ok((ClientConnectionType::Startup, bytes)),

        // Client is requesting to cancel a running query (plain text connection).
        CANCEL_REQUEST_CODE => Ok((ClientConnectionType::CancelQuery, bytes)),

        // Something else, probably something is wrong and it's not our fault,
        // e.g. badly implemented Postgres client.
        _ => Err(Error::ProtocolSyncError),
    }
}

/// Handle TLS connection negotation.
pub async fn startup_tls(
    stream: TcpStream,
    client_server_map: ClientServerMap,
) -> Result<Client<ReadHalf<TlsStream<TcpStream>>, WriteHalf<TlsStream<TcpStream>>>, Error> {
    // Negotiate TLS.
    let tls = Tls::new()?;
    let addr = stream.peer_addr().unwrap();

    let mut stream = match tls.acceptor.accept(stream).await {
        Ok(stream) => stream,

        // TLS negotitation failed.
        Err(err) => {
            error!("TLS negotiation failed: {:?}", err);
            return Err(Error::TlsError);
        }
    };

    // TLS negotitation successful.
    // Continue with regular startup using encrypted connection.
    match get_startup::<TlsStream<TcpStream>>(&mut stream).await {
        // Got good startup message, proceeding like normal except we
        // are encrypted now.
        Ok((ClientConnectionType::Startup, bytes)) => {
            let (read, write) = split(stream);

            Client::startup(read, write, addr, bytes, client_server_map).await
        }

        // Bad Postgres client.
        _ => Err(Error::ProtocolSyncError),
    }
}

impl<S, T> Client<S, T>
where
    S: tokio::io::AsyncRead + std::marker::Unpin,
    T: tokio::io::AsyncWrite + std::marker::Unpin,
{
    /// Handle Postgres client startup after TLS negotiation is complete
    /// or over plain text.
    pub async fn startup(
        mut read: S,
        mut write: T,
        addr: std::net::SocketAddr,
        bytes: BytesMut, // The rest of the startup message.
        client_server_map: ClientServerMap,
    ) -> Result<Client<S, T>, Error> {
        let config = get_config();
        let stats = get_reporter();

        trace!("Got StartupMessage");
        let parameters = parse_startup(bytes.clone())?;

        let database_param = match parameters.get("database") {
            Some(db) => db,
            None => return Err(Error::ClientError),
        };
        let database_name_parts = database_param.split("/").collect::<Vec<&str>>();
        let (database_name, routing_mode) = match database_name_parts.len() {
            1 => (
                database_name_parts[0].to_string(),
                ClientRoutingMode::Default,
            ),
            2 => match database_name_parts[1] {
                "reader" => {
                    info!("Client connected in force reader mode");
                    (
                        database_name_parts[0].to_string(),
                        ClientRoutingMode::Reader,
                    )
                }
                "writer" => {
                    info!("Client connected in force writer mode");
                    (
                        database_name_parts[0].to_string(),
                        ClientRoutingMode::Writer,
                    )
                }
                _ => {
                    error_response(
                        &mut write,
                        &format!("Invalid database mode {}", database_name_parts[1]),
                    )
                    .await?;
                    return Err(Error::ClientError);
                }
            },
            _ => {
                error_response(
                    &mut write,
                    &format!("Invalid database name {}", database_param),
                )
                .await?;
                return Err(Error::ClientError);
            }
        };

        let user = match parameters.get("user") {
            Some(user) => user,
            None => return Err(Error::ClientError),
        };

        let admin = ["pgcat", "pgbouncer"]
            .iter()
            .filter(|db| *db == &database_name)
            .count()
            == 1;

        // Generate random backend ID and secret key
        let process_id: i32 = rand::random();
        let secret_key: i32 = rand::random();

        // Perform MD5 authentication.
        // TODO: Add SASL support.
        let salt = md5_challenge(&mut write).await?;

        let code = match read.read_u8().await {
            Ok(p) => p,
            Err(_) => return Err(Error::SocketError),
        };

        // PasswordMessage
        if code as char != 'p' {
            debug!("Expected p, got {}", code as char);
            return Err(Error::ProtocolSyncError);
        }

        let len = match read.read_i32().await {
            Ok(len) => len,
            Err(_) => return Err(Error::SocketError),
        };

        let mut password_response = vec![0u8; (len - 4) as usize];

        match read.read_exact(&mut password_response).await {
            Ok(_) => (),
            Err(_) => return Err(Error::SocketError),
        };

        let mut target_pool: ConnectionPool = ConnectionPool::default();
        let mut transaction_mode = false;

        if admin {
            let correct_user = config.general.admin_username.as_str();
            let correct_password = config.general.admin_password.as_str();

            // Compare server and client hashes.
            let password_hash = md5_hash_password(correct_user, correct_password, &salt);
            if password_hash != password_response {
                debug!("Password authentication failed");
                wrong_password(&mut write, user).await?;
                return Err(Error::ClientError);
            }
        } else {
            target_pool = match get_pool(database_name.clone(), user.clone()) {
                Some(pool) => pool,
                None => {
                    error_response(
                        &mut write,
                        &format!(
                            "No pool configured for database: {:?}, user: {:?}",
                            database_name, user
                        ),
                    )
                    .await?;
                    return Err(Error::ClientError);
                }
            };
            transaction_mode = target_pool.settings.pool_mode == "transaction";

            // Compare server and client hashes.
            let correct_password = target_pool.settings.user.password.as_str();
            let password_hash = md5_hash_password(user, correct_password, &salt);

            if password_hash != password_response {
                debug!("Password authentication failed");
                wrong_password(&mut write, user).await?;
                return Err(Error::ClientError);
            }
        }

        debug!("Password authentication successful");

        auth_ok(&mut write).await?;
        write_all(&mut write, target_pool.server_info()).await?;
        backend_key_data(&mut write, process_id, secret_key).await?;
        ready_for_query(&mut write).await?;

        trace!("Startup OK");

        // Split the read and write streams
        // so we can control buffering.

        return Ok(Client {
            read: BufReader::new(read),
            write: write,
            addr,
            buffer: BytesMut::with_capacity(8196),
            cancel_mode: false,
            transaction_mode: transaction_mode,
            routing_mode: routing_mode,
            process_id: process_id,
            secret_key: secret_key,
            client_server_map: client_server_map,
            parameters: parameters.clone(),
            stats: stats,
            admin: admin,
            last_address_id: None,
            last_server_id: None,
            target_pool: target_pool,
        });
    }

    /// Handle cancel request.
    pub async fn cancel(
        read: S,
        write: T,
        addr: std::net::SocketAddr,
        mut bytes: BytesMut, // The rest of the startup message.
        client_server_map: ClientServerMap,
    ) -> Result<Client<S, T>, Error> {
        let process_id = bytes.get_i32();
        let secret_key = bytes.get_i32();
        return Ok(Client {
            read: BufReader::new(read),
            write: write,
            addr,
            buffer: BytesMut::with_capacity(8196),
            cancel_mode: true,
            transaction_mode: false,
            routing_mode: ClientRoutingMode::Default,
            process_id: process_id,
            secret_key: secret_key,
            client_server_map: client_server_map,
            parameters: HashMap::new(),
            stats: get_reporter(),
            admin: false,
            last_address_id: None,
            last_server_id: None,
            target_pool: ConnectionPool::default(),
        });
    }

    /// Handle a connected and authenticated client.
    pub async fn handle(&mut self) -> Result<(), Error> {
        // The client wants to cancel a query it has issued previously.
        if self.cancel_mode {
            trace!("Sending CancelRequest");

            let (process_id, secret_key, address, port) = {
                let guard = self.client_server_map.lock();

                match guard.get(&(self.process_id, self.secret_key)) {
                    // Drop the mutex as soon as possible.
                    // We found the server the client is using for its query
                    // that it wants to cancel.
                    Some((process_id, secret_key, address, port)) => (
                        process_id.clone(),
                        secret_key.clone(),
                        address.clone(),
                        port.clone(),
                    ),

                    // The client doesn't know / got the wrong server,
                    // we're closing the connection for security reasons.
                    None => return Ok(()),
                }
            };

            // Opens a new separate connection to the server, sends the backend_id
            // and secret_key and then closes it for security reasons. No other interactions
            // take place.
            return Ok(Server::cancel(&address, &port, process_id, secret_key).await?);
        }

        // The query router determines where the query is going to go,
        // e.g. primary, replica, which shard.
        let mut query_router =
            QueryRouter::new(self.target_pool.clone(), self.routing_mode.clone());

        let mut round_robin = 0;

        // Our custom protocol loop.
        // We expect the client to either start a transaction with regular queries
        // or issue commands for our sharding and server selection protocol.
        loop {
            trace!(
                "Client idle, waiting for message, transaction mode: {}",
                self.transaction_mode
            );

            // Read a complete message from the client, which normally would be
            // either a `Q` (query) or `P` (prepare, extended protocol).
            // We can parse it here before grabbing a server from the pool,
            // in case the client is sending some custom protocol messages, e.g.
            // SET SHARDING KEY TO 'bigint';
            let mut message = read_message(&mut self.read).await?;

            // Get a pool instance referenced by the most up-to-date
            // pointer. This ensures we always read the latest config
            // when starting a query.
            let mut pool = self.target_pool.clone();

            // Avoid taking a server if the client just wants to disconnect.
            if message[0] as char == 'X' {
                debug!("Client disconnecting");
                return Ok(());
            }

            // Handle admin database queries.
            if self.admin {
                debug!("Handling admin command");
                handle_admin(&mut self.write, message, self.client_server_map.clone()).await?;
                continue;
            }

            let current_shard = query_router.shard();

            // Handle all custom protocol commands, if any.
            match query_router.try_execute_command(message.clone()) {
                // Normal query, not a custom command.
                None => {
                    if query_router.query_parser_enabled() {
                        query_router.infer_role(message.clone());
                    }
                }

                // SET SHARD TO
                Some((Command::SetShard, _)) => {
                    // Selected shard is not configured.
                    if query_router.shard() >= pool.shards() {
                        // Set the shard back to what it was.
                        query_router.set_shard(current_shard);

                        error_response(
                            &mut self.write,
                            &format!(
                                "shard {} is more than configured {}, staying on shard {}",
                                query_router.shard(),
                                pool.shards(),
                                current_shard,
                            ),
                        )
                        .await?;
                    } else {
                        custom_protocol_response_ok(&mut self.write, "SET SHARD").await?;
                    }
                    continue;
                }

                // SET PRIMARY READS TO
                Some((Command::SetPrimaryReads, _)) => {
                    custom_protocol_response_ok(&mut self.write, "SET PRIMARY READS").await?;
                    continue;
                }

                // SET SHARDING KEY TO
                Some((Command::SetShardingKey, _)) => {
                    custom_protocol_response_ok(&mut self.write, "SET SHARDING KEY").await?;
                    continue;
                }

                // SET SERVER ROLE TO
                Some((Command::SetServerRole, _)) => {
                    custom_protocol_response_ok(&mut self.write, "SET SERVER ROLE").await?;
                    continue;
                }

                // SHOW SERVER ROLE
                Some((Command::ShowServerRole, value)) => {
                    show_response(&mut self.write, "server role", &value).await?;
                    continue;
                }

                // SHOW SHARD
                Some((Command::ShowShard, value)) => {
                    show_response(&mut self.write, "shard", &value).await?;
                    continue;
                }

                // SHOW PRIMARY READS
                Some((Command::ShowPrimaryReads, value)) => {
                    show_response(&mut self.write, "primary reads", &value).await?;
                    continue;
                }
            };

            debug!("Waiting for connection from pool");

            // Grab a server from the pool.
            let connection = match pool
                .get(
                    query_router.shard(),
                    query_router.role(),
                    self.process_id,
                    round_robin,
                )
                .await
            {
                Ok(conn) => {
                    debug!("Got connection from pool");
                    conn
                }
                Err(err) => {
                    error!("Could not get connection from pool: {:?}", err);
                    error_response(&mut self.write, "could not get connection from the pool")
                        .await?;
                    continue;
                }
            };

            let mut reference = connection.0;
            let address = connection.1;
            let server = &mut *reference;

            round_robin += 1;

            // Server is assigned to the client in case the client wants to
            // cancel a query later.
            server.claim(self.process_id, self.secret_key);

            // Update statistics.
            if let Some(last_address_id) = self.last_address_id {
                self.stats
                    .client_disconnecting(self.process_id, last_address_id);
            }
            self.stats.client_active(self.process_id, address.id);
            self.stats.server_active(server.process_id(), address.id);

            self.last_address_id = Some(address.id);
            self.last_server_id = Some(server.process_id());

            debug!(
                "Client {:?} talking to server {:?}",
                self.addr,
                server.address()
            );

            // Set application_name if any.
            // TODO: investigate other parameters and set them too.
            if self.parameters.contains_key("application_name") {
                server
                    .set_name(&self.parameters["application_name"])
                    .await?;
            }

            // Transaction loop. Multiple queries can be issued by the client here.
            // The connection belongs to the client until the transaction is over,
            // or until the client disconnects if we are in session mode.
            //
            // If the client is in session mode, no more custom protocol
            // commands will be accepted.
            loop {
                let mut message = if message.len() == 0 {
                    trace!("Waiting for message inside transaction or in session mode");

                    match read_message(&mut self.read).await {
                        Ok(message) => message,
                        Err(err) => {
                            // Client disconnected inside a transaction.
                            // Clean up the server and re-use it.
                            // This prevents connection thrashing by bad clients.
                            if server.in_transaction() {
                                server.query("ROLLBACK").await?;
                                server.query("DISCARD ALL").await?;
                                server.set_name("pgcat").await?;
                            }

                            return Err(err);
                        }
                    }
                } else {
                    let msg = message.clone();
                    message.clear();
                    msg
                };

                // The message will be forwarded to the server intact. We still would like to
                // parse it below to figure out what to do with it.
                let original = message.clone();

                let code = message.get_u8() as char;
                let _len = message.get_i32() as usize;

                trace!("Message: {}", code);

                match code {
                    // ReadyForQuery
                    'Q' => {
                        debug!("Sending query to server");

                        server.send(original).await?;

                        // Read all data the server has to offer, which can be multiple messages
                        // buffered in 8196 bytes chunks.
                        loop {
                            let response = server.recv().await?;

                            // Send server reply to the client.
                            match write_all_half(&mut self.write, response).await {
                                Ok(_) => (),
                                Err(err) => {
                                    server.mark_bad();
                                    return Err(err);
                                }
                            };

                            if !server.is_data_available() {
                                break;
                            }
                        }

                        // Report query executed statistics.
                        self.stats.query(self.process_id, address.id);

                        if !server.in_transaction() {
                            // Report transaction executed statistics.
                            self.stats.transaction(self.process_id, address.id);

                            // Release server back to the pool if we are in transaction mode.
                            // If we are in session mode, we keep the server until the client disconnects.
                            if self.transaction_mode {
                                self.stats.server_idle(server.process_id(), address.id);
                                break;
                            }
                        }
                    }

                    // Terminate
                    'X' => {
                        // Client closing. Rollback and clean up
                        // connection before releasing into the pool.
                        // Pgbouncer closes the connection which leads to
                        // connection thrashing when clients misbehave.
                        if server.in_transaction() {
                            server.query("ROLLBACK").await?;
                            server.query("DISCARD ALL").await?;
                            server.set_name("pgcat").await?;
                        }

                        self.release();

                        return Ok(());
                    }

                    // Parse
                    // The query with placeholders is here, e.g. `SELECT * FROM users WHERE email = $1 AND active = $2`.
                    'P' => {
                        self.buffer.put(&original[..]);
                    }

                    // Bind
                    // The placeholder's replacements are here, e.g. 'user@email.com' and 'true'
                    'B' => {
                        self.buffer.put(&original[..]);
                    }

                    // Describe
                    // Command a client can issue to describe a previously prepared named statement.
                    'D' => {
                        self.buffer.put(&original[..]);
                    }

                    // Execute
                    // Execute a prepared statement prepared in `P` and bound in `B`.
                    'E' => {
                        self.buffer.put(&original[..]);
                    }

                    // Sync
                    // Frontend (client) is asking for the query result now.
                    'S' => {
                        debug!("Sending query to server");

                        self.buffer.put(&original[..]);

                        server.send(self.buffer.clone()).await?;

                        self.buffer.clear();

                        // Read all data the server has to offer, which can be multiple messages
                        // buffered in 8196 bytes chunks.
                        loop {
                            let response = server.recv().await?;

                            match write_all_half(&mut self.write, response).await {
                                Ok(_) => (),
                                Err(err) => {
                                    server.mark_bad();
                                    return Err(err);
                                }
                            };

                            if !server.is_data_available() {
                                break;
                            }
                        }

                        // Report query executed statistics.
                        self.stats.query(self.process_id, address.id);

                        if !server.in_transaction() {
                            self.stats.transaction(self.process_id, address.id);

                            // Release server back to the pool if we are in transaction mode.
                            // If we are in session mode, we keep the server until the client disconnects.
                            if self.transaction_mode {
                                self.stats.server_idle(server.process_id(), address.id);
                                break;
                            }
                        }
                    }

                    // CopyData
                    'd' => {
                        // Forward the data to the server,
                        // don't buffer it since it can be rather large.
                        server.send(original).await?;
                    }

                    // CopyDone or CopyFail
                    // Copy is done, successfully or not.
                    'c' | 'f' => {
                        server.send(original).await?;

                        let response = server.recv().await?;

                        match write_all_half(&mut self.write, response).await {
                            Ok(_) => (),
                            Err(err) => {
                                server.mark_bad();
                                return Err(err);
                            }
                        };

                        if !server.in_transaction() {
                            self.stats.transaction(self.process_id, address.id);

                            // Release server back to the pool if we are in transaction mode.
                            // If we are in session mode, we keep the server until the client disconnects.
                            if self.transaction_mode {
                                self.stats.server_idle(server.process_id(), address.id);
                                break;
                            }
                        }
                    }

                    // Some unexpected message. We either did not implement the protocol correctly
                    // or this is not a Postgres client we're talking to.
                    _ => {
                        error!("Unexpected code: {}", code);
                    }
                }
            }

            // The server is no longer bound to us, we can't cancel it's queries anymore.
            debug!("Releasing server back into the pool");
            self.release();
            self.stats.client_idle(self.process_id, address.id);
        }
    }

    /// Release the server from the client: it can't cancel its queries anymore.
    pub fn release(&self) {
        let mut guard = self.client_server_map.lock();
        guard.remove(&(self.process_id, self.secret_key));
    }
}

impl<S, T> Drop for Client<S, T> {
    fn drop(&mut self) {
        let mut guard = self.client_server_map.lock();
        guard.remove(&(self.process_id, self.secret_key));

        // Update statistics.
        if let Some(address_id) = self.last_address_id {
            self.stats.client_disconnecting(self.process_id, address_id);

            if let Some(process_id) = self.last_server_id {
                self.stats.server_idle(process_id, address_id);
            }
        }

        // self.release();
    }
}
