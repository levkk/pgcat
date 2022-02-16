/// Helper functions to send one-off protocol messages
/// and handle TcpStream (TCP socket).
use bytes::{Buf, BufMut, BytesMut};
use md5::{Digest, Md5};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{
    tcp::{OwnedReadHalf, OwnedWriteHalf},
    TcpStream,
};

use std::collections::HashMap;

use crate::errors::Error;

/// Tell the client that authentication handshake completed successfully.
pub async fn auth_ok(stream: &mut TcpStream) -> Result<(), Error> {
    let mut auth_ok = BytesMut::with_capacity(9);

    auth_ok.put_u8(b'R');
    auth_ok.put_i32(8);
    auth_ok.put_i32(0);

    Ok(write_all(stream, auth_ok).await?)
}

/// Give the client the process_id and secret we generated
/// used in query cancellation.
pub async fn backend_key_data(
    stream: &mut TcpStream,
    backend_id: i32,
    secret_key: i32,
) -> Result<(), Error> {
    let mut key_data = BytesMut::from(&b"K"[..]);
    key_data.put_i32(12);
    key_data.put_i32(backend_id);
    key_data.put_i32(secret_key);

    Ok(write_all(stream, key_data).await?)
}

/// Tell the client we're ready for another query.
pub async fn ready_for_query(stream: &mut TcpStream) -> Result<(), Error> {
    let mut bytes = BytesMut::with_capacity(5);

    bytes.put_u8(b'Z');
    bytes.put_i32(5);
    bytes.put_u8(b'I'); // Idle

    Ok(write_all(stream, bytes).await?)
}

/// Send the startup packet the server. We're pretending we're a Pg client.
/// This tells the server which user we are and what database we want.
pub async fn startup(stream: &mut TcpStream, user: &str, database: &str) -> Result<(), Error> {
    let mut bytes = BytesMut::with_capacity(25);

    bytes.put_i32(196608); // Protocol number

    // User
    bytes.put(&b"user\0"[..]);
    bytes.put_slice(&user.as_bytes());
    bytes.put_u8(0);

    // Database
    bytes.put(&b"database\0"[..]);
    bytes.put_slice(&database.as_bytes());
    bytes.put_u8(0);
    bytes.put_u8(0); // Null terminator

    let len = bytes.len() as i32 + 4i32;

    let mut startup = BytesMut::with_capacity(len as usize);

    startup.put_i32(len);
    startup.put(bytes);

    match stream.write_all(&startup).await {
        Ok(_) => Ok(()),
        Err(_) => return Err(Error::SocketError),
    }
}

/// Parse StartupMessage parameters.
/// e.g. user, database, application_name, etc.
pub fn parse_startup(mut bytes: BytesMut) -> Result<HashMap<String, String>, Error> {
    let mut result = HashMap::new();
    let mut buf = Vec::new();
    let mut tmp = String::new();

    while bytes.has_remaining() {
        let mut c = bytes.get_u8();

        // Null-terminated C-strings.
        while c != 0 {
            tmp.push(c as char);
            c = bytes.get_u8();
        }

        if tmp.len() > 0 {
            buf.push(tmp.clone());
            tmp.clear();
        }
    }

    // Expect pairs of name and value
    // and at least one pair to be present.
    if buf.len() % 2 != 0 && buf.len() >= 2 {
        return Err(Error::ClientBadStartup);
    }

    let mut i = 0;
    while i < buf.len() {
        let name = buf[i].clone();
        let value = buf[i + 1].clone();
        let _ = result.insert(name, value);
        i += 2;
    }

    // Minimum required parameters
    // I want to have the user at the very minimum, according to the protocol spec.
    if !result.contains_key("user") {
        return Err(Error::ClientBadStartup);
    }

    Ok(result)
}

/// Send password challenge response to the server.
/// This is the MD5 challenge.
pub async fn md5_password(
    stream: &mut TcpStream,
    user: &str,
    password: &str,
    salt: &[u8],
) -> Result<(), Error> {
    let mut md5 = Md5::new();

    // First pass
    md5.update(&password.as_bytes());
    md5.update(&user.as_bytes());

    let output = md5.finalize_reset();

    // Second pass
    md5.update(format!("{:x}", output));
    md5.update(salt);

    let mut password = format!("md5{:x}", md5.finalize())
        .chars()
        .map(|x| x as u8)
        .collect::<Vec<u8>>();
    password.push(0);

    let mut message = BytesMut::with_capacity(password.len() as usize + 5);

    message.put_u8(b'p');
    message.put_i32(password.len() as i32 + 4);
    message.put_slice(&password[..]);

    Ok(write_all(stream, message).await?)
}

/// Implements a response to our custom `SET SHARDING KEY`
/// and `SET SERVER ROLE` commands.
/// This tells the client we're ready for the next query.
pub async fn custom_protocol_response_ok(
    stream: &mut OwnedWriteHalf,
    message: &str,
) -> Result<(), Error> {
    let mut res = BytesMut::with_capacity(25);

    let set_complete = BytesMut::from(&format!("{}\0", message)[..]);
    let len = (set_complete.len() + 4) as i32;

    // CommandComplete
    res.put_u8(b'C');
    res.put_i32(len);
    res.put_slice(&set_complete[..]);

    // ReadyForQuery (idle)
    res.put_u8(b'Z');
    res.put_i32(5);
    res.put_u8(b'I');

    write_all_half(stream, res).await
}

/// Pooler is shutting down
/// Codes: https://www.postgresql.org/docs/12/errcodes-appendix.html
///
/// TODO: send this when we are shutting down, i.e. implement Tokio graceful shutdown
/// Docs: https://tokio.rs/tokio/topics/shutdown
#[allow(dead_code)]
pub async fn shutting_down(stream: &mut OwnedWriteHalf) -> Result<(), Error> {
    let mut notice = BytesMut::with_capacity(50);

    notice.put_u8(b'S');
    notice.put_slice(&b"FATAL\0"[..]);
    notice.put_u8(b'V');
    notice.put_slice(&b"FATAL\0"[..]);
    notice.put_u8(b'C');
    notice.put_slice(&b"57P01\0"[..]); // Admin shutdown, see Appendix A.
    notice.put_u8(b'M');
    notice.put_slice(&b"terminating connection due to administrator command"[..]);

    let mut res = BytesMut::with_capacity(notice.len() + 5);
    res.put_u8(b'N');
    res.put_i32(res.len() as i32 + 4);
    res.put(notice);

    Ok(write_all_half(stream, res).await?)
}

/// Write all data in the buffer to the TcpStream.
pub async fn write_all(stream: &mut TcpStream, buf: BytesMut) -> Result<(), Error> {
    match stream.write_all(&buf).await {
        Ok(_) => Ok(()),
        Err(_) => return Err(Error::SocketError),
    }
}

/// Write all the data in the buffer to the TcpStream, write owned half (see mpsc).
pub async fn write_all_half(stream: &mut OwnedWriteHalf, buf: BytesMut) -> Result<(), Error> {
    match stream.write_all(&buf).await {
        Ok(_) => Ok(()),
        Err(_) => return Err(Error::SocketError),
    }
}

/// Read a complete message from the socket.
pub async fn read_message(stream: &mut BufReader<OwnedReadHalf>) -> Result<BytesMut, Error> {
    let code = match stream.read_u8().await {
        Ok(code) => code,
        Err(_) => return Err(Error::SocketError),
    };

    let len = match stream.read_i32().await {
        Ok(len) => len,
        Err(_) => return Err(Error::SocketError),
    };

    let mut buf = vec![0u8; len as usize - 4];

    match stream.read_exact(&mut buf).await {
        Ok(_) => (),
        Err(_) => return Err(Error::SocketError),
    };

    let mut bytes = BytesMut::with_capacity(len as usize + 1);

    bytes.put_u8(code);
    bytes.put_i32(len);
    bytes.put_slice(&buf);

    Ok(bytes)
}
