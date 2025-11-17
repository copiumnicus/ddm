use std::collections::HashSet;
use std::io::ErrorKind;

use tokio::io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const LISTEN_ADDR: &str = "0.0.0.0:5433"; // where clients connect
const BACKEND_ADDR: &str = "127.0.0.1:5432"; // real postgres

/// application_name=init_voucher; (strip app_name in msg, set to 'psql')
/// set voucher = next_voucher; (strip set from sql, update voucher)
#[tokio::main]
async fn main() -> io::Result<()> {
    let listener = TcpListener::bind(LISTEN_ADDR).await?;
    println!("pg proxy listening on {LISTEN_ADDR}, forwarding to {BACKEND_ADDR}");

    loop {
        let (client, addr) = listener.accept().await?;
        println!("new connection from {addr}");

        tokio::spawn(async move {
            if let Err(e) = handle_conn2(client).await {
                eprintln!("connection from {addr} ended with error: {e}");
            }
        });
    }
}

async fn handle_conn2(mut client: TcpStream) -> io::Result<()> {
    let mut server = TcpStream::connect(BACKEND_ADDR).await?;
    println!("connected to backend {BACKEND_ADDR}");
    logged_copy_bidirectional(client, server).await?;
    Ok(())
}

mod startup {
    use std::io::{self, ErrorKind};
    /// Parse a PostgreSQL StartupMessage from `buf[..n]`.
    /// Returns (protocol_version, Vec<(key, value)>).
    ///
    /// StartupMessage wire format:
    ///   Int32 length                (includes this Int32, excludes no type byte)
    ///   Int32 protocol_version      (usually 0x00030000)
    ///   key\0value\0...key\0value\0\0
    ///
    /// NOTE: StartupMessage has *no* type byte.
    pub fn parse_startup_message(
        buf: &[u8],
        n: usize,
    ) -> Result<(u32, Vec<(String, String)>), io::Error> {
        use std::io::Error;
        if n < 8 {
            return Err(Error::new(ErrorKind::Other, "startup message too short"));
        }

        // --- Decode message length ---
        let len = u32::from_be_bytes(buf[0..4].try_into().unwrap());
        if len as usize != n {
            return Err(Error::new(
                ErrorKind::Other,
                format!("startup length mismatch: header says {len}, got {n} bytes"),
            ));
        }

        // --- Decode protocol version ---
        let protocol = u32::from_be_bytes(buf[4..8].try_into().unwrap());

        // --- Parse key/value pairs ---
        let mut params = Vec::new();
        let mut i = 8; // skip length + protocol

        while i < n {
            // find key (null-terminated)
            let key_start = i;
            while i < n && buf[i] != 0 {
                i += 1;
            }
            if i >= n {
                return Err(Error::new(ErrorKind::Other, "unterminated key"));
            }

            // empty key means terminator
            if i == key_start {
                break;
            }

            let key = String::from_utf8_lossy(&buf[key_start..i]).to_string();
            i += 1; // skip NUL

            // find value
            let val_start = i;
            while i < n && buf[i] != 0 {
                i += 1;
            }
            if i >= n {
                return Err(Error::new(ErrorKind::Other, "unterminated value"));
            }

            let val = String::from_utf8_lossy(&buf[val_start..i]).to_string();
            i += 1; // skip NUL

            params.push((key, val));
        }

        Ok((protocol, params))
    }
    /// Build a PostgreSQL StartupMessage from:
    ///   - protocol_version (usually 0x00030000)
    ///   - list of (key, value) pairs
    ///
    /// Returns a Vec<u8> ready to send over TCP.
    /// This message has *no* type byte; the first field is Int32 length.
    pub fn build_startup_message(protocol_version: u32, params: &[(String, String)]) -> Vec<u8> {
        let mut body = Vec::new();

        // protocol version
        body.extend_from_slice(&protocol_version.to_be_bytes());

        // key/value pairs
        for (k, v) in params {
            body.extend_from_slice(k.as_bytes());
            body.push(0);
            body.extend_from_slice(v.as_bytes());
            body.push(0);
        }

        // terminator
        body.push(0);

        // length = body.len() + 4 (for length field itself)
        let total_len = (body.len() + 4) as u32;

        let mut msg = Vec::with_capacity(body.len() + 4);
        msg.extend_from_slice(&total_len.to_be_bytes());
        msg.extend_from_slice(&body);

        msg
    }
}

/// Pumps bytes both ways with logging.
/// Returns (bytes_client_to_server, bytes_server_to_client).
pub async fn logged_copy_bidirectional(
    mut client: TcpStream,
    mut server: TcpStream,
) -> io::Result<(u64, u64)> {
    let (mut cr, mut cw) = tokio::io::split(client); // client read/write
    let (mut sr, mut sw) = tokio::io::split(server); // server read/write

    let c2s = {
        let mut buf = [0u8; 8192];
        // read startup msg
        let n = cr.read(&mut buf).await?;
        let (pver, kv) = startup::parse_startup_message(&buf, n)?;
        println!("client sent '{} {:?}'", pver, kv);

        sw.write_all(&buf[..n]).await?;

        // ---- TASK: client → server ----
        tokio::spawn(async move {
            let mut total = 0u64;

            loop {
                let n = match cr.read(&mut buf).await {
                    Ok(0) => break, // client closed
                    Ok(n) => n,
                    Err(e) => return Err(e),
                };

                // LOG BYTES SENT FROM CLIENT
                println!(
                    "CLIENT → SERVER  ({} bytes): {:02x?}",
                    n,
                    &String::from_utf8_lossy(&buf[..n])
                );

                total += n as u64;

                sw.write_all(&buf[..n]).await?;
            }

            let _ = sw.shutdown().await;
            Ok(total)
        })
    };

    // ---- TASK: server → client ----
    let s2c = tokio::spawn(async move {
        let mut buf = [0u8; 8192];
        let mut total = 0u64;

        loop {
            let n = match sr.read(&mut buf).await {
                Ok(0) => break, // server closed
                Ok(n) => n,
                Err(e) => return Err(e),
            };

            // LOG BYTES SENT FROM SERVER
            println!(
                "SERVER → CLIENT  ({} bytes): {:02x?}",
                n,
                &String::from_utf8_lossy(&buf[..n])
            );

            total += n as u64;

            cw.write_all(&buf[..n]).await?;
        }

        let _ = cw.shutdown().await;
        Ok(total)
    });

    // Wait for both directions
    let c2s_res = c2s.await.unwrap()?;
    let s2c_res = s2c.await.unwrap()?;

    Ok((c2s_res, s2c_res))
}
