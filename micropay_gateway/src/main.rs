use tokio::io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const LISTEN_ADDR: &str = "0.0.0.0:5433"; // where clients connect
const BACKEND_ADDR: &str = "127.0.0.1:5432"; // real postgres

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

async fn handle_conn(mut client: TcpStream) -> io::Result<()> {
    // ---- 1) Read startup packet from client ----
    let mut len_buf = [0u8; 4];
    client.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf);

    if len < 8 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("startup length too small: {len}"),
        ));
    }

    let body_len = len - 4;
    let mut body = vec![0u8; body_len as usize];
    client.read_exact(&mut body).await?;

    // ---- 2) Parse protocol + params (StartupMessage) ----
    let protocol = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
    println!("startup protocol: 0x{protocol:08x}");

    // If you accidentally have SSL on, you'll see this magic:
    // 0x04d2162f (80877103) which is SSLRequest.
    if protocol == 0x04d2162f {
        println!("SSLRequest detected. This simple proxy assumes sslmode=disable.");
        // For now, just bail out nicely:
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "SSLRequest not supported in this minimal proxy (use sslmode=disable)",
        ));
    }

    // parse key\0value\0 pairs
    // ex:
    // user\0testuser\0
    // database\0testdb\0
    // application_name\0psql\0
    // client_encoding\0UTF8\0
    // \0

    let mut params = Vec::new();
    let mut i = 4; // we already consumed protocol (first 4 bytes of body)
    while i < body.len() {
        // key
        let key_start = i;
        while i < body.len() && body[i] != 0 {
            i += 1;
        }
        if i == key_start {
            // empty key -> terminator
            break;
        }
        let key = String::from_utf8_lossy(&body[key_start..i]).into_owned();
        i += 1; // skip null

        // value
        let val_start = i;
        while i < body.len() && body[i] != 0 {
            i += 1;
        }
        let value = String::from_utf8_lossy(&body[val_start..i]).into_owned();
        i += 1; // skip null

        params.push((key, value));
    }

    println!("startup params:");
    for (k, v) in &params {
        println!("  {k} = {v}");
    }

    // ----- here is where you'd later inspect/gate on user/app_name/voucher ----
    // e.g. find application_name, parse voucher prefix, etc.

    // ---- 3) Connect to real Postgres ----
    let mut server = TcpStream::connect(BACKEND_ADDR).await?;
    println!("connected to backend {BACKEND_ADDR}");

    // ---- 4) Forward the same startup packet to Postgres ----
    server.write_all(&len_buf).await?;
    server.write_all(&body).await?;
    server.flush().await?;

    // ---- 5) From here on: just raw bidirectional forwarding ----
    let (bytes_c2s, bytes_s2c) = io::copy_bidirectional(&mut client, &mut server).await?;
    println!("connection closed, bytes client->server: {bytes_c2s}, server->client: {bytes_s2c}");

    Ok(())
}

async fn handle_conn2(mut client: TcpStream) -> io::Result<()> {
    let mut server = TcpStream::connect(BACKEND_ADDR).await?;
    println!("connected to backend {BACKEND_ADDR}");
    logged_copy_bidirectional(client, server).await?;
    Ok(())
}

/// Pumps bytes both ways with logging.
/// Returns (bytes_client_to_server, bytes_server_to_client).
pub async fn logged_copy_bidirectional(
    mut client: TcpStream,
    mut server: TcpStream,
) -> io::Result<(u64, u64)> {
    let (mut cr, mut cw) = tokio::io::split(client); // client read/write
    let (mut sr, mut sw) = tokio::io::split(server); // server read/write

    let mut c2s_bytes = 0u64;
    let mut s2c_bytes = 0u64;

    // ---- TASK: client → server ----
    let c2s = tokio::spawn(async move {
        let mut buf = [0u8; 8192];
        let mut total = 0u64;

        loop {
            let n = match cr.read(&mut buf).await {
                Ok(0) => break, // client closed
                Ok(n) => n,
                Err(e) => return Err(e),
            };

            // LOG BYTES SENT FROM CLIENT
            println!("CLIENT → SERVER  ({} bytes): {:02x?}", n, &buf[..n]);

            total += n as u64;

            if let Err(e) = sw.write_all(&buf[..n]).await {
                return Err(e);
            }
        }

        let _ = sw.shutdown().await;
        Ok(total)
    });

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
            println!("SERVER → CLIENT  ({} bytes): {:02x?}", n, &buf[..n]);

            total += n as u64;

            if let Err(e) = cw.write_all(&buf[..n]).await {
                return Err(e);
            }
        }

        let _ = cw.shutdown().await;
        Ok(total)
    });

    // Wait for both directions
    let c2s_res = c2s.await.unwrap()?;
    let s2c_res = s2c.await.unwrap()?;

    Ok((c2s_res, s2c_res))
}
