use tokio::io;
use tokio::net::{TcpListener, TcpStream};

static LISTEN_ADDR: &str = "0.0.0.0:5433"; // where clients connect
static BACKEND_ADDR: &str = "127.0.0.1:5432"; // real postgres

#[tokio::main]
async fn main() -> io::Result<()> {
    let listener = TcpListener::bind(LISTEN_ADDR).await?;
    println!("pg proxy listening on {LISTEN_ADDR}, forwarding to {BACKEND_ADDR}");

    loop {
        let (client, addr) = listener.accept().await?;
        println!("new connection from {addr}");

        tokio::spawn(async move {
            if let Err(e) = handle_conn(client).await {
                eprintln!("connection error from {addr}: {e}");
            }
        });
    }
}

async fn handle_conn(mut client: TcpStream) -> io::Result<()> {
    let mut server = TcpStream::connect(BACKEND_ADDR).await?;
    let res = io::copy_bidirectional(&mut client, &mut server).await;
    if let Err(e) = &res {
        eprintln!("copy_bidirectional error: {e}");
    }
    res.map(|_| ())
}
