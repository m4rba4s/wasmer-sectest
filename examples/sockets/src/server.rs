use std::io::{Read, Write};
use std::net::TcpListener;

fn main() -> std::io::Result<()> {
    println!("[Server] Starting on 127.0.0.1:8080...");
    let listener = TcpListener::bind("127.0.0.1:8080")?;
    println!("[Server] Listening for incoming connections (POSIX sockets inside WASM)!");

    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                println!("[Server] New client connected: {:?}", stream.peer_addr()?);
                
                let mut buffer = [0; 1024];
                let bytes_read = stream.read(&mut buffer)?;
                let message = String::from_utf8_lossy(&buffer[..bytes_read]);
                println!("[Server] Received message: {}", message.trim());
                
                let response = format!("ACK: Received '{}'", message.trim());
                stream.write_all(response.as_bytes())?;
                println!("[Server] Response sent.\n");
            }
            Err(e) => {
                eprintln!("[Server] Connection failed: {}", e);
            }
        }
    }
    Ok(())
}
