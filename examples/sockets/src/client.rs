use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

fn main() -> std::io::Result<()> {
    println!("[Client] Connecting to 127.0.0.1:8080...");
    
    let mut stream = loop {
        match TcpStream::connect("127.0.0.1:8080") {
            Ok(s) => break s,
            Err(e) => {
                println!("[Client] Waiting for server... ({})", e);
                std::thread::sleep(Duration::from_secs(1));
            }
        }
    };
    
    println!("[Client] Connected to the server! (Using standard POSIX TCP socket)");
    
    let message = "Hello from a WASI Client!";
    stream.write_all(message.as_bytes())?;
    println!("[Client] Message sent: {}", message);
    
    let mut buffer = [0; 1024];
    let bytes_read = stream.read(&mut buffer)?;
    let response = String::from_utf8_lossy(&buffer[..bytes_read]);
    
    println!("[Client] Received reply: {}", response);
    Ok(())
}
