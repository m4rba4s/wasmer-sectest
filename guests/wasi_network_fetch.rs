use std::process::ExitCode;

const HOST: &str = "jsonplaceholder.typicode.com";
const PATH: &str = "/users/1";
const PORT: u16 = 80;

const ERRNO_SUCCESS: u16 = 0;
const ADDRESS_FAMILY_INET4: u32 = 1;
const SOCK_TYPE_STREAM: u32 = 1;
const SOCK_PROTO_TCP: u32 = 6;

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Ciovec {
    buf: u32,
    buf_len: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Iovec {
    buf: u32,
    buf_len: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct WasiAddr {
    tag: u8,
    padding: u8,
    octs: [u8; 16],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct WasiAddrPort {
    tag: u8,
    padding: u8,
    octs: [u8; 18],
}

#[link(wasm_import_module = "wasix_32v1")]
unsafe extern "C" {
    fn resolve(
        host: *const u8,
        host_len: u32,
        port: u16,
        addrs: *mut WasiAddr,
        naddrs: u32,
        ret_naddrs: *mut u32,
    ) -> u16;
    fn sock_open(af: u32, ty: u32, pt: u32, ro_sock: *mut u32) -> u16;
    fn sock_connect(sock: u32, addr: *const WasiAddrPort) -> u16;
    fn sock_send(
        sock: u32,
        si_data: *const Ciovec,
        si_data_len: u32,
        si_flags: u16,
        ret_data_len: *mut u32,
    ) -> u16;
    fn sock_recv(
        sock: u32,
        ri_data: *const Iovec,
        ri_data_len: u32,
        ri_flags: u16,
        ro_data_len: *mut u32,
        ro_flags: *mut u16,
    ) -> u16;
}

fn main() -> ExitCode {
    match run() {
        Ok(response) => {
            println!("{response}");
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("wasi network demo failed: {err}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<String, String> {
    let peer = resolve_host(HOST, PORT)?;
    let sock = open_tcp_socket()?;
    connect(sock, peer)?;

    let request = format!("GET {PATH} HTTP/1.1\r\nHost: {HOST}\r\nConnection: close\r\n\r\n");
    send_all(sock, request.as_bytes())?;
    let response = recv_http_response(sock)?;

    String::from_utf8(response).map_err(|err| format!("mock response was not UTF-8: {err}"))
}

fn resolve_host(host: &str, port: u16) -> Result<WasiAddrPort, String> {
    let mut addrs = [WasiAddr::default(); 4];
    let mut found = 0u32;
    let errno = unsafe {
        resolve(
            host.as_ptr(),
            host.len() as u32,
            port,
            addrs.as_mut_ptr(),
            addrs.len() as u32,
            &mut found,
        )
    };
    ensure_success("resolve", errno)?;

    let first = addrs
        .iter()
        .copied()
        .take(found as usize)
        .find(|addr| addr.tag as u32 == ADDRESS_FAMILY_INET4)
        .ok_or_else(|| "resolver returned no IPv4 address".to_string())?;
    let mut peer = WasiAddrPort {
        tag: first.tag,
        padding: 0,
        ..WasiAddrPort::default()
    };
    let port_bytes = port.to_ne_bytes();
    peer.octs[0] = port_bytes[0];
    peer.octs[1] = port_bytes[1];
    peer.octs[2..6].copy_from_slice(&first.octs[..4]);
    Ok(peer)
}

fn open_tcp_socket() -> Result<u32, String> {
    let mut sock = 0u32;
    let errno = unsafe {
        sock_open(
            ADDRESS_FAMILY_INET4,
            SOCK_TYPE_STREAM,
            SOCK_PROTO_TCP,
            &mut sock,
        )
    };
    ensure_success("sock_open", errno)?;
    Ok(sock)
}

fn connect(sock: u32, peer: WasiAddrPort) -> Result<(), String> {
    let errno = unsafe { sock_connect(sock, &peer) };
    ensure_success("sock_connect", errno)
}

fn send_all(sock: u32, mut bytes: &[u8]) -> Result<(), String> {
    while !bytes.is_empty() {
        let iov = Ciovec {
            buf: bytes.as_ptr() as u32,
            buf_len: bytes.len() as u32,
        };
        let mut sent = 0u32;
        let errno = unsafe { sock_send(sock, &iov, 1, 0, &mut sent) };
        ensure_success("sock_send", errno)?;
        if sent == 0 {
            return Err("sock_send wrote zero bytes".to_string());
        }
        bytes = &bytes[sent as usize..];
    }
    Ok(())
}

fn recv_http_response(sock: u32) -> Result<Vec<u8>, String> {
    let mut response = Vec::with_capacity(4096);
    let mut chunk = [0u8; 1024];

    loop {
        let iov = Iovec {
            buf: chunk.as_mut_ptr() as u32,
            buf_len: chunk.len() as u32,
        };
        let mut read = 0u32;
        let mut flags = 0u16;
        let errno = unsafe { sock_recv(sock, &iov, 1, 0, &mut read, &mut flags) };
        ensure_success("sock_recv", errno)?;
        if read == 0 {
            break;
        }
        response.extend_from_slice(&chunk[..read as usize]);
        if http_response_complete(&response)? {
            break;
        }
        if response.len() > 64 * 1024 {
            return Err("mock response exceeded 64 KiB".to_string());
        }
    }

    Ok(response)
}

fn http_response_complete(response: &[u8]) -> Result<bool, String> {
    let Some((header_len, headers)) = split_http_headers(response) else {
        return Ok(false);
    };
    let Some(content_len) = content_length(headers)? else {
        return Ok(false);
    };
    Ok(response.len() >= header_len + content_len)
}

fn split_http_headers(response: &[u8]) -> Option<(usize, &[u8])> {
    if let Some(pos) = response.windows(4).position(|window| window == b"\r\n\r\n") {
        return Some((pos + 4, &response[..pos]));
    }
    response
        .windows(2)
        .position(|window| window == b"\n\n")
        .map(|pos| (pos + 2, &response[..pos]))
}

fn content_length(headers: &[u8]) -> Result<Option<usize>, String> {
    let headers = std::str::from_utf8(headers)
        .map_err(|err| format!("mock response headers were not UTF-8: {err}"))?;
    for line in headers.lines() {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case("content-length") {
            return value
                .trim()
                .parse::<usize>()
                .map(Some)
                .map_err(|err| format!("invalid content-length in mock response: {err}"));
        }
    }
    Ok(None)
}

fn ensure_success(call: &str, errno: u16) -> Result<(), String> {
    if errno == ERRNO_SUCCESS {
        Ok(())
    } else {
        Err(format!("{call} returned errno {errno}"))
    }
}
