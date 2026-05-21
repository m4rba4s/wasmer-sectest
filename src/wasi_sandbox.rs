use std::collections::HashMap;
use std::future::Future;
use std::mem::MaybeUninit;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Component, Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use thiserror::Error;
use virtual_fs::{
    FileOpener, FileSystem, FileType, FsError, Metadata, OpenOptions, OpenOptionsConfig, ReadDir,
    StaticFile, TmpFileSystem,
};
use virtual_mio::InterestType;
use wasmer::Engine;
use wasmer_wasix::runtime::task_manager::tokio::TokioTaskManager;
use wasmer_wasix::virtual_net::{
    Bytes, InterestHandler, NetworkError, Result as NetResult, SocketStatus,
    VirtualConnectedSocket, VirtualIcmpSocket, VirtualIoSource, VirtualNetworking,
    VirtualRawSocket, VirtualSocket, VirtualTcpListener, VirtualTcpSocket, VirtualUdpSocket,
};
use wasmer_wasix::{PluggableRuntime, Runtime, WasiEnv, WasiEnvBuilder};

use crate::error::SectestError;

const FAKE_PASSWD: &[u8] =
    b"root:x:0:0:root:/root:/usr/sbin/nologin\nsvc:x:1000:1000:honeypot:/srv:/bin/false\n";
const FAKE_SHADOW: &[u8] = b"root:*:19000:0:99999:7:::\nsvc:*:19000:0:99999:7:::\n";
const FAKE_PRIVATE_KEY: &[u8] =
    b"-----BEGIN OPENSSH PRIVATE KEY-----\nhoneypot-controlled-decoy\n-----END OPENSSH PRIVATE KEY-----\n";
const DEFAULT_MOCK_JSON: &[u8] =
    br#"{"id":1,"name":"WASI honeypot user","source":"wasmer-sectest"}"#;
const HONEYPOT_EVENT_CAPACITY: usize = 1024;
const RESOLVED_HOST_CAPACITY: usize = 1024;
const MAX_CAPTURED_REQUEST_BYTES: usize = 16 * 1024;
const EPHEMERAL_PORT_BASE: u32 = 49_152;
const EPHEMERAL_PORT_SPAN: u32 = 16_384;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HoneypotOperation {
    ReadDecoy,
    DenyMutation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HoneypotEvent {
    pub path: String,
    pub operation: HoneypotOperation,
    pub bytes_returned: usize,
}

#[derive(Debug, Clone, Copy)]
struct Decoy {
    path: &'static str,
    bytes: &'static [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkHoneypotOperation {
    ResolveIntercepted,
    ConnectIntercepted,
    PayloadCaptured,
    MockResponseInjected,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkHoneypotEvent {
    pub target: SocketAddr,
    pub domain: Option<String>,
    pub operation: NetworkHoneypotOperation,
    pub payload: Vec<u8>,
    pub mocked_response_bytes: usize,
}

#[derive(Debug, Error)]
pub enum NetworkSandboxError {
    #[error("network sandbox requires an active tokio runtime: {0}")]
    MissingTokioRuntime(String),
}

#[derive(Debug)]
struct NetworkHoneypotInner {
    events: Mutex<Vec<NetworkHoneypotEvent>>,
    resolved_hosts: Mutex<HashMap<IpAddr, String>>,
    mock_response: Bytes,
    next_ephemeral: AtomicU32,
}

#[derive(Debug, Clone)]
pub struct NetworkHoneypot {
    inner: Arc<NetworkHoneypotInner>,
}

impl Default for NetworkHoneypot {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkHoneypot {
    pub fn new() -> Self {
        Self::with_mock_response(default_mock_http_response())
    }

    pub fn with_mock_response(mock_response: Vec<u8>) -> Self {
        Self {
            inner: Arc::new(NetworkHoneypotInner {
                events: Mutex::new(Vec::new()),
                resolved_hosts: Mutex::new(HashMap::new()),
                mock_response: Bytes::from(mock_response),
                next_ephemeral: AtomicU32::new(0),
            }),
        }
    }

    pub fn events(&self) -> Vec<NetworkHoneypotEvent> {
        self.inner
            .events
            .lock()
            .map(|events| events.clone())
            .unwrap_or_default()
    }

    pub fn apply_to_builder(
        &self,
        builder: &mut WasiEnvBuilder,
        engine: Engine,
    ) -> Result<(), NetworkSandboxError> {
        builder.set_runtime(self.runtime(engine)?);
        Ok(())
    }

    pub fn runtime(
        &self,
        engine: Engine,
    ) -> Result<Arc<dyn Runtime + Send + Sync>, NetworkSandboxError> {
        let handle = tokio::runtime::Handle::try_current()
            .map_err(|err| NetworkSandboxError::MissingTokioRuntime(err.to_string()))?;
        let task_manager = TokioTaskManager::new(handle);
        let mut runtime = PluggableRuntime::new(Arc::new(task_manager));
        runtime.set_engine(engine);
        runtime.set_networking_implementation(self.clone());
        Ok(Arc::new(runtime))
    }

    fn record(&self, event: NetworkHoneypotEvent) {
        if let Ok(mut events) = self.inner.events.lock() {
            enforce_capacity(&mut events, HONEYPOT_EVENT_CAPACITY);
            events.push(event);
        }
    }

    fn remember_host(&self, ip: IpAddr, host: &str) {
        if let Ok(mut hosts) = self.inner.resolved_hosts.lock() {
            if hosts.len() >= RESOLVED_HOST_CAPACITY
                && let Some(oldest) = hosts.keys().next().copied()
            {
                hosts.remove(&oldest);
            }
            hosts.insert(ip, host.to_string());
        }
    }

    fn domain_for(&self, ip: IpAddr) -> Option<String> {
        self.inner
            .resolved_hosts
            .lock()
            .ok()
            .and_then(|hosts| hosts.get(&ip).cloned())
    }

    fn next_local_addr(&self, requested: SocketAddr, peer: SocketAddr) -> SocketAddr {
        let ip = if requested.ip().is_unspecified() {
            unspecified_for(peer.ip())
        } else {
            requested.ip()
        };
        let port = if requested.port() == 0 {
            let offset =
                self.inner.next_ephemeral.fetch_add(1, Ordering::Relaxed) % EPHEMERAL_PORT_SPAN;
            (EPHEMERAL_PORT_BASE + offset) as u16
        } else {
            requested.port()
        };
        SocketAddr::new(ip, port)
    }
}

#[async_trait::async_trait]
impl VirtualNetworking for NetworkHoneypot {
    async fn listen_tcp(
        &self,
        _addr: SocketAddr,
        _only_v6: bool,
        _reuse_port: bool,
        _reuse_addr: bool,
    ) -> Result<Box<dyn VirtualTcpListener + Sync>, NetworkError> {
        Err(NetworkError::PermissionDenied)
    }

    async fn bind_udp(
        &self,
        _addr: SocketAddr,
        _reuse_port: bool,
        _reuse_addr: bool,
    ) -> Result<Box<dyn VirtualUdpSocket + Sync>, NetworkError> {
        Err(NetworkError::PermissionDenied)
    }

    async fn bind_raw(&self) -> Result<Box<dyn VirtualRawSocket + Sync>, NetworkError> {
        Err(NetworkError::PermissionDenied)
    }

    async fn bind_icmp(
        &self,
        _addr: IpAddr,
    ) -> Result<Box<dyn VirtualIcmpSocket + Sync>, NetworkError> {
        Err(NetworkError::PermissionDenied)
    }

    async fn connect_tcp(
        &self,
        addr: SocketAddr,
        peer: SocketAddr,
    ) -> Result<Box<dyn VirtualTcpSocket + Sync>, NetworkError> {
        let local_addr = self.next_local_addr(addr, peer);
        let domain = self.domain_for(peer.ip());
        self.record(NetworkHoneypotEvent {
            target: peer,
            domain: domain.clone(),
            operation: NetworkHoneypotOperation::ConnectIntercepted,
            payload: Vec::new(),
            mocked_response_bytes: 0,
        });

        Ok(Box::new(HoneypotTcpSocket::new(
            self.clone(),
            local_addr,
            peer,
            domain,
            self.inner.mock_response.clone(),
        )))
    }

    async fn resolve(
        &self,
        host: &str,
        port: Option<u16>,
        _dns_server: Option<IpAddr>,
    ) -> Result<Vec<IpAddr>, NetworkError> {
        let addresses = deterministic_honeypot_ips(host);
        for ip in addresses {
            self.remember_host(ip, host);
        }
        self.record(NetworkHoneypotEvent {
            target: SocketAddr::new(addresses[0], port.unwrap_or_default()),
            domain: Some(host.to_string()),
            operation: NetworkHoneypotOperation::ResolveIntercepted,
            payload: Vec::new(),
            mocked_response_bytes: 0,
        });
        Ok(addresses.to_vec())
    }
}

#[derive(Debug)]
struct HoneypotTcpSocket {
    logger: NetworkHoneypot,
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
    domain: Option<String>,
    request: Vec<u8>,
    response: Bytes,
    response_offset: usize,
    response_ready: bool,
    payload_logged: bool,
    mock_logged: bool,
    closed: bool,
    ttl: u32,
    recv_buf_size: usize,
    send_buf_size: usize,
    handler: Option<Box<dyn InterestHandler + Send + Sync>>,
}

impl HoneypotTcpSocket {
    fn new(
        logger: NetworkHoneypot,
        local_addr: SocketAddr,
        peer_addr: SocketAddr,
        domain: Option<String>,
        response: Bytes,
    ) -> Self {
        Self {
            logger,
            local_addr,
            peer_addr,
            domain,
            request: Vec::with_capacity(512),
            response,
            response_offset: 0,
            response_ready: false,
            payload_logged: false,
            mock_logged: false,
            closed: false,
            ttl: 64,
            recv_buf_size: 64 * 1024,
            send_buf_size: 64 * 1024,
            handler: None,
        }
    }

    fn record_payload_and_prepare_response(&mut self) {
        if !self.payload_logged {
            self.logger.record(NetworkHoneypotEvent {
                target: self.peer_addr,
                domain: self.domain.clone(),
                operation: NetworkHoneypotOperation::PayloadCaptured,
                payload: self.request.clone(),
                mocked_response_bytes: 0,
            });
            self.payload_logged = true;
        }

        if !self.mock_logged {
            self.logger.record(NetworkHoneypotEvent {
                target: self.peer_addr,
                domain: self.domain.clone(),
                operation: NetworkHoneypotOperation::MockResponseInjected,
                payload: Vec::new(),
                mocked_response_bytes: self.response.len(),
            });
            self.mock_logged = true;
        }

        self.response_ready = true;
        self.push_interest(InterestType::Readable);
    }

    fn push_interest(&mut self, interest: InterestType) {
        if let Some(handler) = self.handler.as_mut() {
            handler.push_interest(interest);
        }
    }
}

impl VirtualIoSource for HoneypotTcpSocket {
    fn remove_handler(&mut self) {
        self.handler = None;
    }

    fn poll_read_ready(&mut self, cx: &mut Context<'_>) -> Poll<NetResult<usize>> {
        self.set_handler(cx.waker().into())?;
        if self.response_ready {
            return Poll::Ready(Ok(self.response.len().saturating_sub(self.response_offset)));
        }
        if self.closed {
            return Poll::Ready(Ok(0));
        }
        Poll::Pending
    }

    fn poll_write_ready(&mut self, cx: &mut Context<'_>) -> Poll<NetResult<usize>> {
        self.set_handler(cx.waker().into())?;
        if self.closed {
            Poll::Ready(Err(NetworkError::ConnectionReset))
        } else {
            Poll::Ready(Ok(self.send_buf_size))
        }
    }
}

impl VirtualSocket for HoneypotTcpSocket {
    fn set_ttl(&mut self, ttl: u32) -> NetResult<()> {
        self.ttl = ttl;
        Ok(())
    }

    fn ttl(&self) -> NetResult<u32> {
        Ok(self.ttl)
    }

    fn addr_local(&self) -> NetResult<SocketAddr> {
        Ok(self.local_addr)
    }

    fn status(&self) -> NetResult<SocketStatus> {
        if self.closed {
            Ok(SocketStatus::Closed)
        } else {
            Ok(SocketStatus::Opened)
        }
    }

    fn set_handler(&mut self, handler: Box<dyn InterestHandler + Send + Sync>) -> NetResult<()> {
        self.handler = Some(handler);
        Ok(())
    }
}

impl VirtualConnectedSocket for HoneypotTcpSocket {
    fn set_linger(&mut self, _linger: Option<Duration>) -> NetResult<()> {
        Ok(())
    }

    fn linger(&self) -> NetResult<Option<Duration>> {
        Ok(None)
    }

    fn try_send(&mut self, data: &[u8]) -> NetResult<usize> {
        if self.closed {
            return Err(NetworkError::ConnectionReset);
        }

        let remaining_capture = MAX_CAPTURED_REQUEST_BYTES.saturating_sub(self.request.len());
        let capture_len = remaining_capture.min(data.len());
        self.request.extend_from_slice(&data[..capture_len]);

        if !self.response_ready
            && (!self.request.is_empty()
                && (has_complete_http_headers(&self.request)
                    || self.request.len() >= MAX_CAPTURED_REQUEST_BYTES))
        {
            self.record_payload_and_prepare_response();
        }

        Ok(data.len())
    }

    fn try_flush(&mut self) -> NetResult<()> {
        if !self.request.is_empty() && !self.response_ready {
            self.record_payload_and_prepare_response();
        }
        Ok(())
    }

    fn close(&mut self) -> NetResult<()> {
        self.closed = true;
        self.push_interest(InterestType::Closed);
        Ok(())
    }

    fn try_recv(&mut self, buf: &mut [MaybeUninit<u8>], peek: bool) -> NetResult<usize> {
        if !self.response_ready {
            if self.request.is_empty() {
                return Err(NetworkError::WouldBlock);
            }
            self.record_payload_and_prepare_response();
        }

        let remaining = &self.response[self.response_offset..];
        if remaining.is_empty() {
            self.closed = true;
            self.push_interest(InterestType::Closed);
            return Ok(0);
        }

        let read_len = remaining.len().min(buf.len());
        for (dst, byte) in buf.iter_mut().zip(&remaining[..read_len]) {
            dst.write(*byte);
        }
        if !peek {
            self.response_offset += read_len;
        }
        Ok(read_len)
    }
}

impl VirtualTcpSocket for HoneypotTcpSocket {
    fn set_recv_buf_size(&mut self, size: usize) -> NetResult<()> {
        self.recv_buf_size = size;
        Ok(())
    }

    fn recv_buf_size(&self) -> NetResult<usize> {
        Ok(self.recv_buf_size)
    }

    fn set_send_buf_size(&mut self, size: usize) -> NetResult<()> {
        self.send_buf_size = size;
        Ok(())
    }

    fn send_buf_size(&self) -> NetResult<usize> {
        Ok(self.send_buf_size)
    }

    fn set_nodelay(&mut self, _reuse: bool) -> NetResult<()> {
        Ok(())
    }

    fn nodelay(&self) -> NetResult<bool> {
        Ok(true)
    }

    fn set_keepalive(&mut self, _keepalive: bool) -> NetResult<()> {
        Ok(())
    }

    fn keepalive(&self) -> NetResult<bool> {
        Ok(false)
    }

    fn set_dontroute(&mut self, _keepalive: bool) -> NetResult<()> {
        Ok(())
    }

    fn dontroute(&self) -> NetResult<bool> {
        Ok(false)
    }

    fn addr_peer(&self) -> NetResult<SocketAddr> {
        Ok(self.peer_addr)
    }

    fn shutdown(&mut self, _how: std::net::Shutdown) -> NetResult<()> {
        self.closed = true;
        self.push_interest(InterestType::Closed);
        Ok(())
    }

    fn is_closed(&self) -> bool {
        self.closed
    }
}

#[derive(Debug, Clone)]
pub struct WasiHoneypotSandbox {
    pub filesystem: HoneypotFileSystem,
    pub network: NetworkHoneypot,
}

impl Default for WasiHoneypotSandbox {
    fn default() -> Self {
        Self::new()
    }
}

impl WasiHoneypotSandbox {
    pub fn new() -> Self {
        Self {
            filesystem: HoneypotFileSystem::new(),
            network: NetworkHoneypot::new(),
        }
    }

    pub fn wasi_builder(
        &self,
        program_name: &str,
        engine: Engine,
    ) -> Result<WasiEnvBuilder, SectestError> {
        let mut builder = self.filesystem.wasi_builder(program_name)?;
        self.network
            .apply_to_builder(&mut builder, engine)
            .map_err(|err| SectestError::WasiSandbox(err.to_string()))?;
        Ok(builder)
    }
}

#[derive(Debug, Clone)]
pub struct HoneypotFileSystem {
    root: TmpFileSystem,
    events: Arc<Mutex<Vec<HoneypotEvent>>>,
}

impl Default for HoneypotFileSystem {
    fn default() -> Self {
        Self::new()
    }
}

impl HoneypotFileSystem {
    pub fn new() -> Self {
        let root = virtual_fs::RootFileSystemBuilder::new().build();
        Self {
            root,
            events: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn events(&self) -> Vec<HoneypotEvent> {
        self.events
            .lock()
            .map(|events| events.clone())
            .unwrap_or_default()
    }

    pub fn wasi_builder(&self, program_name: &str) -> Result<WasiEnvBuilder, SectestError> {
        let mut builder = WasiEnv::builder(program_name);
        builder.set_fs(Box::new(self.clone()));
        builder
            .preopen_vfs_dirs(["/".to_string()])
            .map_err(|err| SectestError::WasiSandbox(err.to_string()))?;
        Ok(builder)
    }

    fn record(&self, event: HoneypotEvent) {
        if let Ok(mut events) = self.events.lock() {
            enforce_capacity(&mut events, HONEYPOT_EVENT_CAPACITY);
            events.push(event);
        }
    }
}

impl FileSystem for HoneypotFileSystem {
    fn readlink(&self, path: &Path) -> virtual_fs::Result<PathBuf> {
        self.root.readlink(path)
    }

    fn read_dir(&self, path: &Path) -> virtual_fs::Result<ReadDir> {
        self.root.read_dir(path)
    }

    fn create_dir(&self, path: &Path) -> virtual_fs::Result<()> {
        self.root.create_dir(path)
    }

    fn remove_dir(&self, path: &Path) -> virtual_fs::Result<()> {
        if let Some(decoy) = decoy_for(path) {
            self.record(HoneypotEvent {
                path: decoy.path.to_string(),
                operation: HoneypotOperation::DenyMutation,
                bytes_returned: decoy.bytes.len(),
            });
            return Err(FsError::PermissionDenied);
        }
        self.root.remove_dir(path)
    }

    fn rename<'a>(
        &'a self,
        from: &'a Path,
        to: &'a Path,
    ) -> Pin<Box<dyn Future<Output = virtual_fs::Result<()>> + Send + 'a>> {
        Box::pin(async move {
            if let Some(decoy) = decoy_for(from).or_else(|| decoy_for(to)) {
                self.record(HoneypotEvent {
                    path: decoy.path.to_string(),
                    operation: HoneypotOperation::DenyMutation,
                    bytes_returned: decoy.bytes.len(),
                });
                return Err(FsError::PermissionDenied);
            }
            self.root.rename(from, to).await
        })
    }

    fn metadata(&self, path: &Path) -> virtual_fs::Result<Metadata> {
        if let Some(decoy) = decoy_for(path) {
            return Ok(file_metadata(decoy.bytes.len() as u64));
        }
        self.root.metadata(path)
    }

    fn symlink_metadata(&self, path: &Path) -> virtual_fs::Result<Metadata> {
        self.metadata(path)
    }

    fn remove_file(&self, path: &Path) -> virtual_fs::Result<()> {
        if let Some(decoy) = decoy_for(path) {
            self.record(HoneypotEvent {
                path: decoy.path.to_string(),
                operation: HoneypotOperation::DenyMutation,
                bytes_returned: decoy.bytes.len(),
            });
            return Err(FsError::PermissionDenied);
        }
        self.root.remove_file(path)
    }

    fn new_open_options(&self) -> OpenOptions<'_> {
        OpenOptions::new(self)
    }

    fn mount(
        &self,
        name: String,
        path: &Path,
        fs: Box<dyn FileSystem + Send + Sync>,
    ) -> virtual_fs::Result<()> {
        virtual_fs::FileSystem::mount(&self.root, name, path, fs)
    }
}

impl FileOpener for HoneypotFileSystem {
    fn open(
        &self,
        path: &Path,
        conf: &OpenOptionsConfig,
    ) -> virtual_fs::Result<Box<dyn virtual_fs::VirtualFile + Send + Sync + 'static>> {
        if let Some(decoy) = decoy_for(path) {
            let operation = if conf.would_mutate() {
                HoneypotOperation::DenyMutation
            } else {
                HoneypotOperation::ReadDecoy
            };
            self.record(HoneypotEvent {
                path: decoy.path.to_string(),
                operation: operation.clone(),
                bytes_returned: decoy.bytes.len(),
            });

            if operation == HoneypotOperation::DenyMutation {
                return Err(FsError::PermissionDenied);
            }

            return Ok(Box::new(StaticFile::new(decoy.bytes)));
        }

        self.root
            .new_open_options()
            .options(conf.clone())
            .open(path)
    }
}

fn decoy_for(path: &Path) -> Option<Decoy> {
    match normalized_path(path).as_str() {
        "/etc/passwd" => Some(Decoy {
            path: "/etc/passwd",
            bytes: FAKE_PASSWD,
        }),
        "/etc/shadow" => Some(Decoy {
            path: "/etc/shadow",
            bytes: FAKE_SHADOW,
        }),
        "/root/.ssh/id_rsa" => Some(Decoy {
            path: "/root/.ssh/id_rsa",
            bytes: FAKE_PRIVATE_KEY,
        }),
        "/home/app/.ssh/id_rsa" => Some(Decoy {
            path: "/home/app/.ssh/id_rsa",
            bytes: FAKE_PRIVATE_KEY,
        }),
        "/home/user/.ssh/id_rsa" => Some(Decoy {
            path: "/home/user/.ssh/id_rsa",
            bytes: FAKE_PRIVATE_KEY,
        }),
        _ => None,
    }
}

fn normalized_path(path: &Path) -> String {
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::ParentDir => {
                parts.pop();
            }
            Component::Normal(part) => parts.push(part.to_string_lossy().into_owned()),
            Component::Prefix(prefix) => {
                parts.push(prefix.as_os_str().to_string_lossy().into_owned())
            }
        }
    }

    if parts.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", parts.join("/"))
    }
}

fn file_metadata(len: u64) -> Metadata {
    Metadata {
        ft: FileType::new_file(),
        accessed: 0,
        created: 0,
        modified: 0,
        len,
    }
}

fn has_complete_http_headers(payload: &[u8]) -> bool {
    payload.windows(4).any(|window| window == b"\r\n\r\n")
        || payload.windows(2).any(|window| window == b"\n\n")
}

fn deterministic_honeypot_ips(host: &str) -> [IpAddr; 2] {
    let hash = host
        .bytes()
        .fold(0u8, |acc, byte| acc.wrapping_mul(31).wrapping_add(byte));
    [
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10 + (hash % 200))),
        IpAddr::V6(std::net::Ipv6Addr::new(
            0x2001,
            0x0db8,
            u16::from(hash),
            0,
            0,
            0,
            0,
            1,
        )),
    ]
}

fn unspecified_for(peer: IpAddr) -> IpAddr {
    match peer {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(_) => IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
    }
}

fn default_mock_http_response() -> Vec<u8> {
    let mut response = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        DEFAULT_MOCK_JSON.len()
    )
    .into_bytes();
    response.extend_from_slice(DEFAULT_MOCK_JSON);
    response
}

fn enforce_capacity<T>(events: &mut Vec<T>, capacity: usize) {
    if capacity == 0 {
        events.clear();
        return;
    }

    if events.len() >= capacity {
        let overflow = events.len() + 1 - capacity;
        events.drain(..overflow);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use virtual_fs::{AsyncReadExt, FileSystem};
    use wasmer_wasix::virtual_net::{VirtualNetworking, VirtualTcpSocket};

    #[tokio::test]
    async fn honeypot_serves_fake_passwd_and_logs_read() {
        let fs = HoneypotFileSystem::new();
        let mut file = fs
            .new_open_options()
            .read(true)
            .open("/etc/passwd")
            .expect("honeypot passwd opens");

        let mut body = String::new();
        file.read_to_string(&mut body)
            .await
            .expect("honeypot passwd is readable");

        assert!(body.contains("honeypot"));
        assert_eq!(
            fs.events(),
            vec![HoneypotEvent {
                path: "/etc/passwd".into(),
                operation: HoneypotOperation::ReadDecoy,
                bytes_returned: FAKE_PASSWD.len(),
            }]
        );
    }

    #[tokio::test]
    async fn honeypot_canonicalizes_sensitive_path_aliases() {
        let fs = HoneypotFileSystem::new();
        let mut file = fs
            .new_open_options()
            .read(true)
            .open("etc/../etc/./passwd")
            .expect("canonicalized passwd alias opens");

        let mut body = String::new();
        file.read_to_string(&mut body)
            .await
            .expect("canonicalized decoy is readable");

        assert!(body.contains("honeypot"));
        assert_eq!(
            fs.events(),
            vec![HoneypotEvent {
                path: "/etc/passwd".into(),
                operation: HoneypotOperation::ReadDecoy,
                bytes_returned: FAKE_PASSWD.len(),
            }]
        );
    }

    #[tokio::test]
    async fn honeypot_denies_rename_into_sensitive_alias() {
        let fs = HoneypotFileSystem::new();
        let result = fs
            .rename(
                Path::new("/tmp/source"),
                Path::new("/root/../root/.ssh/./id_rsa"),
            )
            .await;

        assert!(matches!(result, Err(FsError::PermissionDenied)));
        assert_eq!(
            fs.events(),
            vec![HoneypotEvent {
                path: "/root/.ssh/id_rsa".into(),
                operation: HoneypotOperation::DenyMutation,
                bytes_returned: FAKE_PRIVATE_KEY.len(),
            }]
        );
    }

    #[test]
    fn honeypot_event_log_is_bounded() {
        let fs = HoneypotFileSystem::new();
        for _ in 0..(HONEYPOT_EVENT_CAPACITY + 8) {
            let _ = fs.new_open_options().read(true).open("/etc/passwd");
        }

        assert_eq!(fs.events().len(), HONEYPOT_EVENT_CAPACITY);
    }

    #[test]
    fn wasi_builder_uses_honeypot_filesystem() {
        let fs = HoneypotFileSystem::new();
        let builder = fs.wasi_builder("wasmer-sectest");
        assert!(builder.is_ok());
    }

    #[tokio::test]
    async fn network_honeypot_resolves_without_external_dns() {
        let net = NetworkHoneypot::new();
        let resolved = net
            .resolve("jsonplaceholder.typicode.com", Some(80), None)
            .await
            .expect("honeypot resolver returns synthetic address");

        assert_eq!(resolved.len(), 2);
        assert!(matches!(resolved[0], IpAddr::V4(ip) if ip.octets()[0..3] == [203, 0, 113]));
        assert!(matches!(resolved[1], IpAddr::V6(ip) if ip.segments()[0..2] == [0x2001, 0x0db8]));
        assert!(
            net.events().iter().any(|event| {
                event.operation == NetworkHoneypotOperation::ResolveIntercepted
                    && event.domain.as_deref() == Some("jsonplaceholder.typicode.com")
            }),
            "{:#?}",
            net.events()
        );
    }

    #[tokio::test]
    async fn network_honeypot_event_log_is_bounded() {
        let net = NetworkHoneypot::new();
        for idx in 0..(HONEYPOT_EVENT_CAPACITY + 8) {
            let host = format!("host-{idx}.example.invalid");
            net.resolve(&host, Some(80), None)
                .await
                .expect("synthetic resolve succeeds");
        }

        assert_eq!(net.events().len(), HONEYPOT_EVENT_CAPACITY);
    }

    #[tokio::test]
    async fn network_honeypot_mocks_tcp_response_and_logs_payload() {
        let net = NetworkHoneypot::new();
        let peer_ip = net
            .resolve("jsonplaceholder.typicode.com", Some(80), None)
            .await
            .expect("resolve is intercepted")[0];
        let peer = SocketAddr::new(peer_ip, 80);
        let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
        let mut socket = net
            .connect_tcp(local, peer)
            .await
            .expect("connect is intercepted with mock socket");
        let request = b"GET /users/1 HTTP/1.1\r\nHost: jsonplaceholder.typicode.com\r\n\r\n";

        assert_eq!(
            socket
                .try_send(request)
                .expect("guest request is accepted by honeypot socket"),
            request.len()
        );
        socket.try_flush().expect("guest request flushes");

        let mut response = Vec::with_capacity(512);
        recv_virtual_socket(&mut socket, &mut response)
            .await
            .expect("mock response is readable");

        assert!(response.starts_with(b"HTTP/1.1 200 OK"));
        assert!(
            response
                .windows(DEFAULT_MOCK_JSON.len())
                .any(|window| window == DEFAULT_MOCK_JSON)
        );
        let events = net.events();
        assert!(
            events.iter().any(|event| {
                event.operation == NetworkHoneypotOperation::PayloadCaptured
                    && event.target == peer
                    && event.domain.as_deref() == Some("jsonplaceholder.typicode.com")
                    && event.payload == request
            }),
            "{events:#?}"
        );
        assert!(
            events.iter().any(|event| {
                event.operation == NetworkHoneypotOperation::MockResponseInjected
                    && event.target == peer
                    && event.mocked_response_bytes > 0
            }),
            "{events:#?}"
        );
    }

    async fn recv_virtual_socket(
        socket: &mut Box<dyn VirtualTcpSocket + Sync>,
        dst: &mut Vec<u8>,
    ) -> Result<(), NetworkError> {
        let read = tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                match socket.try_recv(dst.spare_capacity_mut(), false) {
                    Ok(read) => return Ok(read),
                    Err(NetworkError::WouldBlock) => tokio::task::yield_now().await,
                    Err(err) => return Err(err),
                }
            }
        })
        .await
        .map_err(|_| NetworkError::TimedOut)??;

        // SAFETY: `VirtualTcpSocket::try_recv` initialized exactly `read` bytes
        // inside the spare capacity returned above.
        unsafe {
            dst.set_len(read);
        }
        Ok(())
    }
}
