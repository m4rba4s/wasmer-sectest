use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use virtual_fs::Pipe;
use wasmer::{Engine, Module, Store, sys::Cranelift};
use wasmer_demo::wasi_sandbox::{
    NetworkHoneypotEvent, NetworkHoneypotOperation, WasiHoneypotSandbox,
};

const GUEST_SOURCE: &str = "guests/wasi_network_fetch.rs";
const GUEST_WASM: &str = "target/wasi-guests/wasi_network_fetch.wasm";
const TARGET: &str = "wasm32-wasip1";
const PUBLIC_HOST: &str = "jsonplaceholder.typicode.com";
const PUBLIC_PATH: &str = "/users/1";
const PUBLIC_PORT: u16 = 80;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wasi_network_guest_is_isolated_and_receives_mocked_http() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let wasm_path = build_demo_guest(&manifest_dir);
    let sandbox = WasiHoneypotSandbox::new();
    let network = sandbox.network.clone();

    let stdout = run_demo_guest(sandbox, wasm_path).expect("guest _start completes");

    assert!(stdout.contains("HTTP/1.1 200 OK"), "{stdout}");
    assert!(stdout.contains("\"source\":\"wasmer-sectest\""), "{stdout}");
    assert!(stdout.contains("WASI honeypot user"), "{stdout}");

    let events = network.events();
    if std::env::var_os("WASMER_SECTEST_SHOW_DEMO").is_some() {
        println!("guest stdout:\n{stdout}");
        println!("honeypot events:");
        for event in &events {
            println!("{event:#?}");
        }
    }

    assert_event(&events, NetworkHoneypotOperation::ResolveIntercepted);
    assert_event(&events, NetworkHoneypotOperation::ConnectIntercepted);
    assert_event(&events, NetworkHoneypotOperation::PayloadCaptured);
    assert_event(&events, NetworkHoneypotOperation::MockResponseInjected);

    let payload = events
        .iter()
        .find(|event| event.operation == NetworkHoneypotOperation::PayloadCaptured)
        .expect("payload capture event exists");
    assert_eq!(payload.target.port(), PUBLIC_PORT);
    assert_eq!(payload.domain.as_deref(), Some(PUBLIC_HOST));
    assert!(is_synthetic_test_net(payload), "{payload:#?}");
    let request = String::from_utf8_lossy(&payload.payload);
    assert!(
        request.contains(&format!("GET {PUBLIC_PATH} HTTP/1.1")),
        "{request}"
    );
    assert!(
        request.contains(&format!("Host: {PUBLIC_HOST}")),
        "{request}"
    );
}

fn run_demo_guest(sandbox: WasiHoneypotSandbox, wasm_path: PathBuf) -> Result<String, String> {
    let engine: Engine = Cranelift::new().into();
    let mut builder = sandbox
        .wasi_builder("wasi-network-fetch", engine.clone())
        .map_err(|err| format!("network honeypot configures WASI runtime: {err}"))?;
    let mut stdout = Pipe::new();
    builder.set_stdout(Box::new(stdout.clone()));

    let mut store = Store::new(engine);
    let wasm =
        fs::read(&wasm_path).map_err(|err| format!("compiled guest wasm is readable: {err}"))?;
    let module = Module::new(&store, wasm)
        .map_err(|err| format!("compiled guest module is valid Wasm: {err}"))?;
    let (instance, _wasi_env) = builder
        .instantiate(module, &mut store)
        .map_err(|err| format!("guest instantiates with WASI and WASIX imports: {err}"))?;
    let start = instance
        .exports
        .get_typed_function::<(), ()>(&store, "_start")
        .map_err(|err| format!("guest exports WASI _start: {err}"))?;

    start
        .call(&mut store)
        .map_err(|err| format!("guest _start completes: {err}"))?;

    Ok(read_available_stdout(&mut stdout))
}

fn build_demo_guest(manifest_dir: &Path) -> PathBuf {
    let source = manifest_dir.join(GUEST_SOURCE);
    let wasm = manifest_dir.join(GUEST_WASM);
    if let Some(parent) = wasm.parent() {
        fs::create_dir_all(parent).expect("guest wasm output directory can be created");
    }

    let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| OsString::from("rustc"));
    let output = Command::new(rustc)
        .arg("--edition=2024")
        .arg("--target")
        .arg(TARGET)
        .arg("-O")
        .arg("-o")
        .arg(&wasm)
        .arg(&source)
        .output()
        .expect("rustc is available to build demo guest");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "failed to build {GUEST_SOURCE} for {TARGET}\nstatus: {}\nstdout:\n{}\nstderr:\n{}\nhint: run `rustup target add {TARGET}` or use `make wasi-network-demo` so the target is provisioned first",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        stderr,
    );

    wasm
}

fn read_available_stdout(stdout: &mut Pipe) -> String {
    let mut captured = Vec::new();
    let mut chunk = [0u8; 4096];
    while let Some(read) = stdout.try_read(&mut chunk) {
        if read == 0 {
            break;
        }
        captured.extend_from_slice(&chunk[..read]);
    }
    String::from_utf8(captured).expect("guest stdout is UTF-8")
}

fn assert_event(events: &[NetworkHoneypotEvent], operation: NetworkHoneypotOperation) {
    assert!(
        events.iter().any(|event| event.operation == operation),
        "missing {operation:?} in {events:#?}"
    );
}

fn is_synthetic_test_net(event: &NetworkHoneypotEvent) -> bool {
    match event.target.ip() {
        std::net::IpAddr::V4(ip) => ip.octets()[..3] == [203, 0, 113],
        std::net::IpAddr::V6(_) => false,
    }
}
