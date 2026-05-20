use std::time::Duration;

use virtual_fs::FileSystem;
use wasmer::{Engine, Instance, Module, Store, imports, sys::Cranelift};
use wasmer_demo::abi;
use wasmer_demo::async_runner::collect_reports_async;
use wasmer_demo::config::{Backend, Config, IsolationMode, OutputFormat, Profile};
use wasmer_demo::guests::find_case;
use wasmer_demo::memory::with_guest_bytes;
use wasmer_demo::policy::Policy;
use wasmer_demo::wasi_sandbox::{HoneypotFileSystem, HoneypotOperation};

const ZERO_COPY_WAT: &str = r#"
(module
  (memory (export "memory") 1)

  (func (export "write_probe")
    (i32.store8 (i32.const 512) (i32.const 90))  ;; Z
    (i32.store8 (i32.const 513) (i32.const 67))  ;; C
    (i32.store8 (i32.const 514) (i32.const 79))  ;; O
    (i32.store8 (i32.const 515) (i32.const 75))  ;; K
  )
)
"#;

const HONEYPOT_READ_WAT: &str = r#"
(module
  (import "wasi_snapshot_preview1" "path_open"
    (func $path_open
      (param i32 i32 i32 i32 i32 i64 i64 i32 i32)
      (result i32)))
  (import "wasi_snapshot_preview1" "fd_read"
    (func $fd_read (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_close"
    (func $fd_close (param i32) (result i32)))

  (memory (export "memory") 1)
  (data (i32.const 64) "etc/passwd")

  (func (export "run") (result i32)
    (local $fd i32)
    (local $status i32)

    ;; iovec: read 96 bytes into offset 256, enough to include the decoy marker.
    (i32.store (i32.const 24) (i32.const 256))
    (i32.store (i32.const 28) (i32.const 96))

    (call $path_open
      (i32.const 4)   ;; VFS preopened root
      (i32.const 0)   ;; no lookup flags
      (i32.const 64)  ;; "etc/passwd"
      (i32.const 10)
      (i32.const 0)   ;; no open flags
      (i64.const 2)   ;; __WASI_RIGHT_FD_READ
      (i64.const 0)
      (i32.const 0)   ;; no fd flags
      (i32.const 16)) ;; opened fd out
    (local.set $status)

    (if (i32.eqz (local.get $status))
      (then
        (local.set $fd (i32.load (i32.const 16)))
        (call $fd_read
          (local.get $fd)
          (i32.const 24)
          (i32.const 1)
          (i32.const 40))
        (local.set $status)
      )
    )

    (if (i32.eqz (local.get $status))
      (then
        (if (i32.lt_u (i32.load (i32.const 40)) (i32.const 64))
          (then (local.set $status (i32.const 100)))
        )
      )
    )

    ;; The fake passwd contains "honeypot" at bytes 56..63.
    (if (i32.eqz (local.get $status))
      (then
        (if
          (i32.or
            (i32.or
              (i32.or
                (i32.ne (i32.load8_u (i32.const 312)) (i32.const 104)) ;; h
                (i32.ne (i32.load8_u (i32.const 313)) (i32.const 111))) ;; o
              (i32.or
                (i32.ne (i32.load8_u (i32.const 314)) (i32.const 110)) ;; n
                (i32.ne (i32.load8_u (i32.const 315)) (i32.const 101)))) ;; e
            (i32.or
              (i32.or
                (i32.ne (i32.load8_u (i32.const 316)) (i32.const 121)) ;; y
                (i32.ne (i32.load8_u (i32.const 317)) (i32.const 112))) ;; p
              (i32.or
                (i32.ne (i32.load8_u (i32.const 318)) (i32.const 111)) ;; o
                (i32.ne (i32.load8_u (i32.const 319)) (i32.const 116))))) ;; t
          (then (local.set $status (i32.const 101)))
        )
      )
    )

    (if (i32.ne (local.get $fd) (i32.const 0))
      (then (drop (call $fd_close (local.get $fd))))
    )

    (local.get $status)
  )
)
"#;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn async_runner_completes_case_without_starving_tokio() {
    let config = test_config();
    let case = find_case("zero_copy_write_probe").expect("zero copy probe is registered");
    let policy = Policy::default();

    let ticker = tokio::spawn(async {
        tokio::time::sleep(Duration::from_millis(5)).await;
        7u8
    });
    let reports = tokio::time::timeout(
        Duration::from_secs(5),
        collect_reports_async(&config, &[case], &policy),
    )
    .await
    .expect("async runner timed out");
    let tick = ticker.await.expect("ticker task panicked");

    assert_eq!(tick, 7);
    assert_eq!(reports.len(), 1);
    assert!(reports[0].passed(), "{reports:#?}");
    assert_eq!(reports[0].actual_code, Some(abi::OK));
    assert!(
        reports[0]
            .telemetry
            .events
            .iter()
            .any(|event| event.import == "host.write_marker" && event.result_code == abi::OK),
        "{:#?}",
        reports[0].telemetry.events
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wasi_honeypot_serves_decoy_passwd_to_real_wasm_module() {
    let fs = HoneypotFileSystem::new();
    let mut builder = fs
        .wasi_builder("honeypot-reader")
        .expect("wasi builder uses honeypot filesystem");
    let engine: Engine = Cranelift::new().into();
    builder.set_engine(engine.clone());
    let mut store = Store::new(engine);
    let wasm = wat::parse_str(HONEYPOT_READ_WAT).expect("honeypot WAT compiles");
    let module = Module::new(&store, wasm).expect("honeypot module compiles");
    let (instance, _wasi_env) = builder
        .instantiate(module, &mut store)
        .expect("honeypot module instantiates with WASI imports");
    let run = instance
        .exports
        .get_typed_function::<(), i32>(&store, "run")
        .expect("run export is typed");

    let status = run.call(&mut store).expect("honeypot module runs");

    assert_eq!(status, abi::OK);
    let events = fs.events();
    assert!(
        events.iter().any(|event| {
            event.path == "/etc/passwd"
                && event.operation == HoneypotOperation::ReadDecoy
                && event.bytes_returned > 0
        }),
        "{events:#?}"
    );
}

#[test]
fn zero_copy_memory_view_reads_guest_written_bytes_and_rejects_oob() {
    let mut store = Store::default();
    let wasm = wat::parse_str(ZERO_COPY_WAT).expect("zero-copy WAT compiles");
    let module = Module::new(&store, wasm).expect("zero-copy module compiles");
    let instance =
        Instance::new(&mut store, &module, &imports! {}).expect("zero-copy module instantiates");
    let write = instance
        .exports
        .get_typed_function::<(), ()>(&store, "write_probe")
        .expect("write_probe export is typed");

    write.call(&mut store).expect("guest writes probe bytes");

    let memory = instance
        .exports
        .get_memory("memory")
        .expect("guest exports memory");
    {
        let view = memory.view(&store);
        // SAFETY: The immutable view is scoped to this test assertion. No guest
        // code runs and memory is not grown while the borrowed slice is alive.
        let data = unsafe { view.data_unchecked() };
        assert_eq!(&data[512..516], b"ZCOK");
    }

    let matched = with_guest_bytes(Some(memory), &store, 512, 4, 4, 16, |guest| {
        assert_eq!(guest.range.offset, 512);
        guest.bytes == b"ZCOK"
    })
    .expect("validated range reads through MemoryView");
    assert!(matched);

    let (err, memory_size, gates) =
        with_guest_bytes(Some(memory), &store, 65_535, 8, 1, 16, |_| ())
            .expect_err("tail range must exceed one wasm page");
    assert_eq!(err.code(), abi::ERR_BOUNDS);
    assert_eq!(memory_size, Some(65_536));
    assert!(
        gates
            .iter()
            .any(|gate| gate.name == "bounds" && !gate.passed)
    );
}

#[test]
fn wasi_honeypot_denies_sensitive_mutations_and_logs_attempt() {
    let fs = HoneypotFileSystem::new();
    let mut options = fs.new_open_options();
    let err = options
        .write(true)
        .truncate(true)
        .open("/etc/passwd")
        .expect_err("honeypot passwd is read-only");

    assert!(matches!(err, virtual_fs::FsError::PermissionDenied));
    let events = fs.events();
    assert!(
        events.iter().any(|event| {
            event.path == "/etc/passwd" && event.operation == HoneypotOperation::DenyMutation
        }),
        "{events:#?}"
    );
}

fn test_config() -> Config {
    Config {
        case: None,
        corpus_dir: None,
        emit_wasm_dir: None,
        interview: false,
        list: false,
        menu: false,
        no_color: true,
        output_format: OutputFormat::Text,
        policy_path: None,
        allow_unmetered: false,
        isolation: IsolationMode::InProcess,
        profile: Profile::All,
        report_path: None,
        summary_only: true,
        timeout_ms: None,
        tui: false,
        tui_delay_ms: 0,
        repeat: 1,
        backend: Backend::Cranelift,
        worker_case: None,
        worker_execute_static: false,
    }
}
