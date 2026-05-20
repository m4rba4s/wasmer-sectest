use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use wasmer::{Instance, Module, Store, imports};
use wasmer_demo::config::Backend;
use wasmer_demo::guests::find_case;
use wasmer_demo::policy::Policy;
use wasmer_demo::runner::run_case;

const MINIMAL_WASM: &str = r#"
(module
  (memory (export "memory") 1)
  (func (export "run") (result i32)
    i32.const 0))
"#;

fn cold_start_instantiation(c: &mut Criterion) {
    let wasm = wat::parse_str(MINIMAL_WASM).expect("benchmark WAT compiles");

    c.bench_function("cold_start_instantiation", |b| {
        b.iter(|| {
            let mut store = Store::default();
            let module = Module::new(&store, black_box(&wasm)).expect("module compiles");
            let instance =
                Instance::new(&mut store, &module, &imports! {}).expect("module instantiates");
            black_box(instance);
        });
    });
}

fn single_security_check(c: &mut Criterion) {
    let case = find_case("good_packet").expect("built-in good_packet exists");

    c.bench_function("single_security_check_good_packet", |b| {
        b.iter(|| {
            let report = run_case(
                black_box(&case),
                Backend::Cranelift,
                black_box(Policy::default()),
            );
            black_box(report.actual_code);
        });
    });
}

fn zero_copy_memory_boundary(c: &mut Criterion) {
    let case = find_case("zero_copy_write_probe").expect("zero-copy probe exists");

    c.bench_function("zero_copy_memory_access", |b| {
        b.iter(|| {
            let report = run_case(
                black_box(&case),
                Backend::Cranelift,
                black_box(Policy::default()),
            );
            black_box(report.memory_after);
        });
    });
}

criterion_group!(
    benches,
    cold_start_instantiation,
    single_security_check,
    zero_copy_memory_boundary
);
criterion_main!(benches);
