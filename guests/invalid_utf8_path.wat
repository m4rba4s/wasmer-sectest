(module
  (import "host" "accept_packet" (func $accept_packet (param i32 i32 i32) (result i32)))
  (import "host" "read_cap" (func $read_cap (param i32 i32) (result i32)))
  (import "host" "alloc_cap" (func $alloc_cap (param i32) (result i32)))
  (import "host" "tick" (func $tick (result i32)))
  (memory (export "memory") 1 2)
  (data (i32.const 384) "\ff\fe\fd")
  (func (export "run") (result i32)
    i32.const 384
    i32.const 3
    call $read_cap))
