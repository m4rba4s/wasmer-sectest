(module
  (import "host" "accept_packet" (func $accept_packet (param i32 i32 i32) (result i32)))
  (import "host" "read_cap" (func $read_cap (param i32 i32) (result i32)))
  (import "host" "alloc_cap" (func $alloc_cap (param i32) (result i32)))
  (import "host" "tick" (func $tick (result i32)))
  (memory (export "memory") 1 2)
  (data (i32.const 64) "\57\53\47\54\01\00\02\00\05\00\00\00\74\01\00\00HELLO")
  (func (export "run") (result i32)
    i32.const 64
    i32.const 21
    i32.const 3
    call $accept_packet))
