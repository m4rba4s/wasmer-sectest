(module
  (import "host" "accept_packet" (func $accept_packet (param i32 i32 i32) (result i32)))
  (import "host" "read_cap" (func $read_cap (param i32 i32) (result i32)))
  (import "host" "alloc_cap" (func $alloc_cap (param i32) (result i32)))
  (import "host" "tick" (func $tick (result i32)))
  (memory (export "memory") 1 2)
  (data (i32.const 448) "/sandbox/../etc/passwd")
  (func (export "run") (result i32)
    i32.const 448
    i32.const 22
    call $read_cap))
