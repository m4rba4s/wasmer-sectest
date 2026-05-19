(module
  (import "host" "accept_packet" (func $accept_packet (param i32 i32 i32) (result i32)))
  (import "host" "read_cap" (func $read_cap (param i32 i32) (result i32)))
  (import "host" "alloc_cap" (func $alloc_cap (param i32) (result i32)))
  (import "host" "tick" (func $tick (result i32)))
  (memory (export "memory") 1 2)
  (func (export "run") (result i32)
    (local $i i32)
    (loop $again
      call $tick
      i32.const 0
      i32.lt_s
      if
        i32.const -6
        return
      end
      local.get $i
      i32.const 1
      i32.add
      local.tee $i
      i32.const 1000000
      i32.lt_s
      br_if $again)
    i32.const 0))
