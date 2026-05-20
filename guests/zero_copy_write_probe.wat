(module
  (import "host" "write_marker" (func $write_marker (param i32 i32 i32) (result i32)))
  (import "host" "tick" (func $tick (result i32)))
  (memory (export "memory") 1 2)
  (func (export "run") (result i32)
    (local $rc i32)
    (local $ok i32)

    i32.const 128
    i32.const 4
    i32.const 4
    call $write_marker
    local.set $rc

    local.get $rc
    i32.const 0
    i32.ne
    if (result i32)
      local.get $rc
    else
      i32.const 1
      local.set $ok

      i32.const 128
      i32.load8_u
      i32.const 87
      i32.eq
      local.get $ok
      i32.and
      local.set $ok

      i32.const 129
      i32.load8_u
      i32.const 83
      i32.eq
      local.get $ok
      i32.and
      local.set $ok

      i32.const 130
      i32.load8_u
      i32.const 69
      i32.eq
      local.get $ok
      i32.and
      local.set $ok

      i32.const 131
      i32.load8_u
      i32.const 67
      i32.eq
      local.get $ok
      i32.and
      local.set $ok

      local.get $ok
      if (result i32)
        i32.const 0
      else
        i32.const -7
      end
    end)
)
