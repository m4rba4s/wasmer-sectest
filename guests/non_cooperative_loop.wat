(module
  (memory (export "memory") 1 1)
  (func (export "run") (result i32)
    (loop $again
      br $again)
    i32.const 0))
