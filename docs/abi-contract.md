# ABI Contract

The hostile guest corpus uses a small packet ABI:

```text
u32 magic      little-endian "WSGT" / 0x54475357
u16 version    must be 1
u16 flags
u32 body_len
u32 checksum   wrapping byte-sum of body
u8[] body
```

Host import:

```text
accept_packet(ptr: u32, len: u32, align: u32) -> i32
```

Required gates:

- `max_len`: `len <= policy.max_packet_len`
- `alignment`: `ptr % align == 0`, with `align` in `{1,2,4,8,16}`
- `checked_add`: `ptr.checked_add(len)` must succeed in the 32-bit WASM address space
- `bounds`: `end <= memory.data_size()`
- `memory.read`: use Wasmer safe reads, not unchecked borrowed slices
- `packet.header`: magic/version/body length must match
- `packet.checksum`: body checksum must match
- zero-length ranges are still parsed as packets and fail the fixed-header gate

String capability import:

```text
read_cap(ptr: u32, len: u32) -> i32
```

The host validates bounds and UTF-8 before comparing against an allow-list. The
comparison is exact over the length-delimited Rust `String`; embedded NUL bytes
do not terminate the string and cannot turn `/sandbox/allowed.txt\0...` into an
allowed capability.

Module audit gates before instantiation:

- `module.memory_min_pages`: every imported/exported memory minimum must be
  `<= policy.max_memory_pages`
- `module.tick_import`: unless policy explicitly disables it, modules must
  import `host.tick` so in-process CPU abuse is budgetable
- `runner.no_execute`: static-audit-only fixtures are compiled and reported but
  not executed

Process supervisor gates:

- `supervisor.spawn`: parent successfully started a worker process
- `supervisor.timeout`: worker returned before timeout, or failed when a
  non-cooperative guest exceeded the timeout
- `supervisor.kill`: parent killed a timed-out worker
- `supervisor.protocol`: parent parsed the worker result protocol
