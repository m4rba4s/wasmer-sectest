use wasmer::{AsStoreRef, Memory};

use crate::abi::{self, AbiError, GuestRange};
use crate::telemetry::Gate;

pub type GuestAccessErr = (AbiError, Option<u64>, Vec<Gate>);

#[derive(Debug)]
pub struct GuestBytes<'a> {
    pub bytes: &'a [u8],
    pub range: GuestRange,
    pub memory_size: u64,
    pub gates: Vec<Gate>,
}

#[derive(Debug)]
pub struct GuestBytesMut<'a> {
    pub bytes: &'a mut [u8],
    pub range: GuestRange,
    pub memory_size: u64,
    pub gates: Vec<Gate>,
}

pub fn with_guest_bytes<R>(
    memory: Option<&Memory>,
    store: &impl AsStoreRef,
    ptr: u32,
    len: u32,
    align: u32,
    max_len: u32,
    read: impl FnOnce(GuestBytes<'_>) -> R,
) -> Result<R, GuestAccessErr> {
    let Some(memory) = memory else {
        let err = AbiError::MissingMemory;
        return Err((err, None, vec![Gate::fail("memory.export")]));
    };

    let view = memory.view(store);
    let memory_size = view.data_size();
    let (range, mut gates) = validate_range(ptr, len, align, memory_size, max_len)?;
    let (start, end) = range_indices(range)?;

    // SAFETY: The borrowed slice is scoped to this host import callback. The
    // callback does not call guest code, grow memory, or write memory while this
    // immutable borrow is alive. A fresh MemoryView is acquired per import.
    let data = unsafe { view.data_unchecked() };
    let Some(bytes) = data.get(start..end) else {
        let err = AbiError::MemoryRead("validated range could not index MemoryView".into());
        gates.push(Gate::fail(err.gate()));
        return Err((err, Some(memory_size), gates));
    };
    gates.push(Gate::pass("memory.read"));

    Ok(read(GuestBytes {
        bytes,
        range,
        memory_size,
        gates,
    }))
}

pub fn with_guest_bytes_mut<R>(
    memory: Option<&Memory>,
    store: &impl AsStoreRef,
    ptr: u32,
    len: u32,
    align: u32,
    max_len: u32,
    write: impl FnOnce(GuestBytesMut<'_>) -> R,
) -> Result<R, GuestAccessErr> {
    let Some(memory) = memory else {
        let err = AbiError::MissingMemory;
        return Err((err, None, vec![Gate::fail("memory.export")]));
    };

    let view = memory.view(store);
    let memory_size = view.data_size();
    let (range, mut gates) = validate_range(ptr, len, align, memory_size, max_len)?;
    let (start, end) = range_indices(range)?;

    // SAFETY: The mutable slice is scoped to this host import callback. No
    // guest code executes and no memory growth happens until the slice is
    // dropped at the end of this function.
    let data = unsafe { view.data_unchecked_mut() };
    let Some(bytes) = data.get_mut(start..end) else {
        let err = AbiError::MemoryRead("validated range could not mutably index MemoryView".into());
        gates.push(Gate::fail(err.gate()));
        return Err((err, Some(memory_size), gates));
    };
    gates.push(Gate::pass("memory.write"));

    Ok(write(GuestBytesMut {
        bytes,
        range,
        memory_size,
        gates,
    }))
}

fn validate_range(
    ptr: u32,
    len: u32,
    align: u32,
    memory_size: u64,
    max_len: u32,
) -> Result<(GuestRange, Vec<Gate>), GuestAccessErr> {
    let mut gates = Vec::with_capacity(5);
    let range = match abi::checked_guest_range(ptr, len, align, memory_size, max_len) {
        Ok(range) => {
            gates.push(Gate::pass("max_len"));
            gates.push(Gate::pass("alignment"));
            gates.push(Gate::pass("checked_add"));
            gates.push(Gate::pass("bounds"));
            range
        }
        Err(err) => {
            let failed_gate = err.gate();
            if failed_gate != "max_len" {
                gates.push(Gate::pass("max_len"));
            }
            if !matches!(failed_gate, "alignment" | "max_len") {
                gates.push(Gate::pass("alignment"));
            }
            if !matches!(failed_gate, "checked_add" | "alignment" | "max_len") {
                gates.push(Gate::pass("checked_add"));
            }
            gates.push(Gate::fail(failed_gate));
            return Err((err, Some(memory_size), gates));
        }
    };

    Ok((range, gates))
}

fn range_indices(range: GuestRange) -> Result<(usize, usize), GuestAccessErr> {
    let start = usize::try_from(range.offset).map_err(|_| {
        (
            AbiError::MemoryRead("guest range offset does not fit host usize".into()),
            None,
            vec![Gate::fail("memory.index")],
        )
    })?;
    let end = usize::try_from(range.end).map_err(|_| {
        (
            AbiError::MemoryRead("guest range end does not fit host usize".into()),
            None,
            vec![Gate::fail("memory.index")],
        )
    })?;
    Ok((start, end))
}
