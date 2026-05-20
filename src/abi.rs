use std::fmt;

pub const OK: i32 = 0;
pub const ERR_BOUNDS: i32 = -1;
pub const ERR_ALIGN: i32 = -2;
pub const ERR_HEADER: i32 = -3;
pub const ERR_CAPABILITY: i32 = -4;
pub const ERR_ALLOC: i32 = -5;
pub const ERR_BUDGET: i32 = -6;
pub const ERR_INTERNAL: i32 = -7;
pub const ERR_TOO_LARGE: i32 = -8;
pub const ERR_UTF8: i32 = -9;
pub const ERR_TIMEOUT: i32 = -10;

pub const PACKET_MAGIC: u32 = 0x5447_5357;
pub const PACKET_HEADER_LEN: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AbiError {
    MissingMemory,
    InvalidAlignment(u32),
    Misaligned {
        ptr: u32,
        align: u32,
    },
    PtrLenOverflow {
        ptr: u32,
        len: u32,
    },
    OutOfBounds {
        ptr: u32,
        len: u32,
        end: u32,
        memory_size: u64,
    },
    TooLarge {
        len: u32,
        max: u32,
    },
    MemoryRead(String),
    PacketTooShort {
        len: usize,
    },
    BadMagic(u32),
    BadVersion(u16),
    PacketLengthMismatch {
        declared: u32,
        actual: usize,
    },
    BadChecksum {
        expected: u32,
        actual: u32,
    },
    InvalidUtf8,
    CapabilityDenied(String),
    AllocationTooLarge {
        requested: u32,
        max: u32,
    },
    BudgetExhausted,
}

impl AbiError {
    pub fn code(&self) -> i32 {
        match self {
            Self::OutOfBounds { .. } | Self::PtrLenOverflow { .. } => ERR_BOUNDS,
            Self::InvalidAlignment(_) | Self::Misaligned { .. } => ERR_ALIGN,
            Self::PacketTooShort { .. }
            | Self::BadMagic(_)
            | Self::BadVersion(_)
            | Self::PacketLengthMismatch { .. }
            | Self::BadChecksum { .. } => ERR_HEADER,
            Self::CapabilityDenied(_) => ERR_CAPABILITY,
            Self::AllocationTooLarge { .. } => ERR_ALLOC,
            Self::BudgetExhausted => ERR_BUDGET,
            Self::TooLarge { .. } => ERR_TOO_LARGE,
            Self::InvalidUtf8 => ERR_UTF8,
            Self::MissingMemory | Self::MemoryRead(_) => ERR_INTERNAL,
        }
    }

    pub fn gate(&self) -> &'static str {
        match self {
            Self::MissingMemory => "memory.export",
            Self::InvalidAlignment(_) | Self::Misaligned { .. } => "alignment",
            Self::PtrLenOverflow { .. } => "checked_add",
            Self::OutOfBounds { .. } => "bounds",
            Self::TooLarge { .. } => "max_len",
            Self::MemoryRead(_) => "memory.read",
            Self::PacketTooShort { .. }
            | Self::BadMagic(_)
            | Self::BadVersion(_)
            | Self::PacketLengthMismatch { .. } => "packet.header",
            Self::BadChecksum { .. } => "packet.checksum",
            Self::InvalidUtf8 => "utf8",
            Self::CapabilityDenied(_) => "capability",
            Self::AllocationTooLarge { .. } => "alloc.cap",
            Self::BudgetExhausted => "fuel",
        }
    }
}

impl fmt::Display for AbiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingMemory => write!(f, "guest did not export linear memory"),
            Self::InvalidAlignment(align) => write!(f, "invalid alignment {align}"),
            Self::Misaligned { ptr, align } => {
                write!(f, "ptr 0x{ptr:08x} is not aligned to {align}")
            }
            Self::PtrLenOverflow { ptr, len } => {
                write!(f, "ptr + len overflow: 0x{ptr:08x} + {len}")
            }
            Self::OutOfBounds {
                ptr,
                len,
                end,
                memory_size,
            } => write!(
                f,
                "range [0x{ptr:08x}, 0x{end:08x}) len={len} exceeds memory_size={memory_size}"
            ),
            Self::TooLarge { len, max } => write!(f, "len {len} exceeds policy max {max}"),
            Self::MemoryRead(err) => write!(f, "memory read failed: {err}"),
            Self::PacketTooShort { len } => {
                write!(
                    f,
                    "packet len {len} smaller than {PACKET_HEADER_LEN}-byte header"
                )
            }
            Self::BadMagic(magic) => write!(f, "bad packet magic 0x{magic:08x}"),
            Self::BadVersion(version) => write!(f, "unsupported packet version {version}"),
            Self::PacketLengthMismatch { declared, actual } => write!(
                f,
                "packet body_len declared {declared}, actual payload bytes {actual}"
            ),
            Self::BadChecksum { expected, actual } => {
                write!(
                    f,
                    "bad checksum expected 0x{expected:08x}, actual 0x{actual:08x}"
                )
            }
            Self::InvalidUtf8 => write!(f, "guest bytes are not valid UTF-8"),
            Self::CapabilityDenied(path) => {
                write!(f, "capability denied for {}", escape_guest_string(path))
            }
            Self::AllocationTooLarge { requested, max } => {
                write!(f, "allocation request {requested} exceeds cap {max}")
            }
            Self::BudgetExhausted => write!(f, "guest fuel budget exhausted"),
        }
    }
}

fn escape_guest_string(value: &str) -> String {
    value.chars().flat_map(char::escape_default).collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuestRange {
    pub ptr: u32,
    pub len: u32,
    pub end: u32,
    pub offset: u64,
}

pub fn checked_guest_range(
    ptr: u32,
    len: u32,
    align: u32,
    memory_size: u64,
    max_len: u32,
) -> Result<GuestRange, AbiError> {
    if !matches!(align, 1 | 2 | 4 | 8 | 16) {
        return Err(AbiError::InvalidAlignment(align));
    }

    if len > max_len {
        return Err(AbiError::TooLarge { len, max: max_len });
    }

    if align > 1 && !ptr.is_multiple_of(align) {
        return Err(AbiError::Misaligned { ptr, align });
    }

    let end = ptr
        .checked_add(len)
        .ok_or(AbiError::PtrLenOverflow { ptr, len })?;

    if u64::from(end) > memory_size {
        return Err(AbiError::OutOfBounds {
            ptr,
            len,
            end,
            memory_size,
        });
    }

    Ok(GuestRange {
        ptr,
        len,
        end,
        offset: u64::from(ptr),
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    pub version: u16,
    pub flags: u16,
    pub body_len: u32,
    pub checksum: u32,
}

pub fn parse_packet(bytes: &[u8]) -> Result<Packet, AbiError> {
    if bytes.len() < PACKET_HEADER_LEN {
        return Err(AbiError::PacketTooShort { len: bytes.len() });
    }

    let magic = u32::from_le_bytes(
        bytes[0..4]
            .try_into()
            .map_err(|_| AbiError::PacketTooShort { len: bytes.len() })?,
    );
    if magic != PACKET_MAGIC {
        return Err(AbiError::BadMagic(magic));
    }

    let version = u16::from_le_bytes(
        bytes[4..6]
            .try_into()
            .map_err(|_| AbiError::PacketTooShort { len: bytes.len() })?,
    );
    if version != 1 {
        return Err(AbiError::BadVersion(version));
    }

    let flags = u16::from_le_bytes(
        bytes[6..8]
            .try_into()
            .map_err(|_| AbiError::PacketTooShort { len: bytes.len() })?,
    );
    let body_len = u32::from_le_bytes(
        bytes[8..12]
            .try_into()
            .map_err(|_| AbiError::PacketTooShort { len: bytes.len() })?,
    );
    let checksum = u32::from_le_bytes(
        bytes[12..16]
            .try_into()
            .map_err(|_| AbiError::PacketTooShort { len: bytes.len() })?,
    );
    let body = &bytes[PACKET_HEADER_LEN..];

    if body.len() != body_len as usize {
        return Err(AbiError::PacketLengthMismatch {
            declared: body_len,
            actual: body.len(),
        });
    }

    let actual = checksum32(body);
    if checksum != actual {
        return Err(AbiError::BadChecksum {
            expected: checksum,
            actual,
        });
    }

    Ok(Packet {
        version,
        flags,
        body_len,
        checksum,
    })
}

pub fn checksum32(bytes: &[u8]) -> u32 {
    bytes
        .iter()
        .fold(0u32, |acc, byte| acc.wrapping_add(u32::from(*byte)))
}

pub fn code_name(code: i32) -> &'static str {
    match code {
        OK => "OK",
        ERR_BOUNDS => "ERR_BOUNDS",
        ERR_ALIGN => "ERR_ALIGN",
        ERR_HEADER => "ERR_HEADER",
        ERR_CAPABILITY => "ERR_CAPABILITY",
        ERR_ALLOC => "ERR_ALLOC",
        ERR_BUDGET => "ERR_BUDGET",
        ERR_INTERNAL => "ERR_INTERNAL",
        ERR_TOO_LARGE => "ERR_TOO_LARGE",
        ERR_UTF8 => "ERR_UTF8",
        ERR_TIMEOUT => "ERR_TIMEOUT",
        _ => "UNKNOWN",
    }
}

pub fn parse_code_name(value: &str) -> Option<i32> {
    match value {
        "OK" => Some(OK),
        "ERR_BOUNDS" => Some(ERR_BOUNDS),
        "ERR_ALIGN" => Some(ERR_ALIGN),
        "ERR_HEADER" => Some(ERR_HEADER),
        "ERR_CAPABILITY" => Some(ERR_CAPABILITY),
        "ERR_ALLOC" => Some(ERR_ALLOC),
        "ERR_BUDGET" => Some(ERR_BUDGET),
        "ERR_INTERNAL" => Some(ERR_INTERNAL),
        "ERR_TOO_LARGE" => Some(ERR_TOO_LARGE),
        "ERR_UTF8" => Some(ERR_UTF8),
        "ERR_TIMEOUT" => Some(ERR_TIMEOUT),
        _ => value.parse().ok(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checked_range_rejects_u32_overflow() {
        let err = checked_guest_range(u32::MAX - 15, 64, 8, 65_536, 4096).unwrap_err();
        assert_eq!(err.code(), ERR_BOUNDS);
        assert_eq!(err.gate(), "checked_add");
    }

    #[test]
    fn checked_range_rejects_misalignment_before_reading() {
        let err = checked_guest_range(65, 16, 8, 65_536, 4096).unwrap_err();
        assert_eq!(err.code(), ERR_ALIGN);
    }

    #[test]
    fn packet_parser_checks_checksum() {
        let mut packet = *b"WSGT\x01\0\x02\0\x05\0\0\0\x74\x01\0\0HELLO";
        assert!(parse_packet(&packet).is_ok());
        packet[20] = b'!';
        assert_eq!(parse_packet(&packet).unwrap_err().code(), ERR_HEADER);
    }
}
