use crate::abi::{
    ERR_ALIGN, ERR_ALLOC, ERR_BOUNDS, ERR_BUDGET, ERR_CAPABILITY, ERR_HEADER, ERR_TIMEOUT,
    ERR_TOO_LARGE, ERR_UTF8, OK,
};
use crate::config::Profile;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaseKind {
    RunExport,
    GrowthProbe,
    StaticAudit,
}

#[derive(Debug, Clone)]
pub enum GuestSource {
    Wat(String),
    Wasm(Vec<u8>),
}

impl GuestSource {
    pub fn wasm_bytes(&self) -> Result<Vec<u8>, String> {
        match self {
            Self::Wat(wat) => wat::parse_str(wat).map_err(|err| format!("WAT parse failed: {err}")),
            Self::Wasm(bytes) => Ok(bytes.clone()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct GuestCase {
    pub name: String,
    pub description: String,
    pub expected_code: i32,
    pub kind: CaseKind,
    pub category: String,
    pub severity: String,
    pub control: String,
    pub stage: String,
    pub ttp: String,
    pub detection: String,
    pub source_path: String,
    pub source: GuestSource,
}

pub fn all_cases() -> Vec<GuestCase> {
    vec![
        case(
            "good_packet",
            "valid repr(C)-style packet, aligned ptr, checked checksum",
            OK,
            CaseKind::RunExport,
            "abi",
            "info",
            "positive control: valid packet crosses the boundary",
            include_str!("../guests/good_packet.wat"),
        ),
        case(
            "boundary_valid_packet",
            "valid packet placed near the end of linear memory",
            OK,
            CaseKind::RunExport,
            "memory",
            "info",
            "positive control: near-boundary reads are allowed only when fully in-bounds",
            include_str!("../guests/boundary_valid_packet.wat"),
        ),
        case(
            "unaligned_packet",
            "guest passes ptr+1 with align=8",
            ERR_ALIGN,
            CaseKind::RunExport,
            "abi",
            "high",
            "reject misaligned structured ABI reads before touching memory",
            include_str!("../guests/unaligned_packet.wat"),
        ),
        case(
            "invalid_align_param",
            "guest passes unsupported alignment value align=3",
            ERR_ALIGN,
            CaseKind::RunExport,
            "abi",
            "medium",
            "reject invalid ABI contracts rather than normalizing them silently",
            include_str!("../guests/invalid_align_param.wat"),
        ),
        case(
            "ptr_len_overflow",
            "ptr + len wraps 32-bit linear-memory address space",
            ERR_BOUNDS,
            CaseKind::RunExport,
            "memory",
            "critical",
            "use checked_add for every guest-controlled pointer range",
            include_str!("../guests/ptr_len_overflow.wat"),
        ),
        case(
            "out_of_bounds",
            "range fits u32 but exceeds current linear memory",
            ERR_BOUNDS,
            CaseKind::RunExport,
            "memory",
            "critical",
            "compare checked end offset against current MemoryView size",
            include_str!("../guests/out_of_bounds.wat"),
        ),
        case(
            "bad_magic",
            "aligned and in-bounds packet with invalid ABI magic",
            ERR_HEADER,
            CaseKind::RunExport,
            "abi",
            "medium",
            "validate fixed header magic before interpreting payload",
            include_str!("../guests/bad_magic.wat"),
        ),
        case(
            "bad_version",
            "valid magic with unsupported ABI version",
            ERR_HEADER,
            CaseKind::RunExport,
            "abi",
            "medium",
            "version explicit ABI formats and reject unsupported contracts",
            include_str!("../guests/bad_version.wat"),
        ),
        case(
            "body_len_mismatch",
            "packet declares a body length that does not match payload bytes",
            ERR_HEADER,
            CaseKind::RunExport,
            "abi",
            "high",
            "validate nested lengths after the outer range has passed",
            include_str!("../guests/body_len_mismatch.wat"),
        ),
        case(
            "checksum_mismatch",
            "packet body length is valid but checksum does not match",
            ERR_HEADER,
            CaseKind::RunExport,
            "integrity",
            "medium",
            "validate integrity fields after parsing little-endian layout",
            include_str!("../guests/checksum_mismatch.wat"),
        ),
        case(
            "packet_too_large",
            "guest asks host to copy more bytes than ABI policy allows",
            ERR_TOO_LARGE,
            CaseKind::RunExport,
            "resource",
            "high",
            "cap host-side copies before allocating buffers",
            include_str!("../guests/packet_too_large.wat"),
        ),
        case(
            "truncated_header",
            "guest points at too few bytes for the fixed ABI header",
            ERR_HEADER,
            CaseKind::RunExport,
            "abi",
            "medium",
            "minimum fixed-header length is checked before field reads",
            include_str!("../guests/truncated_header.wat"),
        ),
        case(
            "zero_length_packet",
            "guest passes an empty range to a structured packet import",
            ERR_HEADER,
            CaseKind::RunExport,
            "abi",
            "medium",
            "zero-length ranges cannot bypass minimum header validation",
            include_str!("../guests/zero_length_packet.wat"),
        ),
        case(
            "capability_escape",
            "guest asks host import for /etc/passwd without a capability",
            ERR_CAPABILITY,
            CaseKind::RunExport,
            "capability",
            "critical",
            "default deny: no host path access without explicit allow-list",
            include_str!("../guests/capability_escape.wat"),
        ),
        case(
            "path_traversal",
            "guest tries a traversal-looking sandbox path",
            ERR_CAPABILITY,
            CaseKind::RunExport,
            "capability",
            "high",
            "capability strings are exact grants, not path-prefix guesses",
            include_str!("../guests/path_traversal.wat"),
        ),
        case(
            "capability_allowed",
            "same import path shape, but with explicit allow-list capability",
            OK,
            CaseKind::RunExport,
            "capability",
            "info",
            "positive control: only the granted path is accepted",
            include_str!("../guests/capability_allowed.wat"),
        ),
        case(
            "null_byte_capability",
            "guest embeds a NUL byte after an allowed-looking path prefix",
            ERR_CAPABILITY,
            CaseKind::RunExport,
            "capability",
            "high",
            "treat strings as length-delimited UTF-8, never C-string prefixes",
            include_str!("../guests/null_byte_capability.wat"),
        ),
        case(
            "invalid_utf8_path",
            "guest sends non-UTF8 bytes into a string ABI",
            ERR_UTF8,
            CaseKind::RunExport,
            "capability",
            "medium",
            "decode guest strings as fallible UTF-8 before policy decisions",
            include_str!("../guests/invalid_utf8_path.wat"),
        ),
        case(
            "cap_string_too_large",
            "guest passes an oversized string length to a capability import",
            ERR_TOO_LARGE,
            CaseKind::RunExport,
            "resource",
            "high",
            "cap string lengths before copying guest memory",
            include_str!("../guests/cap_string_too_large.wat"),
        ),
        case(
            "excessive_alloc",
            "guest tries to force a large host allocation through an import",
            ERR_ALLOC,
            CaseKind::RunExport,
            "resource",
            "high",
            "apply allocation caps before Vec reserve or host-side allocation",
            include_str!("../guests/excessive_alloc.wat"),
        ),
        case(
            "cpu_metered_loop",
            "guest burns host fuel via tick import and gets stopped deterministically",
            ERR_BUDGET,
            CaseKind::RunExport,
            "resource",
            "high",
            "budget guest-driven host imports; using Singlepass for JIT-bomb protection",
            include_str!("../guests/cpu_metered_loop.wat"),
        ),
        case(
            "excessive_memory",
            "guest requests more memory pages than policy allows",
            ERR_TOO_LARGE,
            CaseKind::RunExport,
            "resource",
            "high",
            "reject over-large memories during static module audit before instantiation",
            include_str!("../guests/excessive_memory.wat"),
        ),
        case(
            "non_cooperative_loop",
            "guest has an infinite loop and no cooperative tick import",
            ERR_TIMEOUT,
            CaseKind::StaticAudit,
            "resource",
            "high",
            "reject unmetered modules before an in-process run can hang the host",
            include_str!("../guests/non_cooperative_loop.wat"),
        ),
        case(
            "memory_grow_probe",
            "guest grows memory; host telemetry reacquires a fresh MemoryView",
            OK,
            CaseKind::GrowthProbe,
            "memory",
            "high",
            "drop stale MemoryView state and reacquire views after guest calls",
            include_str!("../guests/memory_grow_probe.wat"),
        ),
        case(
            "zero_copy_write_probe",
            "host writes a marker directly into guest linear memory",
            OK,
            CaseKind::RunExport,
            "memory",
            "info",
            "positive control: host writes through a validated guest pointer without an intermediate buffer",
            include_str!("../guests/zero_copy_write_probe.wat"),
        ),
    ]
}

pub fn find_case(name: &str) -> Option<GuestCase> {
    all_cases().into_iter().find(|case| case.name == name)
}

pub fn profile_cases(profile: Profile) -> Vec<GuestCase> {
    match profile {
        Profile::All => all_cases(),
        Profile::Interview => interview_cases(),
        Profile::Campaign => campaign_cases(),
        Profile::Abi => cases_by_category(&["abi", "integrity"]),
        Profile::Capability => cases_by_category(&["capability"]),
        Profile::Resource => cases_by_category(&["resource"]),
        Profile::Memory => cases_by_category(&["memory"]),
    }
}

pub fn interview_cases() -> Vec<GuestCase> {
    [
        "good_packet",
        "ptr_len_overflow",
        "invalid_align_param",
        "out_of_bounds",
        "body_len_mismatch",
        "checksum_mismatch",
        "capability_escape",
        "capability_allowed",
        "null_byte_capability",
        "excessive_alloc",
        "cpu_metered_loop",
        "non_cooperative_loop",
        "excessive_memory",
        "zero_length_packet",
        "memory_grow_probe",
        "zero_copy_write_probe",
    ]
    .iter()
    .filter_map(|name| find_case(name))
    .collect()
}

pub fn campaign_cases() -> Vec<GuestCase> {
    [
        "good_packet",
        "bad_version",
        "body_len_mismatch",
        "checksum_mismatch",
        "ptr_len_overflow",
        "out_of_bounds",
        "capability_escape",
        "path_traversal",
        "null_byte_capability",
        "cap_string_too_large",
        "excessive_alloc",
        "cpu_metered_loop",
        "non_cooperative_loop",
        "excessive_memory",
        "memory_grow_probe",
        "zero_copy_write_probe",
    ]
    .iter()
    .filter_map(|name| find_case(name))
    .collect()
}

fn cases_by_category(categories: &[&str]) -> Vec<GuestCase> {
    all_cases()
        .into_iter()
        .filter(|case| categories.contains(&case.category.as_str()))
        .collect()
}

#[expect(
    clippy::too_many_arguments,
    reason = "built-in case table mirrors corpus metadata"
)]
fn case(
    name: &'static str,
    description: &'static str,
    expected_code: i32,
    kind: CaseKind,
    category: &'static str,
    severity: &'static str,
    control: &'static str,
    wat: &'static str,
) -> GuestCase {
    let intel = threat_intel(name, category);
    GuestCase {
        name: name.into(),
        description: description.into(),
        expected_code,
        kind,
        category: category.into(),
        severity: severity.into(),
        control: control.into(),
        stage: intel.stage.into(),
        ttp: intel.ttp.into(),
        detection: intel.detection.into(),
        source_path: format!("guests/{name}.wat"),
        source: GuestSource::Wat(wat.into()),
    }
}

struct ThreatIntel {
    stage: &'static str,
    ttp: &'static str,
    detection: &'static str,
}

fn threat_intel(name: &str, category: &str) -> ThreatIntel {
    match name {
        "good_packet" | "boundary_valid_packet" | "capability_allowed" => ThreatIntel {
            stage: "baseline",
            ttp: "positive-control",
            detection: "valid traffic proves controls are precise, not blanket-deny",
        },
        "bad_version" => ThreatIntel {
            stage: "supply-chain validation",
            ttp: "abi-contract-drift",
            detection: "unsupported guest ABI version is denied before payload parsing",
        },
        "bad_magic" | "truncated_header" | "zero_length_packet" => ThreatIntel {
            stage: "payload validation",
            ttp: "malformed-abi-message",
            detection: "fixed packet header gates reject malformed guest-controlled ranges",
        },
        "body_len_mismatch" | "checksum_mismatch" => ThreatIntel {
            stage: "payload integrity",
            ttp: "schema-confusion",
            detection: "nested packet length and checksum gates catch forged payload metadata",
        },
        "unaligned_packet" | "invalid_align_param" => ThreatIntel {
            stage: "abi probing",
            ttp: "misaligned-host-read",
            detection: "alignment gates reject invalid structured reads before memory access",
        },
        "ptr_len_overflow" | "out_of_bounds" => ThreatIntel {
            stage: "memory-boundary probing",
            ttp: "guest-pointer-confusion",
            detection: "checked arithmetic and MemoryView bounds gates deny unsafe ranges",
        },
        "memory_grow_probe" => ThreatIntel {
            stage: "runtime state mutation",
            ttp: "linear-memory-growth",
            detection: "telemetry records memory growth and fresh MemoryView reacquisition",
        },
        "zero_copy_write_probe" => ThreatIntel {
            stage: "host-boundary validation",
            ttp: "guest-pointer-output-buffer",
            detection: "host writes are scoped to validated MemoryView ranges and logged as direct memory writes",
        },
        "capability_escape" | "path_traversal" | "null_byte_capability" => ThreatIntel {
            stage: "capability escalation",
            ttp: "host-capability-abuse",
            detection: "exact allow-list capability checks deny path escape attempts",
        },
        "invalid_utf8_path" => ThreatIntel {
            stage: "capability escalation",
            ttp: "string-decoder-confusion",
            detection: "fallible UTF-8 decoding runs before capability policy decisions",
        },
        "cap_string_too_large" => ThreatIntel {
            stage: "capability escalation",
            ttp: "oversized-string-copy",
            detection: "string length cap denies copy before host allocation",
        },
        "excessive_alloc" => ThreatIntel {
            stage: "resource pressure",
            ttp: "host-allocation-pressure",
            detection: "allocation cap denies request before Vec reserve",
        },
        "cpu_metered_loop" => ThreatIntel {
            stage: "resource pressure",
            ttp: "cooperative-cpu-exhaustion",
            detection: "host.tick fuel records guest progress and denies after budget exhaustion",
        },
        "non_cooperative_loop" => ThreatIntel {
            stage: "containment validation",
            ttp: "unmetered-cpu-loop",
            detection: "static audit blocks in-process execution; supervisor can enforce timeout",
        },
        "excessive_memory" => ThreatIntel {
            stage: "containment validation",
            ttp: "memory-declaration-abuse",
            detection: "module audit rejects over-large memory before instantiation",
        },
        _ => default_threat_intel(category),
    }
}

fn default_threat_intel(category: &str) -> ThreatIntel {
    match category {
        "abi" => ThreatIntel {
            stage: "abi probing",
            ttp: "guest-host-contract-abuse",
            detection: "ABI gates reject malformed import arguments before host work",
        },
        "capability" => ThreatIntel {
            stage: "capability escalation",
            ttp: "host-capability-abuse",
            detection: "capability policy denies ungranted host-side authority",
        },
        "resource" => ThreatIntel {
            stage: "resource pressure",
            ttp: "sandbox-resource-exhaustion",
            detection: "resource gates deny CPU, memory, or allocation abuse",
        },
        "memory" => ThreatIntel {
            stage: "memory-boundary probing",
            ttp: "guest-pointer-confusion",
            detection: "memory gates deny unsafe linear-memory access",
        },
        _ => ThreatIntel {
            stage: "host-boundary validation",
            ttp: "host-import-abuse",
            detection: "host import telemetry records the boundary decision",
        },
    }
}
