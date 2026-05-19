#[derive(Debug, Clone)]
pub struct Gate {
    pub name: &'static str,
    pub passed: bool,
}

impl Gate {
    pub fn pass(name: &'static str) -> Self {
        Self { name, passed: true }
    }

    pub fn fail(name: &'static str) -> Self {
        Self {
            name,
            passed: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ImportEvent {
    pub import: &'static str,
    pub ptr: Option<u32>,
    pub len: Option<u32>,
    pub align: Option<u32>,
    pub memory_size: Option<u64>,
    pub result_code: i32,
    pub detail: String,
    pub elapsed_us: u128,
    pub gates: Vec<Gate>,
}

impl ImportEvent {
    pub fn decision(&self) -> &'static str {
        if self.result_code == crate::abi::OK {
            "ALLOW"
        } else {
            "DENY"
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct Telemetry {
    pub events: Vec<ImportEvent>,
    pub ticks_seen: u32,
}

impl Telemetry {
    pub fn push(&mut self, event: ImportEvent) {
        self.events.push(event);
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct MemorySnapshot {
    pub pages: u32,
    pub bytes: u64,
    pub data_ptr: usize,
}

impl MemorySnapshot {
    pub fn delta_pages(self, other: Self) -> i64 {
        i64::from(other.pages) - i64::from(self.pages)
    }
}
