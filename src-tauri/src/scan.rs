#[derive(Debug)]
pub struct ScanResult {
    pub total_bytes: u64,
}

pub fn scan_stub() -> ScanResult {
    ScanResult { total_bytes: 0 }
}
