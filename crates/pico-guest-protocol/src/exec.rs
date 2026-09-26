/// Wire format: exit_code (i32, big-endian, 4 bytes) + duration_ms (u64, big-endian, 8 bytes).
pub fn parse_exec_exit(payload: &[u8]) -> (i32, u64) {
    let exit_code = payload
        .get(..4)
        .and_then(|b| b.try_into().ok())
        .map(i32::from_be_bytes)
        .unwrap_or(0);
    let duration_ms = payload
        .get(4..12)
        .and_then(|b| b.try_into().ok())
        .map(u64::from_be_bytes)
        .unwrap_or(0);
    (exit_code, duration_ms)
}
