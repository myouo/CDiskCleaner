#[cfg(target_os = "windows")]
pub fn is_admin() -> bool {
    is_elevated::is_elevated()
}

#[cfg(not(target_os = "windows"))]
pub fn is_admin() -> bool {
    false
}
