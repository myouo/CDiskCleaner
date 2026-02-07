use std::env;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use glob::Pattern;
use jwalk::WalkDir;

use crate::models::{Rule, RuleScan};

pub struct ScanOptions {
    pub is_admin: bool,
}

pub fn scan_rules(rules: &[Rule], options: &ScanOptions) -> Vec<RuleScan> {
    rules
        .iter()
        .map(|rule| scan_rule(rule, options))
        .collect()
}

fn scan_rule(rule: &Rule, options: &ScanOptions) -> RuleScan {
    if rule.requires_admin && !options.is_admin {
        return RuleScan {
            id: rule.id.clone(),
            total_bytes: 0,
            file_count: 0,
            status: "blocked".to_string(),
            blocked: true,
            blocked_reason: Some("Requires administrator privileges".to_string()),
        };
    }

    if rule.rule_type != "path" && rule.rule_type != "pattern" && rule.rule_type != "app_residue" {
        return RuleScan {
            id: rule.id.clone(),
            total_bytes: 0,
            file_count: 0,
            status: "unsupported".to_string(),
            blocked: false,
            blocked_reason: None,
        };
    }

    let now = SystemTime::now();
    let age_threshold = rule
        .age_threshold_days
        .and_then(|days| days.try_into().ok())
        .map(|days: u64| Duration::from_secs(days * 24 * 60 * 60));
    let size_threshold = rule
        .size_threshold_mb
        .and_then(|mb| mb.try_into().ok())
        .map(|mb: u64| mb * 1024 * 1024);

    let mut total_bytes: u64 = 0;
    let mut file_count: u64 = 0;

    if rule.rule_type == "app_residue" {
        let candidates = residue_candidates(rule.age_threshold_days);
        for dir in candidates {
            let (bytes, files) = scan_directory(&dir, now, age_threshold, size_threshold, None);
            total_bytes += bytes;
            file_count += files;
        }
    } else {
        let base = match &rule.path {
            Some(path) => expand_percent_env(path),
            None => {
                return RuleScan {
                    id: rule.id.clone(),
                    total_bytes: 0,
                    file_count: 0,
                    status: "missing_path".to_string(),
                    blocked: false,
                    blocked_reason: None,
                }
            }
        };
        let base_path = PathBuf::from(base);
        if !base_path.exists() {
            return RuleScan {
                id: rule.id.clone(),
                total_bytes: 0,
                file_count: 0,
                status: "missing".to_string(),
                blocked: false,
                blocked_reason: None,
            };
        }
        if rule.rule_type == "path" && base_path.is_file() {
            if let Ok(meta) = base_path.metadata() {
                if should_count(&meta, now, age_threshold, size_threshold) {
                    total_bytes += meta.len();
                    file_count += 1;
                }
            }
        } else {
            let pattern = rule.pattern.as_deref().map(normalize_pattern);
            let matcher = pattern
                .as_deref()
                .and_then(|p| Pattern::new(p).ok());

            let (bytes, files) = scan_directory(&base_path, now, age_threshold, size_threshold, matcher.as_ref());
            total_bytes += bytes;
            file_count += files;
        }
    }

    RuleScan {
        id: rule.id.clone(),
        total_bytes,
        file_count,
        status: "ok".to_string(),
        blocked: false,
        blocked_reason: None,
    }
}

fn scan_directory(
    base_path: &Path,
    now: SystemTime,
    age_threshold: Option<Duration>,
    size_threshold: Option<u64>,
    matcher: Option<&Pattern>,
) -> (u64, u64) {
    let mut total_bytes: u64 = 0;
    let mut file_count: u64 = 0;
    for entry in WalkDir::new(base_path)
        .follow_links(false)
        .into_iter()
    {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => continue,
        };
        if !entry.file_type().is_file() {
            continue;
        }
        if let Some(matcher) = matcher {
            if let Some(rel) = entry.path().strip_prefix(base_path).ok() {
                let rel_norm = normalize_path(rel);
                if !matcher.matches(&rel_norm) {
                    continue;
                }
            }
        }
        let meta = match entry.metadata() {
            Ok(meta) => meta,
            Err(_) => continue,
        };
        if !should_count(&meta, now, age_threshold, size_threshold) {
            continue;
        }
        total_bytes += meta.len();
        file_count += 1;
    }
    (total_bytes, file_count)
}

fn residue_candidates(age_threshold_days: Option<i64>) -> Vec<PathBuf> {
    let mut roots: Vec<PathBuf> = Vec::new();
    let env_keys = [
        "ProgramFiles",
        "ProgramFiles(x86)",
        "ProgramData",
        "LOCALAPPDATA",
        "APPDATA",
    ];
    for key in env_keys {
        if let Ok(val) = env::var(key) {
            roots.push(PathBuf::from(val));
        }
    }
    let cutoff = age_threshold_days.unwrap_or(180);
    let cutoff_duration = Duration::from_secs(cutoff as u64 * 24 * 60 * 60);
    let now = SystemTime::now();
    let installed = installed_paths();

    let mut candidates = Vec::new();
    for root in roots {
        if let Ok(entries) = std::fs::read_dir(&root) {
            for entry in entries.flatten() {
                let path = entry.path();
                if !path.is_dir() {
                    continue;
                }
                if is_under_installed(&path, &installed) {
                    continue;
                }
                if let Ok(meta) = entry.metadata() {
                    if let Ok(modified) = meta.modified() {
                        if let Ok(age) = now.duration_since(modified) {
                            if age >= cutoff_duration {
                                candidates.push(path);
                            }
                        }
                    }
                }
            }
        }
    }
    candidates
}

fn is_under_installed(path: &Path, installed: &[PathBuf]) -> bool {
    installed.iter().any(|p| path.starts_with(p))
}

#[cfg(target_os = "windows")]
fn installed_paths() -> Vec<PathBuf> {
    use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ};
    use winreg::RegKey;

    let mut paths = Vec::new();
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let keys = [
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
        "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
    ];

    for root in [hklm, hkcu] {
        for key in keys {
            if let Ok(uninstall) = root.open_subkey_with_flags(key, KEY_READ) {
                for sub in uninstall.enum_keys().flatten() {
                    if let Ok(app) = uninstall.open_subkey_with_flags(sub, KEY_READ) {
                        if let Ok(loc) = app.get_value::<String, _>("InstallLocation") {
                            if !loc.trim().is_empty() {
                                paths.push(PathBuf::from(loc));
                            }
                        }
                    }
                }
            }
        }
    }
    paths
}

#[cfg(not(target_os = "windows"))]
fn installed_paths() -> Vec<PathBuf> {
    Vec::new()
}

fn should_count(
    meta: &std::fs::Metadata,
    now: SystemTime,
    age_threshold: Option<Duration>,
    size_threshold: Option<u64>,
) -> bool {
    if let Some(min_size) = size_threshold {
        if meta.len() < min_size {
            return false;
        }
    }
    if let Some(min_age) = age_threshold {
        if let Ok(modified) = meta.modified() {
            if let Ok(age) = now.duration_since(modified) {
                if age < min_age {
                    return false;
                }
            }
        }
    }
    true
}

fn expand_percent_env(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '%' {
            let mut var = String::new();
            while let Some(&next) = chars.peek() {
                chars.next();
                if next == '%' {
                    break;
                }
                var.push(next);
            }
            if var.is_empty() {
                out.push('%');
                continue;
            }
            if let Ok(val) = env::var(&var) {
                out.push_str(&val);
            } else {
                out.push('%');
                out.push_str(&var);
                out.push('%');
            }
        } else {
            out.push(ch);
        }
    }
    out
}

fn normalize_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn normalize_pattern(pattern: &str) -> String {
    pattern.replace('\\', "/")
}
