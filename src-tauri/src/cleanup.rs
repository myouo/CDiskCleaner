use std::collections::HashMap;
use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime};

use glob::Pattern;
use jwalk::WalkDir;

use crate::models::{CleanupItemReport, CleanupReport, CleanupSummary, Rule, SummaryBucket};

pub struct CleanupOptions {
    pub is_admin: bool,
}

pub fn cleanup_rules(rules: &[Rule], selected_ids: &[String], options: &CleanupOptions) -> CleanupReport {
    let mut items: Vec<CleanupItemReport> = Vec::new();

    for rule in rules.iter().filter(|rule| selected_ids.contains(&rule.id)) {
        if rule.requires_admin && !options.is_admin {
            items.push(CleanupItemReport {
                id: rule.id.clone(),
                title: rule.title.clone(),
                category: rule.category.clone(),
                risk: rule.risk.clone(),
                total_bytes: 0,
                file_count: 0,
                status: "blocked".to_string(),
                message: Some("Requires administrator privileges".to_string()),
                drive: None,
            });
            continue;
        }

        let report = match rule.rule_type.as_str() {
            "path" | "pattern" => cleanup_path_rule(rule),
            "special" => cleanup_tool_rule(rule),
            "registry" => cleanup_registry_rule(rule),
            "app_residue" => cleanup_residue_rule(rule),
            _ => CleanupItemReport {
                id: rule.id.clone(),
                title: rule.title.clone(),
                category: rule.category.clone(),
                risk: rule.risk.clone(),
                total_bytes: 0,
                file_count: 0,
                status: "unknown".to_string(),
                message: Some("Unknown rule type".to_string()),
                drive: None,
            },
        };
        items.push(report);
    }

    let summary = summarize(&items);
    CleanupReport { items, summary }
}

fn cleanup_tool_rule(rule: &Rule) -> CleanupItemReport {
    let mut report = base_report(rule);
    if rule.action != "tool_call" {
        report.status = "skipped".to_string();
        report.message = Some("Action not supported for special rule".to_string());
        return report;
    }
    let cmd = match &rule.tool_cmd {
        Some(cmd) => cmd,
        None => {
            report.status = "error".to_string();
            report.message = Some("Missing tool command".to_string());
            return report;
        }
    };
    let status = if cfg!(target_os = "windows") {
        Command::new("cmd").args(["/C", cmd]).status()
    } else {
        Command::new("sh").args(["-c", cmd]).status()
    };
    match status {
        Ok(exit) if exit.success() => {
            report.status = "ok".to_string();
        }
        Ok(exit) => {
            report.status = "error".to_string();
            report.message = Some(format!("Tool exit code: {:?}", exit.code()));
        }
        Err(err) => {
            report.status = "error".to_string();
            report.message = Some(err.to_string());
        }
    }
    report
}

fn cleanup_path_rule(rule: &Rule) -> CleanupItemReport {
    let mut report = base_report(rule);
    let base = match &rule.path {
        Some(path) => expand_percent_env(path),
        None => {
            report.status = "missing_path".to_string();
            return report;
        }
    };
    let base_path = PathBuf::from(&base);
    if !base_path.exists() {
        report.status = "missing".to_string();
        return report;
    }
    report.drive = drive_from_path(&base_path);

    let now = SystemTime::now();
    let age_threshold = rule
        .age_threshold_days
        .and_then(|days| days.try_into().ok())
        .map(|days: u64| Duration::from_secs(days * 24 * 60 * 60));
    let size_threshold = rule
        .size_threshold_mb
        .and_then(|mb| mb.try_into().ok())
        .map(|mb: u64| mb * 1024 * 1024);

    let pattern = rule.pattern.as_deref().map(normalize_pattern);
    let matcher = pattern
        .as_deref()
        .and_then(|p| Pattern::new(p).ok());

    let mut total_bytes: u64 = 0;
    let mut file_count: u64 = 0;
    let mut had_error = false;

    if base_path.is_file() {
        process_path(
            &base_path,
            &base_path,
            &matcher,
            now,
            age_threshold,
            size_threshold,
            rule.action.as_str(),
            &mut total_bytes,
            &mut file_count,
            &mut had_error,
        );
    } else {
        for entry in WalkDir::new(&base_path)
            .follow_links(false)
            .into_iter()
        {
            let entry = match entry {
                Ok(entry) => entry,
                Err(_) => {
                    had_error = true;
                    continue;
                }
            };
            if !entry.file_type().is_file() {
                continue;
            }
            let path = entry.path();
            process_path(
                &path,
                &base_path,
                &matcher,
                now,
                age_threshold,
                size_threshold,
                rule.action.as_str(),
                &mut total_bytes,
                &mut file_count,
                &mut had_error,
            );
        }
    }

    report.total_bytes = total_bytes;
    report.file_count = file_count;
    report.status = if had_error { "partial".to_string() } else { "ok".to_string() };
    report
}

fn cleanup_registry_rule(rule: &Rule) -> CleanupItemReport {
    let mut report = base_report(rule);
    if !cfg!(target_os = "windows") {
        report.status = "unsupported".to_string();
        report.message = Some("Registry cleanup only supported on Windows".to_string());
        return report;
    }
    let entries = registry_orphans();
    let mut cleaned = 0u64;
    let mut had_error = false;
    for entry in entries {
        if let Err(err) = delete_registry_key(&entry) {
            had_error = true;
            report.message = Some(err);
        } else {
            cleaned += 1;
        }
    }
    report.file_count = cleaned;
    report.status = if had_error { "partial".to_string() } else { "ok".to_string() };
    report.message = Some("Only orphan uninstall keys with missing InstallLocation were removed. Portable apps may be misdetected; review carefully.".to_string());
    report
}

fn cleanup_residue_rule(rule: &Rule) -> CleanupItemReport {
    let mut report = base_report(rule);
    let candidates = residue_candidates(rule.age_threshold_days);
    let mut total_bytes: u64 = 0;
    let mut file_count: u64 = 0;
    let mut had_error = false;
    for dir in candidates {
        let (bytes, files) = scan_directory(&dir, SystemTime::now(), None, None, None);
        total_bytes += bytes;
        file_count += files;
        if let Err(_) = std::fs::remove_dir_all(&dir) {
            had_error = true;
        }
    }
    report.total_bytes = total_bytes;
    report.file_count = file_count;
    report.status = if had_error { "partial".to_string() } else { "ok".to_string() };
    report.message = Some("Removed old folders not linked to uninstall records. Portable apps may be misdetected; review carefully.".to_string());
    report
}

fn process_path(
    path: &Path,
    base_path: &Path,
    matcher: &Option<Pattern>,
    now: SystemTime,
    age_threshold: Option<Duration>,
    size_threshold: Option<u64>,
    action: &str,
    total_bytes: &mut u64,
    file_count: &mut u64,
    had_error: &mut bool,
) {
    if let Some(matcher) = &matcher {
        if let Some(rel) = path.strip_prefix(&base_path).ok() {
            let rel_norm = normalize_path(rel);
            if !matcher.matches(&rel_norm) {
                return;
            }
        }
    }
    let meta = match path.metadata() {
        Ok(meta) => meta,
        Err(_) => {
            *had_error = true;
            return;
        }
    };
    if !should_count(&meta, now, age_threshold, size_threshold) {
        return;
    }
    *total_bytes += meta.len();
    *file_count += 1;

    if action == "recycle" {
        if let Err(_) = trash::delete(&path) {
            *had_error = true;
        }
    } else if let Err(_) = std::fs::remove_file(&path) {
        *had_error = true;
    }
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

fn base_report(rule: &Rule) -> CleanupItemReport {
    CleanupItemReport {
        id: rule.id.clone(),
        title: rule.title.clone(),
        category: rule.category.clone(),
        risk: rule.risk.clone(),
        total_bytes: 0,
        file_count: 0,
        status: "pending".to_string(),
        message: None,
        drive: None,
    }
}

fn summarize(items: &[CleanupItemReport]) -> CleanupSummary {
    let mut total_bytes: u64 = 0;
    let mut total_files: u64 = 0;
    let mut by_category: HashMap<String, (u64, u64)> = HashMap::new();
    let mut by_drive: HashMap<String, (u64, u64)> = HashMap::new();

    for item in items {
        if item.status != "ok" && item.status != "partial" {
            continue;
        }
        total_bytes += item.total_bytes;
        total_files += item.file_count;
        let category = item.category.clone();
        let entry = by_category.entry(category).or_insert((0, 0));
        entry.0 += item.total_bytes;
        entry.1 += item.file_count;

        if let Some(drive) = &item.drive {
            let entry = by_drive.entry(drive.clone()).or_insert((0, 0));
            entry.0 += item.total_bytes;
            entry.1 += item.file_count;
        }
    }

    let by_category = buckets_from_map(by_category, total_bytes);
    let by_drive = buckets_from_map(by_drive, total_bytes);

    CleanupSummary {
        total_bytes,
        total_files,
        by_category,
        by_drive,
    }
}

fn buckets_from_map(map: HashMap<String, (u64, u64)>, total: u64) -> Vec<SummaryBucket> {
    let mut buckets: Vec<SummaryBucket> = map
        .into_iter()
        .map(|(key, (bytes, files))| SummaryBucket {
            key,
            bytes,
            files,
            percent: if total == 0 {
                0.0
            } else {
                (bytes as f64 / total as f64) * 100.0
            },
        })
        .collect();
    buckets.sort_by(|a, b| b.bytes.cmp(&a.bytes));
    buckets
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

fn drive_from_path(path: &Path) -> Option<String> {
    let text = path.to_string_lossy();
    let mut chars = text.chars();
    let drive = chars.next()?;
    if chars.next() == Some(':') {
        Some(format!("{}:", drive))
    } else {
        None
    }
}

#[cfg(target_os = "windows")]
fn registry_orphans() -> Vec<String> {
    use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ};
    use winreg::RegKey;

    let mut orphans = Vec::new();
    let roots = [
        (HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall"),
        (HKEY_LOCAL_MACHINE, "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall"),
        (HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall"),
    ];
    for (hkey, path) in roots {
        let root = RegKey::predef(hkey);
        if let Ok(uninstall) = root.open_subkey_with_flags(path, KEY_READ) {
            for sub in uninstall.enum_keys().flatten() {
                if let Ok(app) = uninstall.open_subkey_with_flags(&sub, KEY_READ) {
                    let install: Result<String, _> = app.get_value("InstallLocation");
                    let display: Result<String, _> = app.get_value("DisplayName");
                    let uninstall_str: Result<String, _> = app.get_value("UninstallString");
                    let install_missing = install
                        .as_ref()
                        .map(|s| s.trim().is_empty() || !Path::new(s).exists())
                        .unwrap_or(true);
                    let display_missing = display.as_ref().map(|s| s.trim().is_empty()).unwrap_or(true);
                    let uninstall_missing = uninstall_str.as_ref().map(|s| s.trim().is_empty()).unwrap_or(true);
                    if install_missing && (display_missing || uninstall_missing) {
                        let full = format!("{}\\{}", path, sub);
                        orphans.push(full);
                    }
                }
            }
        }
    }
    orphans
}

#[cfg(not(target_os = "windows"))]
fn registry_orphans() -> Vec<String> {
    Vec::new()
}

#[cfg(target_os = "windows")]
fn delete_registry_key(subkey: &str) -> Result<(), String> {
    use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
    use winreg::RegKey;

    let (hkey, path) = if subkey.starts_with("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall")
        || subkey.starts_with("SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall")
    {
        (HKEY_LOCAL_MACHINE, subkey)
    } else {
        (HKEY_CURRENT_USER, subkey)
    };
    let root = RegKey::predef(hkey);
    root.delete_subkey_all(path).map_err(|e| e.to_string())
}

#[cfg(not(target_os = "windows"))]
fn delete_registry_key(_subkey: &str) -> Result<(), String> {
    Err("Not supported".to_string())
}

#[cfg(target_os = "windows")]
fn residue_candidates(age_threshold_days: Option<i64>) -> Vec<PathBuf> {
    use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ};
    use winreg::RegKey;

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

    let mut installed = Vec::new();
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
                                installed.push(PathBuf::from(loc));
                            }
                        }
                    }
                }
            }
        }
    }

    let cutoff = age_threshold_days.unwrap_or(180);
    let cutoff_duration = Duration::from_secs(cutoff as u64 * 24 * 60 * 60);
    let now = SystemTime::now();

    let mut candidates = Vec::new();
    for root in roots {
        if let Ok(entries) = std::fs::read_dir(&root) {
            for entry in entries.flatten() {
                let path = entry.path();
                if !path.is_dir() {
                    continue;
                }
                if installed.iter().any(|p| path.starts_with(p)) {
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

#[cfg(not(target_os = "windows"))]
fn residue_candidates(_age_threshold_days: Option<i64>) -> Vec<PathBuf> {
    Vec::new()
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
