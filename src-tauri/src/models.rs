use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct Rule {
    pub id: String,
    pub title: String,
    pub description: String,
    pub category: String,
    pub risk: String,
    pub default_checked: bool,
    pub requires_admin: bool,
    pub rule_type: String,
    pub scope: String,
    pub path: Option<String>,
    pub pattern: Option<String>,
    pub size_threshold_mb: Option<i64>,
    pub age_threshold_days: Option<i64>,
    pub action: String,
    pub tool_cmd: Option<String>,
    pub enabled: bool,
    pub sort_order: i64,
    pub notes: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RuleView {
    pub id: String,
    pub title: String,
    pub description: String,
    pub category: String,
    pub risk: String,
    pub default_checked: bool,
    pub requires_admin: bool,
    pub rule_type: String,
    pub scope: String,
    pub path: Option<String>,
    pub pattern: Option<String>,
    pub size_threshold_mb: Option<i64>,
    pub age_threshold_days: Option<i64>,
    pub action: String,
    pub tool_cmd: Option<String>,
    pub enabled: bool,
    pub sort_order: i64,
    pub notes: Option<String>,
    pub blocked: bool,
    pub blocked_reason: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RuleScan {
    pub id: String,
    pub total_bytes: u64,
    pub file_count: u64,
    pub status: String,
    pub blocked: bool,
    pub blocked_reason: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CleanupItemReport {
    pub id: String,
    pub title: String,
    pub category: String,
    pub risk: String,
    pub total_bytes: u64,
    pub file_count: u64,
    pub status: String,
    pub message: Option<String>,
    pub drive: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CleanupSummary {
    pub total_bytes: u64,
    pub total_files: u64,
    pub by_category: Vec<SummaryBucket>,
    pub by_drive: Vec<SummaryBucket>,
}

#[derive(Debug, Serialize)]
pub struct SummaryBucket {
    pub key: String,
    pub bytes: u64,
    pub files: u64,
    pub percent: f64,
}

#[derive(Debug, Serialize)]
pub struct CleanupReport {
    pub items: Vec<CleanupItemReport>,
    pub summary: CleanupSummary,
}
