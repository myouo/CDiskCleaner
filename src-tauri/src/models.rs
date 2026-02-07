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
