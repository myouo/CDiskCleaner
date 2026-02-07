use rusqlite::Connection;

use crate::models::{Rule, RuleView};

pub fn list_rules(conn: &Connection) -> rusqlite::Result<Vec<Rule>> {
    let mut stmt = conn.prepare(
        "SELECT id, title, description, category, risk, default_checked, requires_admin,
                rule_type, scope, path, pattern, size_threshold_mb, age_threshold_days,
                action, tool_cmd, enabled, sort_order, notes
         FROM rules
         WHERE enabled = 1
         ORDER BY sort_order, category, title",
    )?;

    let rows = stmt.query_map([], |row| {
        Ok(Rule {
            id: row.get(0)?,
            title: row.get(1)?,
            description: row.get(2)?,
            category: row.get(3)?,
            risk: row.get(4)?,
            default_checked: row.get::<_, i64>(5)? != 0,
            requires_admin: row.get::<_, i64>(6)? != 0,
            rule_type: row.get(7)?,
            scope: row.get(8)?,
            path: row.get(9)?,
            pattern: row.get(10)?,
            size_threshold_mb: row.get(11)?,
            age_threshold_days: row.get(12)?,
            action: row.get(13)?,
            tool_cmd: row.get(14)?,
            enabled: row.get::<_, i64>(15)? != 0,
            sort_order: row.get(16)?,
            notes: row.get(17)?,
        })
    })?;

    let mut out = Vec::new();
    for item in rows {
        out.push(item?);
    }
    Ok(out)
}

pub fn list_rules_with_privilege(conn: &Connection, is_admin: bool) -> rusqlite::Result<Vec<RuleView>> {
    let rules = list_rules(conn)?;
    let views = rules
        .into_iter()
        .map(|rule| {
            let blocked = rule.requires_admin && !is_admin;
            let blocked_reason = if blocked {
                Some("Requires administrator privileges".to_string())
            } else {
                None
            };
            RuleView {
                id: rule.id,
                title: rule.title,
                description: rule.description,
                category: rule.category,
                risk: rule.risk,
                default_checked: rule.default_checked,
                requires_admin: rule.requires_admin,
                rule_type: rule.rule_type,
                scope: rule.scope,
                path: rule.path,
                pattern: rule.pattern,
                size_threshold_mb: rule.size_threshold_mb,
                age_threshold_days: rule.age_threshold_days,
                action: rule.action,
                tool_cmd: rule.tool_cmd,
                enabled: rule.enabled,
                sort_order: rule.sort_order,
                notes: rule.notes,
                blocked,
                blocked_reason,
            }
        })
        .collect();
    Ok(views)
}
