-- Core tables for rule-driven cleanup
CREATE TABLE IF NOT EXISTS rules (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  category TEXT NOT NULL,
  risk TEXT NOT NULL CHECK (risk IN ('low','medium','high')),
  default_checked INTEGER NOT NULL DEFAULT 0,
  requires_admin INTEGER NOT NULL DEFAULT 0,
  rule_type TEXT NOT NULL CHECK (rule_type IN ('path','pattern','special','registry','app_residue')),
  scope TEXT NOT NULL CHECK (scope IN ('system','user','both')),
  path TEXT,
  pattern TEXT,
  size_threshold_mb INTEGER,
  age_threshold_days INTEGER,
  action TEXT NOT NULL CHECK (action IN ('delete','recycle','tool_call')),
  tool_cmd TEXT,
  enabled INTEGER NOT NULL DEFAULT 1,
  sort_order INTEGER NOT NULL DEFAULT 0,
  notes TEXT
);

CREATE TABLE IF NOT EXISTS rule_tags (
  rule_id TEXT NOT NULL,
  tag TEXT NOT NULL,
  PRIMARY KEY (rule_id, tag),
  FOREIGN KEY (rule_id) REFERENCES rules(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
