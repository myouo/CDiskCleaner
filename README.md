# CDiskCleaner

Rust + Tauri based Windows C drive cleanup tool.

## Structure
- `src-tauri/` Rust backend (Tauri)
- `ui/` Static frontend
- `data/` SQLite schema + seed rules
- `logs/` Conversation logs

## Next steps
- Wire scan engine to rules
- Implement deletion actions and preview
- Add permission escalation flow
