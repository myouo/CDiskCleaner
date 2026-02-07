#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod db;
mod models;
mod rules;
mod scan;

use std::path::PathBuf;
use tauri::State;

struct AppState {
    db_path: PathBuf,
}

#[tauri::command]
fn list_rules_cmd(state: State<'_, AppState>) -> Result<Vec<models::Rule>, String> {
    let conn = db::open_db(&state.db_path).map_err(|e| e.to_string())?;
    rules::list_rules(&conn).map_err(|e| e.to_string())
}

fn main() {
    tauri::Builder::default()
        .setup(|app| {
            let data_dir = tauri::api::path::app_data_dir(&app.config())
                .ok_or_else(|| "Failed to resolve app data dir".to_string())?;
            let db_paths = db::init_db(&data_dir).map_err(|e| e.to_string())?;
            app.manage(AppState {
                db_path: db_paths.db_path,
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![list_rules_cmd])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
