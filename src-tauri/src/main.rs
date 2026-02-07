#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod db;
mod cleanup;
mod models;
mod privilege;
mod rules;
mod scan;
mod settings;

use std::path::PathBuf;
use tauri::{Emitter, Manager, State};

struct AppState {
    db_path: PathBuf,
}

#[tauri::command]
fn list_rules_cmd(state: State<'_, AppState>) -> Result<Vec<models::RuleView>, String> {
    let conn = db::open_db(&state.db_path).map_err(|e| e.to_string())?;
    let is_admin = privilege::is_admin();
    rules::list_rules_with_privilege(&conn, is_admin).map_err(|e| e.to_string())
}

#[tauri::command]
fn privilege_state_cmd() -> Result<bool, String> {
    Ok(privilege::is_admin())
}

#[tauri::command]
fn scan_rules_cmd(app: tauri::AppHandle, state: State<'_, AppState>) -> Result<Vec<models::RuleScan>, String> {
    let conn = db::open_db(&state.db_path).map_err(|e| e.to_string())?;
    let rules = rules::list_rules(&conn).map_err(|e| e.to_string())?;
    let is_admin = privilege::is_admin();
    scan::clear_cancel();
    let mut progress = |rule: &models::Rule| {
        let _ = app.emit(
            "scan:progress",
            serde_json::json!({
                "id": rule.id,
                "title": rule.title,
                "path": rule.path
            }),
        );
    };
    Ok(scan::scan_rules(&rules, &scan::ScanOptions { is_admin }, &mut progress))
}

#[tauri::command]
fn clean_rules_cmd(state: State<'_, AppState>, selected_ids: Vec<String>) -> Result<models::CleanupReport, String> {
    let conn = db::open_db(&state.db_path).map_err(|e| e.to_string())?;
    let rules = rules::list_rules(&conn).map_err(|e| e.to_string())?;
    let is_admin = privilege::is_admin();
    Ok(cleanup::cleanup_rules(
        &rules,
        &selected_ids,
        &cleanup::CleanupOptions { is_admin },
    ))
}

#[tauri::command]
fn get_setting_cmd(state: State<'_, AppState>, key: String) -> Result<Option<String>, String> {
    let conn = db::open_db(&state.db_path).map_err(|e| e.to_string())?;
    settings::get_setting(&conn, &key).map_err(|e| e.to_string())
}

#[tauri::command]
fn set_setting_cmd(state: State<'_, AppState>, key: String, value: String) -> Result<(), String> {
    let conn = db::open_db(&state.db_path).map_err(|e| e.to_string())?;
    settings::set_setting(&conn, &key, &value).map_err(|e| e.to_string())
}

#[tauri::command]
fn cancel_scan_cmd() -> Result<(), String> {
    scan::request_cancel();
    Ok(())
}

fn main() {
    tauri::Builder::default()
        .setup(|app| {
            let data_dir = app
                .path()
                .app_data_dir()
                .map_err(|e| e.to_string())?;
            let db_paths = db::init_db(&data_dir).map_err(|e| e.to_string())?;
            app.manage(AppState {
                db_path: db_paths.db_path,
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            list_rules_cmd,
            privilege_state_cmd,
            scan_rules_cmd,
            cancel_scan_cmd,
            clean_rules_cmd,
            get_setting_cmd,
            set_setting_cmd
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
