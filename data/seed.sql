BEGIN TRANSACTION;

INSERT OR REPLACE INTO meta (key, value) VALUES
  ('schema_version','1'),
  ('seed_version','1');

-- Low risk: temp and caches
INSERT OR REPLACE INTO rules (id, title, description, category, risk, default_checked, requires_admin, rule_type, scope, path, pattern, size_threshold_mb, age_threshold_days, action, tool_cmd, enabled, sort_order, notes) VALUES
  ('sys_temp','System temp files','Windows system temp directory','temp','low',1,1,'path','system','C:\\Windows\\Temp',NULL,NULL,NULL,'delete',NULL,1,10,NULL),
  ('user_temp','User temp files','Current user temp directory','temp','low',1,0,'path','user','%LOCALAPPDATA%\\Temp',NULL,NULL,NULL,'delete',NULL,1,20,NULL),
  ('thumb_cache','Thumbnail cache','Explorer thumbnail cache database','cache','low',1,0,'pattern','user','%LOCALAPPDATA%\\Microsoft\\Windows\\Explorer', 'thumbcache_*.db',NULL,NULL,'delete',NULL,1,30,NULL),
  ('icon_cache','Icon cache','Explorer icon cache database','cache','low',1,0,'pattern','user','%LOCALAPPDATA%\\Microsoft\\Windows\\Explorer','iconcache_*.db',NULL,NULL,'delete',NULL,1,40,NULL),
  ('font_cache','Font cache','Windows font cache files','cache','low',1,1,'path','system','%WINDIR%\\ServiceProfiles\\LocalService\\AppData\\Local\\FontCache',NULL,NULL,NULL,'delete',NULL,1,50,NULL),
  ('wer_logs','Windows Error Reporting','WER report files and logs','logs','low',1,1,'path','system','C:\\ProgramData\\Microsoft\\Windows\\WER',NULL,NULL,NULL,'delete',NULL,1,60,NULL),
  ('diag_etl','Diagnostic ETL logs','Windows diagnostic ETL logs','logs','low',1,1,'path','system','%PROGRAMDATA%\\Microsoft\\Diagnosis\\ETLLogs',NULL,NULL,7,'delete',NULL,1,70,NULL),
  ('windows_logs','Windows logs (old)','Old logs under Windows\\Logs','logs','low',1,1,'path','system','%WINDIR%\\Logs',NULL,NULL,14,'delete',NULL,1,80,'Delete only older files'),
  ('recent_file_cache','Recent file lists','Windows recent file cache','privacy','low',0,0,'path','user','%APPDATA%\\Microsoft\\Windows\\Recent',NULL,NULL,NULL,'delete',NULL,1,90,NULL),
  ('prefetch','Prefetch files','Prefetch cache for app launches','cache','low',0,1,'path','system','%WINDIR%\\Prefetch',NULL,NULL,30,'delete',NULL,1,100,'Keep recent files'),
  ('recycle_bin','Recycle Bin','Clear Recycle Bin contents','temp','low',0,0,'special','both',NULL,NULL,NULL,NULL,'tool_call','shell:recycle_bin_empty',1,110,NULL);

-- Browsers (low risk by default)
INSERT OR REPLACE INTO rules VALUES
  ('chrome_cache','Chrome cache','Google Chrome cache folders','browser','low',1,0,'path','user','%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Cache',NULL,NULL,NULL,'delete',NULL,1,120,NULL),
  ('chrome_code_cache','Chrome code cache','Chrome code cache folders','browser','low',1,0,'path','user','%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Code Cache',NULL,NULL,NULL,'delete',NULL,1,121,NULL),
  ('chrome_gpu_cache','Chrome GPU cache','Chrome GPU cache folders','browser','low',1,0,'path','user','%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\GPUCache',NULL,NULL,NULL,'delete',NULL,1,122,NULL),
  ('edge_cache','Edge cache','Microsoft Edge cache folders','browser','low',1,0,'path','user','%LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\Default\\Cache',NULL,NULL,NULL,'delete',NULL,1,130,NULL),
  ('edge_code_cache','Edge code cache','Edge code cache folders','browser','low',1,0,'path','user','%LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\Default\\Code Cache',NULL,NULL,NULL,'delete',NULL,1,131,NULL),
  ('edge_gpu_cache','Edge GPU cache','Edge GPU cache folders','browser','low',1,0,'path','user','%LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\Default\\GPUCache',NULL,NULL,NULL,'delete',NULL,1,132,NULL),
  ('brave_cache','Brave cache','Brave cache folders','browser','low',1,0,'path','user','%LOCALAPPDATA%\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Cache',NULL,NULL,NULL,'delete',NULL,1,140,NULL),
  ('firefox_cache','Firefox cache','Firefox cache2 folders','browser','low',1,0,'pattern','user','%APPDATA%\\Mozilla\\Firefox\\Profiles','*\\cache2',NULL,NULL,'delete',NULL,1,150,NULL);

-- Medium risk: system caches and update caches
INSERT OR REPLACE INTO rules VALUES
  ('win_update_cache','Windows Update cache','Downloaded update packages','update','medium',0,1,'path','system','C:\\Windows\\SoftwareDistribution\\Download',NULL,NULL,NULL,'delete',NULL,1,200,NULL),
  ('delivery_opt_cache','Delivery Optimization cache','Update delivery cache','update','medium',0,1,'path','system','%PROGRAMDATA%\\Microsoft\\Windows\\DeliveryOptimization\\Cache',NULL,NULL,NULL,'delete',NULL,1,210,NULL),
  ('windows_update_logs','Windows Update logs','Windows Update logs','logs','medium',0,1,'path','system','%WINDIR%\\Logs\\WindowsUpdate',NULL,NULL,14,'delete',NULL,1,220,NULL),
  ('wer_archive','WER archive','WER report archive','logs','medium',0,1,'path','system','%PROGRAMDATA%\\Microsoft\\Windows\\WER\\ReportArchive',NULL,NULL,NULL,'delete',NULL,1,230,NULL),
  ('crash_dumps','Crash dump files','System crash dump files','crash','medium',0,1,'pattern','system','C:\\Windows', 'MEMORY.DMP',NULL,NULL,'delete',NULL,1,240,NULL),
  ('minidumps','Minidump files','System minidump files','crash','medium',0,1,'path','system','C:\\Windows\\Minidump',NULL,NULL,NULL,'delete',NULL,1,241,NULL),
  ('driver_logs','Driver install logs','SetupAPI logs for driver installs','logs','medium',0,1,'pattern','system','C:\\Windows\\INF','setupapi*.log',NULL,30,'delete',NULL,1,250,NULL),
  ('user_cache','User cache folders','Windows user cache folders','cache','medium',0,0,'path','user','%LOCALAPPDATA%\\Microsoft\\Windows\\Caches',NULL,NULL,NULL,'delete',NULL,1,260,NULL),
  ('onedrive_cache','OneDrive cache','OneDrive logs and temp','apps','medium',0,0,'path','user','%LOCALAPPDATA%\\Microsoft\\OneDrive\\logs',NULL,NULL,NULL,'delete',NULL,1,270,NULL),
  ('onedrive_temp','OneDrive temp','OneDrive temp','apps','medium',0,0,'path','user','%LOCALAPPDATA%\\Microsoft\\OneDrive\\temp',NULL,NULL,NULL,'delete',NULL,1,271,NULL);

-- App caches (medium risk, default off)
INSERT OR REPLACE INTO rules VALUES
  ('teams_cache','Teams cache','Microsoft Teams cache','apps','medium',0,0,'path','user','%APPDATA%\\Microsoft\\Teams\\Cache',NULL,NULL,NULL,'delete',NULL,1,300,NULL),
  ('teams_gpu_cache','Teams GPU cache','Microsoft Teams GPU cache','apps','medium',0,0,'path','user','%APPDATA%\\Microsoft\\Teams\\GPUCache',NULL,NULL,NULL,'delete',NULL,1,301,NULL),
  ('office_cache','Office cache','Office file cache','apps','medium',0,0,'path','user','%LOCALAPPDATA%\\Microsoft\\Office\\16.0\\OfficeFileCache',NULL,NULL,NULL,'delete',NULL,1,310,NULL),
  ('wechat_cache','WeChat cache','WeChat cache files','apps','medium',0,0,'path','user','%APPDATA%\\Tencent\\WeChat\\XPlugin',NULL,NULL,NULL,'delete',NULL,1,320,NULL),
  ('qq_cache','QQ cache','QQ cache files','apps','medium',0,0,'path','user','%APPDATA%\\Tencent\\QQ\\Cache',NULL,NULL,NULL,'delete',NULL,1,321,NULL),
  ('discord_cache','Discord cache','Discord cache files','apps','medium',0,0,'path','user','%APPDATA%\\discord\\Cache',NULL,NULL,NULL,'delete',NULL,1,330,NULL),
  ('telegram_cache','Telegram cache','Telegram cache files','apps','medium',0,0,'path','user','%APPDATA%\\Telegram Desktop\\tdata',NULL,NULL,NULL,'delete',NULL,1,340,'Keep login data'),
  ('steam_cache','Steam download cache','Steam download cache','apps','medium',0,0,'path','user','%PROGRAMFILES(X86)%\\Steam\\steamapps\\downloading',NULL,NULL,NULL,'delete',NULL,1,350,NULL),
  ('epic_cache','Epic download cache','Epic Games download cache','apps','medium',0,0,'path','user','%PROGRAMDATA%\\Epic\\EpicGamesLauncher\\Data\\Manifests',NULL,NULL,NULL,'delete',NULL,1,360,NULL),
  ('battle_net_cache','Battle.net cache','Battle.net cache folders','apps','medium',0,0,'path','user','%PROGRAMDATA%\\Battle.net\\Agent',NULL,NULL,NULL,'delete',NULL,1,370,NULL),
  ('adobe_cache','Adobe cache','Adobe common cache','apps','medium',0,0,'path','user','%APPDATA%\\Adobe\\Common\\Media Cache Files',NULL,NULL,NULL,'delete',NULL,1,380,NULL),
  ('autodesk_cache','Autodesk cache','Autodesk cache folders','apps','medium',0,0,'path','user','%LOCALAPPDATA%\\Autodesk\\Web Services',NULL,NULL,NULL,'delete',NULL,1,390,NULL);

-- High risk: use tool calls or special warnings
INSERT OR REPLACE INTO rules VALUES
  ('winsxs_cleanup','WinSxS cleanup (不建议删除该内容，除非您已知删除该内容的风险)','Clean component store via DISM','system','high',0,1,'special','system',NULL,NULL,NULL,NULL,'tool_call','DISM /Online /Cleanup-Image /StartComponentCleanup',1,500,'Use DISM only'),
  ('restore_points','System Restore Points (不建议删除该内容，除非您已知删除该内容的风险)','Delete restore points','system','high',0,1,'special','system',NULL,NULL,NULL,NULL,'tool_call','vssadmin Delete Shadows /All /Quiet',1,510,'Requires admin'),
  ('registry_orphans','Registry orphans (不建议删除该内容，除非您已知删除该内容的风险)','Detect orphan uninstall entries and invalid paths','registry','high',0,1,'registry','system',NULL,NULL,NULL,NULL,'delete',NULL,1,520,'Backup required'),
  ('app_residue','Uninstalled app residue (不建议删除该内容，除非您已知删除该内容的风险)','Detect leftover files from uninstalled apps','apps','high',0,0,'app_residue','both',NULL,NULL,NULL,NULL,'delete',NULL,1,530,'Match by uninstall records');

COMMIT;
