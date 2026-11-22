//! Userscript manager for handling multiple scripts

use crate::{script::Userscript, storage::UserscriptStorage, Error, Result};
use common::db::redb::{Durability, ReadableTable};
use common::db::{tables, Db, DbError};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{debug, info, warn};

/// Manages a collection of userscripts
pub struct UserscriptManager {
    /// All installed userscripts indexed by ID
    scripts: Arc<RwLock<HashMap<String, Userscript>>>,
    /// Storage for script data
    storage: Arc<UserscriptStorage>,
    /// Shared database (userscripts and GM values)
    db: Arc<Db>,
}

impl UserscriptManager {
    /// Create a new userscript manager
    pub fn new(data_dir: PathBuf) -> Result<Self> {
        info!(
            "Initializing userscript manager with data dir: {:?}",
            data_dir
        );

        // Create data directory if it doesn't exist
        std::fs::create_dir_all(&data_dir)?;

        let db = Db::open(&data_dir)?;
        let storage = Arc::new(UserscriptStorage::with_db(db.clone()));

        Ok(Self {
            scripts: Arc::new(RwLock::new(HashMap::new())),
            storage,
            db,
        })
    }

    /// Install a new userscript from source code
    pub fn install(&self, source: String) -> Result<String> {
        let script = Userscript::new(source)?;
        let script_id = script.id.clone();

        info!("Installing userscript: {} ({})", script.name(), script_id);

        // Check if already installed
        {
            let scripts = self.scripts.read();
            if scripts.contains_key(&script_id) {
                return Err(Error::InvalidScript(format!(
                    "Script {} is already installed",
                    script_id
                )));
            }
        }

        // Persist
        self.save_script(&script, Durability::Immediate)?;

        // Add to in-memory collection
        self.scripts.write().insert(script_id.clone(), script);

        Ok(script_id)
    }

    /// Update an existing userscript
    pub fn update(&self, script_id: &str, new_source: String) -> Result<()> {
        let mut scripts = self.scripts.write();

        let script = scripts
            .get_mut(script_id)
            .ok_or_else(|| Error::ScriptNotFound(script_id.to_string()))?;

        info!("Updating userscript: {} ({})", script.name(), script_id);

        script.update(new_source)?;

        self.save_script(script, Durability::Immediate)?;

        Ok(())
    }

    /// Uninstall a userscript
    pub fn uninstall(&self, script_id: &str) -> Result<()> {
        info!("Uninstalling userscript: {}", script_id);

        // Remove from in-memory collection
        let script = self
            .scripts
            .write()
            .remove(script_id)
            .ok_or_else(|| Error::ScriptNotFound(script_id.to_string()))?;

        // Remove the script and its stored values in one transaction.
        self.storage.flush()?;
        self.db.write::<_, Error>(Durability::Immediate, |t| {
            t.open_table(tables::USERSCRIPTS)
                .map_err(DbError::from)?
                .remove(script_id)
                .map_err(DbError::from)?;
            UserscriptStorage::clear_in_txn(t, script_id)
        })?;
        self.storage.drop_cache(script_id);

        info!("Uninstalled userscript: {}", script.name());

        Ok(())
    }

    /// Get a userscript by ID
    pub fn get(&self, script_id: &str) -> Option<Userscript> {
        self.scripts.read().get(script_id).cloned()
    }

    /// Get all userscripts
    pub fn get_all(&self) -> Vec<Userscript> {
        self.scripts.read().values().cloned().collect()
    }

    /// Get userscripts that should run on a given URL
    pub fn get_scripts_for_url(&self, url: &str) -> Vec<Userscript> {
        let scripts = self.scripts.read();
        scripts
            .values()
            .filter(|script| script.should_run_on(url))
            .cloned()
            .collect()
    }

    /// Enable or disable a userscript
    pub fn set_enabled(&self, script_id: &str, enabled: bool) -> Result<()> {
        let mut scripts = self.scripts.write();

        let script = scripts
            .get_mut(script_id)
            .ok_or_else(|| Error::ScriptNotFound(script_id.to_string()))?;

        info!(
            "{} userscript: {}",
            if enabled { "Enabling" } else { "Disabling" },
            script.name()
        );

        script.enabled = enabled;

        self.save_script(script, Durability::Immediate)?;

        Ok(())
    }

    /// Record script execution
    pub fn record_execution(&self, script_id: &str) -> Result<()> {
        let mut scripts = self.scripts.write();

        let script = scripts
            .get_mut(script_id)
            .ok_or_else(|| Error::ScriptNotFound(script_id.to_string()))?;

        script.record_execution();

        // Periodically persist (every 10 executions; no fsync, counters are best-effort)
        if script.execution_count % 10 == 0 {
            self.save_script(script, Durability::Eventual)?;
        }

        Ok(())
    }

    /// Load all userscripts from the database
    pub fn load_all(&self) -> Result<usize> {
        info!("Loading userscripts");

        let loaded: Vec<Userscript> = self.db.read(|r| {
            let t = r.open_table(tables::USERSCRIPTS).map_err(DbError::from)?;
            let mut out = Vec::new();
            for item in t.iter().map_err(DbError::from)? {
                let (k, v) = item.map_err(DbError::from)?;
                match serde_json::from_slice::<Userscript>(v.value()) {
                    Ok(s) => out.push(s),
                    Err(e) => warn!("Failed to load script {}: {}", k.value(), e),
                }
            }
            Ok::<_, Error>(out)
        })?;

        let count = loaded.len();
        let mut scripts = self.scripts.write();
        for script in loaded {
            debug!("Loaded userscript: {}", script.name());
            scripts.insert(script.id.clone(), script);
        }

        info!("Loaded {} userscripts", count);
        Ok(count)
    }

    /// Get storage instance reference
    pub fn storage(&self) -> &UserscriptStorage {
        &self.storage
    }

    /// Get storage instance as Arc (for sharing with runtime)
    pub fn storage_arc(&self) -> Arc<UserscriptStorage> {
        Arc::clone(&self.storage)
    }

    /// Persist a script
    fn save_script(&self, script: &Userscript, durability: Durability) -> Result<()> {
        let json = serde_json::to_vec(script)?;
        self.db.write::<_, Error>(durability, |t| {
            t.open_table(tables::USERSCRIPTS)
                .map_err(DbError::from)?
                .insert(script.id.as_str(), json.as_slice())
                .map_err(DbError::from)?;
            Ok(())
        })
    }

    /// Get statistics
    pub fn stats(&self) -> UserscriptStats {
        let scripts = self.scripts.read();
        let total = scripts.len();
        let enabled = scripts.values().filter(|s| s.enabled).count();
        let disabled = total - enabled;
        let total_executions: u64 = scripts.values().map(|s| s.execution_count).sum();

        UserscriptStats {
            total_scripts: total,
            enabled_scripts: enabled,
            disabled_scripts: disabled,
            total_executions,
        }
    }
}

/// Statistics about userscripts
#[derive(Debug, Clone)]
pub struct UserscriptStats {
    pub total_scripts: usize,
    pub enabled_scripts: usize,
    pub disabled_scripts: usize,
    pub total_executions: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    const TEST_SCRIPT: &str = r#"
// ==UserScript==
// @name         Test Script
// @namespace    http://example.com
// @version      1.0.0
// @match        *://example.com/*
// ==/UserScript==

console.log('test');
"#;

    #[test]
    fn test_install_uninstall() {
        let temp_dir = tempdir().unwrap();
        let manager = UserscriptManager::new(temp_dir.path().to_path_buf()).unwrap();

        let script_id = manager.install(TEST_SCRIPT.to_string()).unwrap();
        assert!(manager.get(&script_id).is_some());

        manager.uninstall(&script_id).unwrap();
        assert!(manager.get(&script_id).is_none());
    }

    #[test]
    fn test_get_scripts_for_url() {
        let temp_dir = tempdir().unwrap();
        let manager = UserscriptManager::new(temp_dir.path().to_path_buf()).unwrap();

        manager.install(TEST_SCRIPT.to_string()).unwrap();

        let scripts = manager.get_scripts_for_url("https://example.com/page");
        assert_eq!(scripts.len(), 1);

        let scripts = manager.get_scripts_for_url("https://other.com/page");
        assert_eq!(scripts.len(), 0);
    }

    #[test]
    fn test_enable_disable() {
        let temp_dir = tempdir().unwrap();
        let manager = UserscriptManager::new(temp_dir.path().to_path_buf()).unwrap();

        let script_id = manager.install(TEST_SCRIPT.to_string()).unwrap();

        manager.set_enabled(&script_id, false).unwrap();
        let script = manager.get(&script_id).unwrap();
        assert!(!script.enabled);

        // Disabled script should not run
        let scripts = manager.get_scripts_for_url("https://example.com/page");
        assert_eq!(scripts.len(), 0);
    }

    #[test]
    fn test_load_save() {
        let temp_dir = tempdir().unwrap();
        let script_id;

        {
            // Create first manager and install script
            let manager = UserscriptManager::new(temp_dir.path().to_path_buf()).unwrap();
            script_id = manager.install(TEST_SCRIPT.to_string()).unwrap();
            // manager is dropped here, closing the database
        }

        // Create new manager instance - now the lock is released
        let manager2 = UserscriptManager::new(temp_dir.path().to_path_buf()).unwrap();
        manager2.load_all().unwrap();

        assert!(manager2.get(&script_id).is_some());
    }

    #[test]
    fn test_stats() {
        let temp_dir = tempdir().unwrap();
        let manager = UserscriptManager::new(temp_dir.path().to_path_buf()).unwrap();

        let script_id = manager.install(TEST_SCRIPT.to_string()).unwrap();

        let stats = manager.stats();
        assert_eq!(stats.total_scripts, 1);
        assert_eq!(stats.enabled_scripts, 1);
        assert_eq!(stats.disabled_scripts, 0);

        manager.set_enabled(&script_id, false).unwrap();

        let stats = manager.stats();
        assert_eq!(stats.enabled_scripts, 0);
        assert_eq!(stats.disabled_scripts, 1);
    }
}
