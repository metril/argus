//! Userscript manager for handling multiple scripts

use crate::{
    backend::{GmBackend, Quotas},
    index::{BuildReport, ScriptIndex},
    matcher::Options,
    script::{Userscript, DEFAULT_PROFILE},
    storage::{ns, UserscriptStorage},
    token::TokenKey,
    Error, Result,
};
use arc_swap::ArcSwap;
use common::db::redb::{Durability, ReadableTable};
use common::db::{tables, Db, DbError};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{debug, info, warn};

/// Manages a collection of userscripts. Every operation exists in a profile-aware `*_in` form;
/// the plain methods address [`DEFAULT_PROFILE`].
pub struct UserscriptManager {
    /// All installed userscripts indexed by (profile, id)
    scripts: Arc<RwLock<HashMap<(String, String), Userscript>>>,
    /// Storage for script data
    storage: Arc<UserscriptStorage>,
    /// Shared database (userscripts and GM values)
    db: Arc<Db>,
    /// Live per-document index of the default profile, rebuilt (and swapped atomically) after
    /// every change; the proxy reads it lock-free.
    live_index: ArcSwap<ScriptIndex>,
    /// The GM value/xhr/resource logic shared by the proxy endpoints and the management API.
    gm: GmBackend,
    /// Capability-token key: random per process (pages refresh tokens after a restart).
    token_key: TokenKey,
}

fn key(profile: &str, id: &str) -> (String, String) {
    (profile.to_string(), id.to_string())
}

fn check_ids(profile: &str, id: &str) -> Result<()> {
    let bad = |s: &str| s.is_empty() || s.chars().any(|c| c.is_control());
    if bad(profile) || bad(id) {
        return Err(Error::InvalidScript(
            "profile/script id must be non-empty without control characters".into(),
        ));
    }
    Ok(())
}

impl UserscriptManager {
    /// Create a new userscript manager
    pub fn new(data_dir: PathBuf) -> Result<Self> {
        info!(
            "Initializing userscript manager with data dir: {:?}",
            data_dir
        );
        std::fs::create_dir_all(&data_dir)?;
        let db = Db::open(&data_dir)?;
        let storage = Arc::new(UserscriptStorage::with_db(db.clone()));
        Ok(Self {
            scripts: Arc::new(RwLock::new(HashMap::new())),
            db,
            live_index: ArcSwap::from_pointee(ScriptIndex::default()),
            gm: GmBackend::new(storage.clone(), Quotas::default()),
            token_key: {
                use rand::RngCore;
                let mut k = [0u8; 32];
                rand::rngs::OsRng.fill_bytes(&mut k);
                TokenKey::new(k.to_vec())
            },
            storage,
        })
    }

    pub fn gm(&self) -> &GmBackend {
        &self.gm
    }

    pub fn token_key(&self) -> &TokenKey {
        &self.token_key
    }

    /// Delete every stored value of a script (and its in-memory accounting and change log).
    pub fn clear_values(&self, profile: &str, script_id: &str) -> Result<()> {
        self.storage.clear_script_storage(&ns(profile, script_id))?;
        self.gm.forget_script(profile, script_id);
        Ok(())
    }

    /// The current index of the default profile (one atomic load).
    pub fn live_index(&self) -> arc_swap::Guard<Arc<ScriptIndex>> {
        self.live_index.load()
    }

    /// Rebuild the default profile's live index from its scripts and swap it in. Called after
    /// every mutation (never on the proxy request path).
    pub fn refresh_index(&self) {
        let report = self.build_index(DEFAULT_PROFILE, Options::default());
        for (id, msg) in &report.problems {
            warn!("userscript {id}: {msg}");
        }
        self.live_index.store(Arc::new(report.index));
    }

    /// Install a new userscript from source code (default profile; no dependencies fetched).
    pub fn install(&self, source: String) -> Result<String> {
        self.install_in(DEFAULT_PROFILE, source)
    }

    pub fn install_in(&self, profile: &str, source: String) -> Result<String> {
        self.install_script(profile, Userscript::new(source)?)
    }

    /// Install a prepared script (e.g. from `install::finish_install`) into `profile`.
    pub fn install_script(&self, profile: &str, script: Userscript) -> Result<String> {
        let r = self.install_script_raw(profile, script);
        if r.is_ok() {
            self.refresh_index();
        }
        r
    }

    fn install_script_raw(&self, profile: &str, mut script: Userscript) -> Result<String> {
        check_ids(profile, &script.id)?;
        script.profile = profile.to_string();
        let script_id = script.id.clone();
        info!("Installing userscript: {} ({})", script.name(), script_id);
        if self.scripts.read().contains_key(&key(profile, &script_id)) {
            return Err(Error::InvalidScript(format!(
                "Script {} is already installed",
                script_id
            )));
        }
        self.save_script(&script, Durability::Immediate)?;
        self.scripts
            .write()
            .insert(key(profile, &script_id), script);
        Ok(script_id)
    }

    /// Update an existing userscript (default profile)
    pub fn update(&self, script_id: &str, new_source: String) -> Result<()> {
        self.update_in(DEFAULT_PROFILE, script_id, new_source)
    }

    pub fn update_in(&self, profile: &str, script_id: &str, new_source: String) -> Result<()> {
        let r = self.update_in_raw(profile, script_id, new_source);
        if r.is_ok() {
            self.refresh_index();
        }
        r
    }

    fn update_in_raw(&self, profile: &str, script_id: &str, new_source: String) -> Result<()> {
        let mut scripts = self.scripts.write();
        let script = scripts
            .get_mut(&key(profile, script_id))
            .ok_or_else(|| Error::ScriptNotFound(script_id.to_string()))?;
        info!("Updating userscript: {} ({})", script.name(), script_id);
        script.update(new_source)?;
        self.save_script(script, Durability::Immediate)?;
        Ok(())
    }

    /// Replace an installed script with an already verified update (see
    /// `install::finish_update`, which enforces re-approval for widening updates).
    pub fn replace_script(&self, profile: &str, script: Userscript) -> Result<()> {
        let r = self.replace_script_raw(profile, script);
        if r.is_ok() {
            self.refresh_index();
        }
        r
    }

    fn replace_script_raw(&self, profile: &str, mut script: Userscript) -> Result<()> {
        let mut scripts = self.scripts.write();
        if !scripts.contains_key(&key(profile, &script.id)) {
            return Err(Error::ScriptNotFound(script.id));
        }
        script.profile = profile.to_string();
        self.save_script(&script, Durability::Immediate)?;
        scripts.insert(key(profile, &script.id), script);
        Ok(())
    }

    /// Mutate an installed script in place and persist it (no index refresh: only for fields
    /// the index does not read, e.g. update-check state).
    pub fn modify_script<R>(
        &self,
        profile: &str,
        script_id: &str,
        f: impl FnOnce(&mut Userscript) -> R,
    ) -> Result<R> {
        let mut scripts = self.scripts.write();
        let script = scripts
            .get_mut(&key(profile, script_id))
            .ok_or_else(|| Error::ScriptNotFound(script_id.to_string()))?;
        let r = f(script);
        self.save_script(script, Durability::Immediate)?;
        Ok(r)
    }

    /// Uninstall a userscript (default profile)
    pub fn uninstall(&self, script_id: &str) -> Result<()> {
        self.uninstall_in(DEFAULT_PROFILE, script_id)
    }

    pub fn uninstall_in(&self, profile: &str, script_id: &str) -> Result<()> {
        let r = self.uninstall_in_raw(profile, script_id);
        if r.is_ok() {
            self.refresh_index();
        }
        r
    }

    fn uninstall_in_raw(&self, profile: &str, script_id: &str) -> Result<()> {
        info!("Uninstalling userscript: {}", script_id);
        let script = self
            .scripts
            .write()
            .remove(&key(profile, script_id))
            .ok_or_else(|| Error::ScriptNotFound(script_id.to_string()))?;

        // Remove the script and its stored values in one transaction.
        let namespace = ns(profile, script_id);
        self.storage.flush()?;
        self.db.write::<_, Error>(Durability::Immediate, |t| {
            t.open_table(tables::USERSCRIPTS)
                .map_err(DbError::from)?
                .remove(namespace.as_str())
                .map_err(DbError::from)?;
            UserscriptStorage::clear_in_txn(t, &namespace)
        })?;
        self.storage.drop_cache(&namespace);
        self.gm.forget_script(profile, script_id);
        info!("Uninstalled userscript: {}", script.name());
        Ok(())
    }

    /// Get a userscript by ID (default profile)
    pub fn get(&self, script_id: &str) -> Option<Userscript> {
        self.get_in(DEFAULT_PROFILE, script_id)
    }

    pub fn get_in(&self, profile: &str, script_id: &str) -> Option<Userscript> {
        self.scripts.read().get(&key(profile, script_id)).cloned()
    }

    /// Get all userscripts (all profiles)
    pub fn get_all(&self) -> Vec<Userscript> {
        self.scripts.read().values().cloned().collect()
    }

    /// Scripts of one profile, in install order.
    pub fn get_all_in(&self, profile: &str) -> Vec<Userscript> {
        let mut v: Vec<Userscript> = self
            .scripts
            .read()
            .values()
            .filter(|s| s.profile == profile)
            .cloned()
            .collect();
        v.sort_by(|a, b| {
            a.installed_at
                .cmp(&b.installed_at)
                .then_with(|| a.id.cmp(&b.id))
        });
        v
    }

    /// Build the immutable per-document index of a profile's enabled scripts. Rebuild and swap
    /// it (e.g. into an `ArcSwap`) after any change.
    pub fn build_index(&self, profile: &str, opts: Options) -> BuildReport {
        ScriptIndex::build(profile, &self.get_all_in(profile), opts)
    }

    /// Userscripts of the default profile that should run on a given URL
    pub fn get_scripts_for_url(&self, url: &str) -> Vec<Userscript> {
        self.get_all_in(DEFAULT_PROFILE)
            .into_iter()
            .filter(|script| script.should_run_on(url))
            .collect()
    }

    /// Enable or disable a userscript (default profile)
    pub fn set_enabled(&self, script_id: &str, enabled: bool) -> Result<()> {
        self.set_enabled_in(DEFAULT_PROFILE, script_id, enabled)
    }

    pub fn set_enabled_in(&self, profile: &str, script_id: &str, enabled: bool) -> Result<()> {
        let r = self.set_enabled_in_raw(profile, script_id, enabled);
        if r.is_ok() {
            self.refresh_index();
        }
        r
    }

    fn set_enabled_in_raw(&self, profile: &str, script_id: &str, enabled: bool) -> Result<()> {
        let mut scripts = self.scripts.write();
        let script = scripts
            .get_mut(&key(profile, script_id))
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

    /// Record script execution (default profile)
    pub fn record_execution(&self, script_id: &str) -> Result<()> {
        self.record_execution_in(DEFAULT_PROFILE, script_id)
    }

    pub fn record_execution_in(&self, profile: &str, script_id: &str) -> Result<()> {
        let mut scripts = self.scripts.write();
        let script = scripts
            .get_mut(&key(profile, script_id))
            .ok_or_else(|| Error::ScriptNotFound(script_id.to_string()))?;
        script.record_execution();
        // Periodically persist (every 10 executions; no fsync, counters are best-effort)
        if script.execution_count % 10 == 0 {
            self.save_script(script, Durability::Eventual)?;
        }
        Ok(())
    }

    /// Load all userscripts from the database. Rows that no longer parse (the pre-rewrite
    /// format kept `@resource`s in a `resources` map) are dropped with a log line: there is
    /// nothing to migrate them to, and a row that never loads would be re-reported forever.
    pub fn load_all(&self) -> Result<usize> {
        info!("Loading userscripts");
        let (loaded, stale): (Vec<Userscript>, Vec<String>) = self.db.read(|r| {
            let t = r.open_table(tables::USERSCRIPTS).map_err(DbError::from)?;
            let (mut out, mut stale) = (Vec::new(), Vec::new());
            for item in t.iter().map_err(DbError::from)? {
                let (k, v) = item.map_err(DbError::from)?;
                match serde_json::from_slice::<Userscript>(v.value()) {
                    Ok(s) => out.push(s),
                    Err(e) => {
                        warn!(
                            "Dropping stored userscript {} (old or unreadable format: {e})",
                            k.value()
                        );
                        stale.push(k.value().to_string());
                    }
                }
            }
            Ok::<_, Error>((out, stale))
        })?;
        if !stale.is_empty() {
            self.db.write::<_, Error>(Durability::Immediate, |t| {
                let mut tbl = t.open_table(tables::USERSCRIPTS).map_err(DbError::from)?;
                for k in &stale {
                    tbl.remove(k.as_str()).map_err(DbError::from)?;
                }
                Ok(())
            })?;
        }
        let count = loaded.len();
        {
            let mut scripts = self.scripts.write();
            for script in loaded {
                debug!("Loaded userscript: {}", script.name());
                scripts.insert(key(&script.profile, &script.id), script);
            }
        }
        self.refresh_index();
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
        let k = ns(&script.profile, &script.id);
        self.db.write::<_, Error>(durability, |t| {
            t.open_table(tables::USERSCRIPTS)
                .map_err(DbError::from)?
                .insert(k.as_str(), json.as_slice())
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
    fn profiles_are_isolated() {
        let temp_dir = tempdir().unwrap();
        let m = UserscriptManager::new(temp_dir.path().to_path_buf()).unwrap();
        let id = m.install_in("a", TEST_SCRIPT.to_string()).unwrap();
        m.install_in("b", TEST_SCRIPT.to_string()).unwrap();
        assert!(m.get(&id).is_none());
        m.storage()
            .set_raw(&ns("a", &id), "k", serde_json::json!(1))
            .unwrap();
        assert!(m.storage().get_raw(&ns("b", &id), "k").unwrap().is_none());
        m.set_enabled_in("a", &id, false).unwrap();
        assert!(m.build_index("a", Options::default()).index.is_empty());
        assert_eq!(m.build_index("b", Options::default()).index.len(), 1);
        m.uninstall_in("a", &id).unwrap();
        assert!(m.storage().get_raw(&ns("a", &id), "k").unwrap().is_none());
        assert_eq!(m.get_all_in("b").len(), 1);
        drop(m);
        let m = UserscriptManager::new(temp_dir.path().to_path_buf()).unwrap();
        m.load_all().unwrap();
        assert!(m.get_all_in("a").is_empty());
        assert_eq!(m.get_all_in("b").len(), 1);
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
