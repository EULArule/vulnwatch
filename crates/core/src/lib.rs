//! vulnwatch core: everything except the UI shell.
//!
//! Hosts (the HTTP server, the Tauri/Android app) create one [`Core`] and talk to it through
//! [`Core::call`] (a JSON method/params API shared by every front end) and [`Core::poll`].

pub mod api;
pub mod catalog;
pub mod engine;
pub mod matcher;
pub mod model;
pub mod net;
pub mod notify;
pub mod settings;
pub mod sources;
pub mod store;

use std::{
    collections::BTreeMap,
    path::Path,
    sync::{Arc, Mutex, MutexGuard},
};

use anyhow::Result;

use net::Net;
use settings::Settings;
use store::Store;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub struct Core {
    store: Mutex<Store>,
    pub net: Net,
    poll_lock: Mutex<()>,
    /// Running inside the mobile app (changes a few defaults and what the UI offers).
    pub mobile: bool,
    kev: Mutex<Option<Arc<BTreeMap<String, String>>>>,
    /// Counts `assemble` calls (and keeps them one at a time); see there.
    assembled: Mutex<u64>,
    progress: Mutex<engine::Progress>,
}

impl Core {
    /// Open (creating if needed) the database in `data_dir`.
    pub fn open(data_dir: &Path, mobile: bool) -> Result<Self> {
        Ok(Self::with_store(Store::open(&data_dir.join("vulnwatch.db"))?, mobile))
    }

    pub fn with_store(store: Store, mobile: bool) -> Self {
        Self { store: Mutex::new(store), net: Net::new(), poll_lock: Mutex::new(()), mobile, kev: Mutex::new(None), assembled: Mutex::new(0), progress: Default::default() }
    }

    pub(crate) fn db(&self) -> MutexGuard<'_, Store> {
        self.store.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub fn settings(&self) -> Settings {
        let stored: Option<Settings> = self.db().get("settings").ok().flatten();
        stored.unwrap_or_else(|| Settings { interval_minutes: if self.mobile { 15 } else { 5 }, ..Default::default() })
    }

    /// Small host-owned values (e.g. the server's access token) kept alongside the data.
    pub fn kv_get(&self, key: &str) -> Option<String> {
        self.db().get(&format!("host:{key}")).ok().flatten()
    }

    pub fn kv_set(&self, key: &str, value: &str) -> Result<()> {
        self.db().set(&format!("host:{key}"), &value)
    }
}
