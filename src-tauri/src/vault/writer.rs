//! Saving in the background. Encrypting a KDBX file includes the key derivation (Argon2, a
//! quarter of a second and more), so a click that pins or moves an entry must not wait for it.
//! A change updates the vault in memory at once and queues a snapshot here; one thread per file
//! writes it. Changes that arrive while a save runs are folded into a single save of the newest
//! state. `flush` waits until a file is on disk: before locking, closing, quitting, updating and
//! before anything else writes or reloads that file.

use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
    sync::{Condvar, Mutex, OnceLock},
};

use keepass::{Database, DatabaseKey};
use tauri::Emitter;

use super::R;

struct Job {
    db: Database,
    key: DatabaseKey,
}

#[derive(Default)]
struct Queue {
    /// newest unsaved snapshot per file
    pending: HashMap<PathBuf, Job>,
    /// files a thread is writing right now
    busy: HashSet<PathBuf>,
}

static QUEUE: Mutex<Option<Queue>> = Mutex::new(None);
static DONE: Condvar = Condvar::new();
static APP: OnceLock<tauri::AppHandle> = OnceLock::new();

/// For reporting failed saves to the UI (`akp-save-failed`).
pub fn init(app: tauri::AppHandle) {
    let _ = APP.set(app);
}

fn with<T>(f: impl FnOnce(&mut Queue) -> T) -> T {
    let mut q = QUEUE.lock().unwrap_or_else(|e| e.into_inner());
    f(q.get_or_insert_with(Queue::default))
}

/// Queue a snapshot of the vault for writing; returns at once.
pub fn queue(path: &Path, db: &Database, key: &DatabaseKey) {
    let start = with(|q| {
        q.pending.insert(path.to_path_buf(), Job { db: db.clone(), key: key.clone() });
        q.busy.insert(path.to_path_buf())
    });
    if start {
        let path = path.to_path_buf();
        std::thread::spawn(move || run(path));
    }
}

fn run(path: PathBuf) {
    loop {
        let Some(job) = with(|q| q.pending.remove(&path)) else {
            with(|q| q.busy.remove(&path));
            DONE.notify_all();
            return;
        };
        let t = std::time::Instant::now();
        match super::write_file(&path, &job.db, job.key) {
            Ok(()) => log::info!("saved in the background ({} ms)", t.elapsed().as_millis()),
            Err(e) => {
                log::error!("background save failed: {e}");
                if let Some(app) = APP.get() {
                    let _ = app.emit("akp-save-failed", e);
                }
            }
        }
    }
}

/// true while a save of this file is queued or running
pub fn busy(path: &Path) -> bool {
    with(|q| q.busy.contains(path) || q.pending.contains_key(path))
}

/// Wait until this file is written.
pub fn flush(path: &Path) {
    let mut q = QUEUE.lock().unwrap_or_else(|e| e.into_inner());
    while q.as_ref().is_some_and(|q| q.busy.contains(path) || q.pending.contains_key(path)) {
        q = DONE.wait(q).unwrap_or_else(|e| e.into_inner());
    }
}

/// Wait until every queued save is written (quitting, installing an update).
pub fn flush_all() {
    let mut q = QUEUE.lock().unwrap_or_else(|e| e.into_inner());
    while q.as_ref().is_some_and(|q| !q.busy.is_empty() || !q.pending.is_empty()) {
        q = DONE.wait(q).unwrap_or_else(|e| e.into_inner());
    }
}

/// Synchronous writers (`write_db`) wait for a queued older state first, so it can't land
/// on top of theirs.
pub(super) fn before_sync_write(path: &Path) -> R<()> {
    flush(path);
    Ok(())
}
