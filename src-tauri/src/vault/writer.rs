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
    /// files whose newest save failed for good (reason): `flush` reports it
    failed: HashMap<PathBuf, String>,
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
        q.failed.remove(path); // a newer state is on its way
        q.pending.insert(path.to_path_buf(), Job { db: db.clone(), key: key.clone() });
        q.busy.insert(path.to_path_buf())
    });
    if start {
        let path = path.to_path_buf();
        std::thread::spawn(move || run(path));
    }
}

/// Clears `busy` however the thread ends (also on a panic), so `flush` never waits forever.
struct Done(PathBuf);
impl Drop for Done {
    fn drop(&mut self) {
        with(|q| q.busy.remove(&self.0));
        DONE.notify_all();
    }
}

/// Write one snapshot; a failure is retried a few times (file briefly locked by a sync client).
/// If it still fails, the snapshot goes to `<file>.unsaved.kdbx` so the change is not lost.
fn save_with_retry(path: &Path, job: &Job) -> R<()> {
    let mut last = String::new();
    for wait in [0u64, 300, 1500] {
        std::thread::sleep(std::time::Duration::from_millis(wait));
        let attempt = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| super::write_file(path, &job.db, job.key.clone())));
        match attempt {
            Ok(Ok(())) => return Ok(()),
            Ok(Err(e)) => last = e,
            Err(_) => last = "save:internal error".into(),
        }
        if last.starts_with("conflict:") {
            break; // retrying cannot fix a file we could not read
        }
    }
    let rescue = path.with_extension("unsaved.kdbx");
    let rescued = super::write_plain(&rescue, &job.db, job.key.clone()).is_ok();
    Err(if rescued { format!("{last} (copy: {})", rescue.display()) } else { last })
}

fn run(path: PathBuf) {
    let _done = Done(path.clone());
    // taking the next job and leaving are one step, so a job queued meanwhile is never stranded
    let next = |path: &PathBuf| {
        with(|q| {
            let job = q.pending.remove(path);
            if job.is_none() {
                q.busy.remove(path);
            }
            job
        })
    };
    while let Some(job) = next(&path) {
        let t = std::time::Instant::now();
        match save_with_retry(&path, &job) {
            Ok(()) => log::info!("saved in the background ({} ms)", t.elapsed().as_millis()),
            Err(e) => {
                log::error!("background save failed: {e}");
                // only while nothing newer is queued; the newer state decides then
                with(|q| {
                    if !q.pending.contains_key(&path) {
                        q.failed.insert(path.clone(), e.clone());
                    }
                });
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

/// Wait until this file is written. Err: the newest save failed (a copy may be next to the file).
pub fn flush(path: &Path) -> R<()> {
    let mut q = QUEUE.lock().unwrap_or_else(|e| e.into_inner());
    while q.as_ref().is_some_and(|q| q.busy.contains(path) || q.pending.contains_key(path)) {
        q = DONE.wait(q).unwrap_or_else(|e| e.into_inner());
    }
    match q.as_ref().and_then(|q| q.failed.get(path)) {
        Some(e) => Err(e.clone()),
        None => Ok(()),
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
    let _ = flush(path); // an older failed save is replaced by the write that follows
    with(|q| q.failed.remove(path));
    Ok(())
}
