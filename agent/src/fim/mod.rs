use notify::event::EventKind;
use notify::{Config, Event, RecommendedWatcher, RecursiveMode, Watcher};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum FimEventType {
    Added,
    Modified,
    Deleted,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FimEvent {
    pub event_type: FimEventType,
    pub file_path: String,
    pub sha256_hash: Option<String>,
    pub timestamp: String,
}

pub type FimSink = Arc<Mutex<Vec<FimEvent>>>;

pub struct FileIntegrityMonitor {
    watched_directories: Vec<PathBuf>,
    state: HashMap<PathBuf, String>,
    sink: FimSink,
    _watcher: Option<RecommendedWatcher>,
    _watcher_thread: Option<thread::JoinHandle<()>>,
}

impl FileIntegrityMonitor {
    pub fn new(directories: Vec<PathBuf>) -> Self {
        let sink: FimSink = Arc::new(Mutex::new(Vec::new()));
        let (_watcher, _watcher_thread) = Self::start_watcher(directories.clone(), sink.clone());
        Self {
            watched_directories: directories,
            state: HashMap::new(),
            sink,
            _watcher,
            _watcher_thread,
        }
    }

    fn start_watcher(
        dirs: Vec<PathBuf>,
        sink: FimSink,
    ) -> (Option<RecommendedWatcher>, Option<thread::JoinHandle<()>>) {
        let (tx, rx) = mpsc::channel::<Result<Event, notify::Error>>();

        let mut watcher = match RecommendedWatcher::new(tx, Config::default()) {
            Ok(w) => w,
            Err(e) => {
                eprintln!("aetherix-fim: failed to create watcher: {e}");
                return (None, None);
            }
        };

        for dir in &dirs {
            if dir.exists() && dir.is_dir() {
                if let Err(e) = watcher.watch(dir, RecursiveMode::Recursive) {
                    eprintln!("aetherix-fim: failed to watch {}: {e}", dir.display());
                }
            }
        }

        let handle = thread::Builder::new()
            .name("aetherix-fim-watcher".to_string())
            .spawn(move || {
                // Simple debounce: collect events over a short window
                loop {
                    let batch = Self::collect_batch(&rx, Duration::from_millis(500));
                    if batch.is_empty() {
                        continue;
                    }
                    let mut collected = sink.lock().expect("fim sink poisoned");
                    for event in batch {
                        let event_type = classify_event(&event.kind);
                        if event_type.is_none() {
                            continue;
                        }
                        for path in &event.paths {
                            let hash = if path.is_file() {
                                hash_file(path).ok()
                            } else {
                                None
                            };
                            collected.push(FimEvent {
                                event_type: event_type.clone().unwrap(),
                                file_path: path.to_string_lossy().into_owned(),
                                sha256_hash: hash,
                                timestamp: chrono::Utc::now().to_rfc3339(),
                            });
                        }
                    }
                }
            })
            .ok();

        (Some(watcher), handle)
    }

    fn collect_batch(rx: &Receiver<Result<Event, notify::Error>>, window: Duration) -> Vec<Event> {
        let mut events = Vec::new();
        let deadline = std::time::Instant::now() + window;

        // Block for first event
        match rx.recv() {
            Ok(Ok(event)) => events.push(event),
            Ok(Err(e)) => {
                eprintln!("aetherix-fim: watcher error: {e}");
            }
            Err(_) => return events,
        }

        // Collect more events within the time window
        while std::time::Instant::now() < deadline {
            match rx.recv_timeout(Duration::from_millis(50)) {
                Ok(Ok(event)) => events.push(event),
                Ok(Err(e)) => eprintln!("aetherix-fim: watcher error: {e}"),
                Err(mpsc::RecvTimeoutError::Timeout) => break,
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }

        events
    }

    /// Perform a one-time baseline scan of all watched directories.
    pub fn baseline_scan(&mut self) -> Vec<FimEvent> {
        let mut events = Vec::new();
        let mut current_state = HashMap::new();

        for dir in &self.watched_directories {
            if dir.exists() && dir.is_dir() {
                Self::walk_and_hash(dir, &mut current_state);
            }
        }

        for (path, hash) in &current_state {
            events.push(FimEvent {
                event_type: FimEventType::Added,
                file_path: path.to_string_lossy().into_owned(),
                sha256_hash: Some(hash.clone()),
                timestamp: chrono::Utc::now().to_rfc3339(),
            });
        }

        self.state = current_state;
        events
    }

    /// Drain buffered real-time events from the watcher thread.
    pub fn drain_events(&mut self) -> Vec<FimEvent> {
        let mut sink = self.sink.lock().expect("fim sink poisoned");
        let events: Vec<FimEvent> = sink.drain(..).collect();

        for event in &events {
            let path = PathBuf::from(&event.file_path);
            match event.event_type {
                FimEventType::Added | FimEventType::Modified => {
                    if let Some(ref hash) = event.sha256_hash {
                        self.state.insert(path, hash.clone());
                    }
                }
                FimEventType::Deleted => {
                    self.state.remove(&path);
                }
            }
        }

        events
    }

    /// Verify current file hashes against stored baseline.
    pub fn verify_integrity(&mut self) -> Vec<FimEvent> {
        let mut events = Vec::new();
        let mut current_state = HashMap::new();

        for dir in &self.watched_directories {
            if dir.exists() && dir.is_dir() {
                Self::walk_and_hash(dir, &mut current_state);
            }
        }

        for (path, current_hash) in &current_state {
            match self.state.get(path) {
                Some(old_hash) if old_hash != current_hash => {
                    events.push(FimEvent {
                        event_type: FimEventType::Modified,
                        file_path: path.to_string_lossy().into_owned(),
                        sha256_hash: Some(current_hash.clone()),
                        timestamp: chrono::Utc::now().to_rfc3339(),
                    });
                }
                _ => {}
            }
        }

        for path in self.state.keys() {
            if !current_state.contains_key(path) {
                events.push(FimEvent {
                    event_type: FimEventType::Deleted,
                    file_path: path.to_string_lossy().into_owned(),
                    sha256_hash: None,
                    timestamp: chrono::Utc::now().to_rfc3339(),
                });
            }
        }

        self.state = current_state;
        events
    }

    fn walk_and_hash(dir: &Path, state: &mut HashMap<PathBuf, String>) {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    if let Ok(metadata) = std::fs::symlink_metadata(&path) {
                        if metadata.is_dir() {
                            Self::walk_and_hash(&path, state);
                        }
                    }
                } else if path.is_file() {
                    if let Ok(hash) = hash_file(&path) {
                        state.insert(path, hash);
                    }
                }
            }
        }
    }
}

fn classify_event(kind: &EventKind) -> Option<FimEventType> {
    match kind {
        EventKind::Create(_) => Some(FimEventType::Added),
        EventKind::Modify(_) => Some(FimEventType::Modified),
        EventKind::Remove(_) => Some(FimEventType::Deleted),
        _ => None,
    }
}

static RECENT_HASHES: std::sync::OnceLock<Mutex<HashMap<PathBuf, String>>> = std::sync::OnceLock::new();

pub fn get_recent_hashes() -> &'static Mutex<HashMap<PathBuf, String>> {
    RECENT_HASHES.get_or_init(|| Mutex::new(HashMap::new()))
}

fn hash_file(path: &Path) -> std::io::Result<String> {
    let file = std::fs::File::open(path);
    if let Err(ref err) = file {
        if err.kind() == std::io::ErrorKind::NotFound {
            if let Ok(cache) = get_recent_hashes().lock() {
                if let Some(hash) = cache.get(path) {
                    return Ok(hash.clone());
                }
            }
        }
    }
    let mut file = file?;
    let mut hasher = Sha256::new();
    let mut buffer = [0; 8192];

    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }

    let result = hasher.finalize();
    let hash = format!("{:x}", result);
    if let Ok(mut cache) = get_recent_hashes().lock() {
        cache.insert(path.to_path_buf(), hash.clone());
    }
    Ok(hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn baseline_scan_finds_files() {
        let dir = tempdir().unwrap();
        let test_file = dir.path().join("test.txt");
        fs::write(&test_file, "hello world").unwrap();

        let mut fim = FileIntegrityMonitor::new(vec![dir.path().to_path_buf()]);
        let events = fim.baseline_scan();
        assert!(events.iter().any(|e| e.file_path.contains("test.txt")));
        assert!(events.iter().all(|e| e.event_type == FimEventType::Added));
    }

    #[test]
    fn verify_integrity_detects_modification() {
        let dir = tempdir().unwrap();
        let test_file = dir.path().join("test.txt");
        fs::write(&test_file, "original").unwrap();

        let mut fim = FileIntegrityMonitor::new(vec![dir.path().to_path_buf()]);
        fim.baseline_scan();

        fs::write(&test_file, "modified").unwrap();

        let events = fim.verify_integrity();
        assert!(events.iter().any(|e| {
            e.file_path.contains("test.txt") && e.event_type == FimEventType::Modified
        }));
    }

    #[test]
    fn verify_integrity_detects_deletion() {
        let dir = tempdir().unwrap();
        let test_file = dir.path().join("test.txt");
        fs::write(&test_file, "content").unwrap();

        let mut fim = FileIntegrityMonitor::new(vec![dir.path().to_path_buf()]);
        fim.baseline_scan();

        fs::remove_file(&test_file).unwrap();

        let events = fim.verify_integrity();
        assert!(events.iter().any(|e| {
            e.file_path.contains("test.txt") && e.event_type == FimEventType::Deleted
        }));
    }
}
