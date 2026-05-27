//! File-upload / save interceptor.
//!
//! Watches a configurable set of "exfiltration-prone" directories
//! (Downloads, Desktop, custom upload staging dirs) for newly created
//! or modified files. Each new/changed file is read (capped at
//! `MAX_SCAN_BYTES`), wrapped in a `DlpEvent` of type `Upload`, and
//! routed through the same `DlpClient::evaluate` pipeline used by the
//! clipboard interceptor. When the decision is `Block`, the file is
//! deleted in place — the equivalent of cancelling an OS save dialog
//! without needing a kernel hook.
//!
//! The interceptor is polling-based by design: it pulls in zero new
//! crates, behaves identically on macOS / Linux / Windows, and is
//! trivially deterministic for integration tests. The poll interval
//! is shared with the main DLP loop.

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use crate::dlp::{DlpEvent, DlpEventType, EventSource};

/// Hard cap on how many bytes of a file we feed into the semantic
/// detector. Anything larger is sampled from the head — covers
/// virtually all human-authored documents and prevents huge media
/// files from stalling the loop.
pub const MAX_SCAN_BYTES: usize = 1 * 1024 * 1024;

/// Default file extensions the interceptor will scan. Binary office
/// formats are intentionally omitted from the default set; operators
/// can add them via `AETHERIX_FILE_WATCH_EXTENSIONS`.
const DEFAULT_EXTENSIONS: &[&str] = &[
    "txt", "csv", "tsv", "json", "yaml", "yml", "log", "md", "html", "xml", "ini", "conf", "sql",
];

#[derive(Debug, Clone, Eq, PartialEq)]
struct FileFingerprint {
    modified: SystemTime,
    size: u64,
}

/// Real file-upload interceptor.
pub struct FileUploadInterceptor {
    watched_dirs: Vec<PathBuf>,
    extensions: Vec<String>,
    seen: HashMap<PathBuf, FileFingerprint>,
    max_scan_bytes: usize,
    primed: bool,
}

impl FileUploadInterceptor {
    pub fn new(watched_dirs: Vec<PathBuf>, extensions: Vec<String>) -> Self {
        Self {
            watched_dirs,
            extensions,
            seen: HashMap::new(),
            max_scan_bytes: MAX_SCAN_BYTES,
            primed: false,
        }
    }

    /// Build an interceptor from env-vars:
    ///
    ///   * `AETHERIX_FILE_WATCH_DIRS`   – comma-separated absolute paths.
    ///                                     Defaults to `$HOME/Downloads`.
    ///   * `AETHERIX_FILE_WATCH_EXTENSIONS` – comma-separated bare
    ///                                     extensions (no dot). Defaults
    ///                                     to a curated text-document set.
    ///
    /// Returns `None` when no usable watch directory could be resolved
    /// (e.g. headless container without `$HOME`); the main loop treats
    /// that as "file interceptor disabled".
    pub fn from_env() -> Option<Self> {
        let watched_dirs: Vec<PathBuf> = std::env::var("AETHERIX_FILE_WATCH_DIRS")
            .ok()
            .map(|raw| {
                raw.split(',')
                    .map(|s| s.trim())
                    .filter(|s| !s.is_empty())
                    .map(PathBuf::from)
                    .collect()
            })
            .filter(|v: &Vec<PathBuf>| !v.is_empty())
            .or_else(|| {
                let home = std::env::var("HOME")
                    .or_else(|_| std::env::var("USERPROFILE"))
                    .ok()?;
                Some(vec![PathBuf::from(home).join("Downloads")])
            })?;

        let extensions: Vec<String> = std::env::var("AETHERIX_FILE_WATCH_EXTENSIONS")
            .ok()
            .map(|raw| {
                raw.split(',')
                    .map(|s| s.trim().trim_start_matches('.').to_ascii_lowercase())
                    .filter(|s| !s.is_empty())
                    .collect()
            })
            .unwrap_or_else(|| DEFAULT_EXTENSIONS.iter().map(|s| s.to_string()).collect());

        Some(Self::new(watched_dirs, extensions))
    }

    pub fn watched_dirs(&self) -> &[PathBuf] {
        &self.watched_dirs
    }

    /// Walk each watched directory once and return events for files
    /// that are new or whose (size, mtime) changed since the last scan.
    /// The first call is "priming": existing files are recorded but
    /// not emitted, so the agent does not flood the control plane the
    /// instant it starts up.
    pub fn scan(&mut self) -> Vec<UploadCandidate> {
        let mut events = Vec::new();
        let priming = !self.primed;

        for dir in self.watched_dirs.clone() {
            if let Err(err) = self.scan_dir(&dir, priming, &mut events) {
                eprintln!(
                    "aetherix-agent: file watcher: skipping {} ({err})",
                    dir.display()
                );
            }
        }

        self.primed = true;
        events
    }

    fn scan_dir(
        &mut self,
        dir: &Path,
        priming: bool,
        out: &mut Vec<UploadCandidate>,
    ) -> Result<()> {
        let entries = match fs::read_dir(dir) {
            Ok(e) => e,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(err) => return Err(err).context("read_dir"),
        };

        for entry in entries.flatten() {
            let path = entry.path();
            let metadata = match entry.metadata() {
                Ok(m) if m.is_file() => m,
                _ => continue,
            };

            if !self.extension_allowed(&path) {
                continue;
            }

            let modified = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);
            let size = metadata.len();
            let fingerprint = FileFingerprint { modified, size };

            let changed = match self.seen.get(&path) {
                Some(existing) => existing != &fingerprint,
                None => true,
            };

            self.seen.insert(path.clone(), fingerprint);
            if priming || !changed {
                continue;
            }

            let content = match self.read_capped(&path) {
                Ok(c) => c,
                Err(err) => {
                    eprintln!(
                        "aetherix-agent: file watcher: cannot read {} ({err})",
                        path.display()
                    );
                    continue;
                }
            };

            let event = DlpEvent {
                event_type: DlpEventType::Upload,
                source: EventSource::Endpoint,
                content,
                // The file path is the artifact, not the exfiltration
                // destination — leaving this `None` lets the semantic
                // policy gate evaluate the upload on its own merits
                // rather than failing the destination allow-list check.
                // The path is preserved on the surrounding
                // `UploadCandidate` for enforcement and logging.
                destination: None,
                process_name: Some(format!("file://{}", path.display())),
            };
            out.push(UploadCandidate { path, event });
        }

        Ok(())
    }

    fn extension_allowed(&self, path: &Path) -> bool {
        let ext = match path.extension().and_then(|e| e.to_str()) {
            Some(e) => e.to_ascii_lowercase(),
            None => return false,
        };
        self.extensions.iter().any(|allowed| allowed == &ext)
    }

    fn read_capped(&self, path: &Path) -> Result<String> {
        let bytes = fs::read(path).context("reading watched file")?;
        let slice = if bytes.len() > self.max_scan_bytes {
            &bytes[..self.max_scan_bytes]
        } else {
            &bytes[..]
        };
        Ok(String::from_utf8_lossy(slice).into_owned())
    }

    /// Real enforcement: delete the file so the user's upload /
    /// downstream sync (Dropbox watcher, browser upload picker, etc.)
    /// has nothing to ship. Also forgets the fingerprint so a
    /// subsequent re-creation is treated as a fresh event.
    pub fn enforce_block(&mut self, path: &Path) -> Result<()> {
        self.seen.remove(path);
        fs::remove_file(path).with_context(|| format!("removing blocked file {}", path.display()))
    }
}

/// One candidate file flagged by the scanner. The path is kept
/// separately from the `DlpEvent` so the main loop can call
/// `enforce_block(path)` on a `Block` decision without re-parsing
/// the event destination.
#[derive(Debug)]
pub struct UploadCandidate {
    pub path: PathBuf,
    pub event: DlpEvent,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::thread;
    use std::time::Duration;

    fn write_file(dir: &Path, name: &str, body: &str) -> PathBuf {
        let path = dir.join(name);
        let mut f = fs::File::create(&path).unwrap();
        f.write_all(body.as_bytes()).unwrap();
        f.sync_all().unwrap();
        path
    }

    #[test]
    fn priming_scan_does_not_emit_existing_files() {
        let dir = tempfile::tempdir().unwrap();
        write_file(dir.path(), "pre-existing.txt", "hello");
        let mut interceptor = FileUploadInterceptor::new(
            vec![dir.path().to_path_buf()],
            vec!["txt".into()],
        );

        let first = interceptor.scan();
        assert!(first.is_empty(), "priming scan must not emit pre-existing files");

        let second = interceptor.scan();
        assert!(second.is_empty(), "unchanged files must not re-emit");
    }

    #[test]
    fn new_file_after_priming_is_emitted_once() {
        let dir = tempfile::tempdir().unwrap();
        let mut interceptor = FileUploadInterceptor::new(
            vec![dir.path().to_path_buf()],
            vec!["txt".into()],
        );
        let _ = interceptor.scan(); // priming

        thread::sleep(Duration::from_millis(10));
        let path = write_file(dir.path(), "new.txt", "[restricted] secret payload");
        let events = interceptor.scan();

        assert_eq!(events.len(), 1, "exactly one event for a brand-new file");
        assert_eq!(events[0].path, path);
        assert_eq!(events[0].event.event_type, DlpEventType::Upload);

        let again = interceptor.scan();
        assert!(again.is_empty(), "same fingerprint must not re-emit");
    }

    #[test]
    fn extensions_outside_allow_list_are_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let mut interceptor = FileUploadInterceptor::new(
            vec![dir.path().to_path_buf()],
            vec!["txt".into()],
        );
        let _ = interceptor.scan();
        write_file(dir.path(), "image.png", "binary");
        let events = interceptor.scan();
        assert!(events.is_empty());
    }

    #[test]
    fn enforce_block_deletes_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let mut interceptor = FileUploadInterceptor::new(
            vec![dir.path().to_path_buf()],
            vec!["txt".into()],
        );
        let _ = interceptor.scan();
        let path = write_file(dir.path(), "leak.txt", "[restricted] data");
        let events = interceptor.scan();
        assert_eq!(events.len(), 1);

        interceptor.enforce_block(&path).expect("delete must succeed");
        assert!(!path.exists(), "blocked file must be removed");
    }
}
