use super::{EdrAction, EdrDetectionKind, EdrEvent};
use std::collections::HashMap;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use sysinfo::{ProcessesToUpdate, System};

#[derive(Clone, Debug)]
pub struct ProcessExec {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub path: String,
    pub cmdline: String,
}

pub type ProcessSink = Arc<Mutex<Vec<EdrEvent>>>;

pub struct ProcessMonitor {
    known_pids: HashMap<u32, ProcessExec>,
    system: System,
    sink: ProcessSink,
    _watcher_thread: Option<thread::JoinHandle<()>>,
    _shutdown: Option<Sender<()>>,
}

impl ProcessMonitor {
    pub fn new() -> Self {
        let sink: ProcessSink = Arc::new(Mutex::new(Vec::new()));
        let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>();

        let (system, known_pids) = Self::snapshot();
        Self::start_watcher(sink.clone(), shutdown_rx);

        Self {
            known_pids,
            system,
            sink,
            _watcher_thread: None,
            _shutdown: Some(shutdown_tx),
        }
    }

    fn snapshot() -> (System, HashMap<u32, ProcessExec>) {
        let mut system = System::new_all();
        system.refresh_processes(ProcessesToUpdate::All, true);

        let mut known_pids = HashMap::new();
        for (pid, process) in system.processes() {
            let pid_u32 = pid.as_u32();
            let ppid_u32 = process.parent().map(|p| p.as_u32()).unwrap_or(0);

            let cmd_str: Vec<String> = process
                .cmd()
                .iter()
                .map(|s| s.to_string_lossy().into_owned())
                .collect();

            known_pids.insert(
                pid_u32,
                ProcessExec {
                    pid: pid_u32,
                    ppid: ppid_u32,
                    name: process.name().to_string_lossy().into_owned(),
                    path: process
                        .exe()
                        .map(|p| p.to_string_lossy().into_owned())
                        .unwrap_or_default(),
                    cmdline: cmd_str.join(" "),
                },
            );
        }

        (system, known_pids)
    }

    fn start_watcher(sink: ProcessSink, shutdown: Receiver<()>) {
        thread::Builder::new()
            .name("aetherix-edr-process-watcher".to_string())
            .spawn(move || {
                let mut system = System::new_all();
                let mut known_pids = HashMap::new();

                // Initial snapshot
                system.refresh_processes(ProcessesToUpdate::All, true);
                for (pid, process) in system.processes() {
                    let pid_u32 = pid.as_u32();
                    known_pids.insert(
                        pid_u32,
                        ProcessExec {
                            pid: pid_u32,
                            ppid: process.parent().map(|p| p.as_u32()).unwrap_or(0),
                            name: process.name().to_string_lossy().into_owned(),
                            path: process
                                .exe()
                                .map(|p| p.to_string_lossy().into_owned())
                                .unwrap_or_default(),
                            cmdline: process
                                .cmd()
                                .iter()
                                .map(|s| s.to_string_lossy().into_owned())
                                .collect::<Vec<_>>()
                                .join(" "),
                        },
                    );
                }

                let delay = Duration::from_millis(1000);
                loop {
                    if shutdown.try_recv().is_ok() {
                        break;
                    }

                    thread::sleep(delay);
                    system.refresh_processes(ProcessesToUpdate::All, true);

                    let mut current_pids = HashMap::new();
                    for (pid, process) in system.processes() {
                        let pid_u32 = pid.as_u32();
                        let ppid_u32 = process.parent().map(|p| p.as_u32()).unwrap_or(0);

                        let cmd_str: Vec<String> = process
                            .cmd()
                            .iter()
                            .map(|s| s.to_string_lossy().into_owned())
                            .collect();

                        let exec = ProcessExec {
                            pid: pid_u32,
                            ppid: ppid_u32,
                            name: process.name().to_string_lossy().into_owned(),
                            path: process
                                .exe()
                                .map(|p| p.to_string_lossy().into_owned())
                                .unwrap_or_default(),
                            cmdline: cmd_str.join(" "),
                        };

                        current_pids.insert(pid_u32, exec.clone());

                        // New process detected
                        if !known_pids.contains_key(&pid_u32) {
                            let mut collected = sink.lock().expect("edr sink poisoned");
                            if let Some(event) = evaluate_exec(&exec, &current_pids) {
                                collected.push(event);
                            }
                        }
                    }

                    known_pids = current_pids;
                }
            })
            .ok();
    }

    /// Drain buffered events from the watcher thread.
    pub fn drain_events(&mut self) -> Vec<EdrEvent> {
        let mut sink = self.sink.lock().expect("edr sink poisoned");
        sink.drain(..).collect()
    }

    /// Single snapshot scan (for backward compatibility / on-demand use).
    pub fn scan(&mut self, policy_version: &str) -> Vec<EdrEvent> {
        let mut events = Vec::new();
        self.system.refresh_processes(ProcessesToUpdate::All, true);

        let mut current_pids = HashMap::new();

        for (pid, process) in self.system.processes() {
            let pid_u32 = pid.as_u32();
            let ppid_u32 = process.parent().map(|p| p.as_u32()).unwrap_or(0);

            let cmd_str: Vec<String> = process
                .cmd()
                .iter()
                .map(|s| s.to_string_lossy().into_owned())
                .collect();

            let exec = ProcessExec {
                pid: pid_u32,
                ppid: ppid_u32,
                name: process.name().to_string_lossy().into_owned(),
                path: process
                    .exe()
                    .map(|p| p.to_string_lossy().into_owned())
                    .unwrap_or_default(),
                cmdline: cmd_str.join(" "),
            };

            current_pids.insert(pid_u32, exec.clone());

            if !self.known_pids.contains_key(&pid_u32) {
                if let Some(event) = evaluate_exec(&exec, &current_pids) {
                    let mut e = event;
                    e.policy_version = policy_version.to_string();
                    events.push(e);
                }
            }
        }

        self.known_pids = current_pids;
        events
    }
}

fn evaluate_exec(exec: &ProcessExec, current_pids: &HashMap<u32, ProcessExec>) -> Option<EdrEvent> {
    // Rule 1: Office app spawning a shell
    if let Some(parent) = current_pids.get(&exec.ppid) {
        let parent_name = parent.name.to_lowercase();
        let child_name = exec.name.to_lowercase();

        let is_suspicious_parent = parent_name.contains("winword")
            || parent_name.contains("excel")
            || parent_name.contains("powerpnt");

        let is_suspicious_child = child_name.contains("powershell")
            || child_name.contains("cmd.exe")
            || child_name.contains("bash")
            || child_name.contains("sh");

        if is_suspicious_parent && is_suspicious_child {
            return Some(EdrEvent {
                kind: EdrDetectionKind::SuspiciousProcessChain,
                rule_id: "office_spawns_shell".to_string(),
                action: EdrAction::Monitor,
                process_path: Some(exec.path.clone()),
                process_pid: Some(exec.pid),
                parent_pid: Some(exec.ppid),
                file_path: None,
                file_sha256: None,
                matched_indicator: Some(format!("{} -> {}", parent.name, exec.name)),
                policy_version: String::new(),
                collected_at: chrono::Utc::now().to_rfc3339(),
                tags: Vec::new(),
                matched_strings: Vec::new(),
                rule_metadata: HashMap::new(),
                scan_duration_ms: None,
                matched_rules: Vec::new(),
                evidence_controls: Vec::new(),
                response: None,
                recovery_hints: None,
                rollback_evidence: None,
            });
        }

        // Rule 2: Encoded PowerShell command
        if child_name.contains("powershell")
            && (exec.cmdline.to_lowercase().contains("-enc")
                || exec.cmdline.to_lowercase().contains("-encodedcommand"))
        {
            return Some(EdrEvent {
                kind: EdrDetectionKind::SuspiciousProcessChain,
                rule_id: "powershell_encoded_command".to_string(),
                action: EdrAction::Monitor,
                process_path: Some(exec.path.clone()),
                process_pid: Some(exec.pid),
                parent_pid: Some(exec.ppid),
                file_path: None,
                file_sha256: None,
                matched_indicator: Some(exec.cmdline.clone()),
                policy_version: String::new(),
                collected_at: chrono::Utc::now().to_rfc3339(),
                tags: Vec::new(),
                matched_strings: Vec::new(),
                rule_metadata: HashMap::new(),
                scan_duration_ms: None,
                matched_rules: Vec::new(),
                evidence_controls: Vec::new(),
                response: None,
                recovery_hints: None,
                rollback_evidence: None,
            });
        }
    }

    None
}
