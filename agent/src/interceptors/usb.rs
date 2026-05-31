use crate::dlp::{DlpEvent, DlpEventType, EventSource};
use std::collections::HashSet;
use sysinfo::Disks;

pub struct UsbInterceptor {
    known_disks: HashSet<String>,
}

impl UsbInterceptor {
    pub fn new() -> Self {
        let mut interceptor = Self {
            known_disks: HashSet::new(),
        };
        // Initial scan to populate known_disks without triggering alerts
        interceptor.scan_internal(false);
        interceptor
    }

    pub fn poll(&mut self) -> Vec<DlpEvent> {
        self.scan_internal(true)
    }

    fn scan_internal(&mut self, emit_events: bool) -> Vec<DlpEvent> {
        let mut events = Vec::new();
        let disks = Disks::new_with_refreshed_list();
        let mut current_disks = HashSet::new();

        for disk in &disks {
            if disk.is_removable() {
                let name = disk.name().to_string_lossy().into_owned();
                let mount = disk.mount_point().to_string_lossy().into_owned();
                let id = format!("{}::{}", name, mount);

                current_disks.insert(id.clone());

                if emit_events && !self.known_disks.contains(&id) {
                    events.push(DlpEvent {
                        event_type: DlpEventType::UsbMounted,
                        source: EventSource::Endpoint,
                        content: format!("USB Drive Mounted: {} at {}", name, mount),
                        destination: Some(mount.clone()),
                        process_name: None,
                        sha256_hash: None,
                    });
                }
            }
        }

        self.known_disks = current_disks;
        events
    }
}
