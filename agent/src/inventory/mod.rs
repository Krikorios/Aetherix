use serde::{Deserialize, Serialize};
use sysinfo::{System, Networks};
use std::collections::HashMap;

/// System inventory collected periodically.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SystemInventory {
    pub hostname: String,
    pub os_name: String,
    pub os_version: String,
    pub kernel_version: String,
    pub total_memory: u64,
    pub used_memory: u64,
    pub total_swap: u64,
    pub used_swap: u64,
    pub cpu_count: usize,
    pub processes_count: usize,
    pub networks: HashMap<String, NetworkInterfaceInfo>,
    pub timestamp: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NetworkInterfaceInfo {
    pub mac_address: String,
    pub ip_addresses: Vec<String>,
}

pub fn collect_inventory(sys: &mut System) -> SystemInventory {
    sys.refresh_all();
    
    let networks = Networks::new_with_refreshed_list();
    let mut net_info = HashMap::new();
    
    for (name, data) in &networks {
        let mac = data.mac_address();
        let mac_str = mac.to_string();
        let ip_nets = data.ip_networks();
            
        let ips = ip_nets.iter().map(|n| n.addr.to_string()).collect();
        
        net_info.insert(name.to_string(), NetworkInterfaceInfo {
            mac_address: mac_str,
            ip_addresses: ips,
        });
    }

    SystemInventory {
        hostname: System::host_name().unwrap_or_else(|| "unknown".to_string()),
        os_name: System::name().unwrap_or_else(|| "unknown".to_string()),
        os_version: System::os_version().unwrap_or_else(|| "unknown".to_string()),
        kernel_version: System::kernel_version().unwrap_or_else(|| "unknown".to_string()),
        total_memory: sys.total_memory(),
        used_memory: sys.used_memory(),
        total_swap: sys.total_swap(),
        used_swap: sys.used_swap(),
        cpu_count: sys.cpus().len(),
        processes_count: sys.processes().len(),
        networks: net_info,
        timestamp: chrono::Utc::now().to_rfc3339(),
    }
}
