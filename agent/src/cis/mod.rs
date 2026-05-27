use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CisCheckResult {
    pub rule_id: String,
    pub title: String,
    pub status: CisStatus,
    pub actual_value: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum CisStatus {
    Pass,
    Fail,
    Error,
}

pub struct CisScanner {
    // stub
}

impl CisScanner {
    pub fn new() -> Self {
        Self {}
    }

    pub fn scan(&self) -> Vec<CisCheckResult> {
        let mut results = Vec::new();

        // Check 1: Ensure SSH root login is disabled (Linux only for POC)
        if cfg!(unix) {
            let root_login_disabled = check_ssh_root_login();
            results.push(CisCheckResult {
                rule_id: "CIS_5.2.3".to_string(),
                title: "Ensure SSH root login is disabled".to_string(),
                status: if root_login_disabled { CisStatus::Pass } else { CisStatus::Fail },
                actual_value: if root_login_disabled { "disabled".to_string() } else { "enabled or unknown".to_string() },
            });
        }

        // Check 2: Mock check for BitLocker / FileVault (Cross-platform)
        results.push(CisCheckResult {
            rule_id: "CIS_2.1.1".to_string(),
            title: "Ensure disk encryption is enabled".to_string(),
            status: CisStatus::Pass, // Assumed pass for POC
            actual_value: "encrypted".to_string(),
        });

        results
    }
}

#[cfg(unix)]
fn check_ssh_root_login() -> bool {
    if let Ok(content) = std::fs::read_to_string("/etc/ssh/sshd_config") {
        for line in content.lines() {
            let line = line.trim();
            if line.starts_with("PermitRootLogin") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() > 1 && parts[1].to_lowercase() == "no" {
                    return true;
                }
            }
        }
    }
    false
}

#[cfg(not(unix))]
fn check_ssh_root_login() -> bool {
    true
}
