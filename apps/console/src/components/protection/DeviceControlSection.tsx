import React, { useState } from "react";
import { ChevronDown, Plus, Trash2 } from "lucide-react";

type DeviceRule = {
  id: string;
  deviceClass: string;
  description: string;
  permission: "Allowed" | "Blocked" | "Read-only" | "Ask every time";
};

type DeviceExclusion = {
  id: string;
  exclusionType: string;
  excludedItem: string;
  description: string;
  permission: string;
};

const DEFAULT_RULES: DeviceRule[] = [
  { id: "bluetooth", deviceClass: "Bluetooth", description: "Bluetooth Devices", permission: "Allowed" },
  { id: "cdrom", deviceClass: "CDROM Drive", description: "CDROM Drives", permission: "Allowed" },
  { id: "floppy", deviceClass: "Floppy Disk Drive", description: "Floppy Disk Drives", permission: "Allowed" },
  { id: "ieee-1284", deviceClass: "IEEE 1284.4", description: "IEEE 1284.4", permission: "Allowed" },
  { id: "ieee-1394", deviceClass: "IEEE 1394", description: "IEEE 1394", permission: "Allowed" },
  { id: "imaging", deviceClass: "Imaging", description: "Imaging Devices", permission: "Allowed" },
  { id: "modem", deviceClass: "Modem", description: "Modems", permission: "Allowed" },
  { id: "tape", deviceClass: "Tape Drive", description: "Tape Drives", permission: "Allowed" },
  { id: "portable", deviceClass: "Windows Portable", description: "Windows Portable", permission: "Allowed" },
  { id: "lpt", deviceClass: "COM/LPT Ports", description: "LPT/COM Ports", permission: "Allowed" },
  { id: "scsi", deviceClass: "SCSI Raid", description: "SCSI Raid", permission: "Allowed" },
  { id: "printers", deviceClass: "Printers", description: "Printers", permission: "Allowed" },
  { id: "network", deviceClass: "Network Adapter", description: "Network Adapters", permission: "Allowed" },
  { id: "wireless", deviceClass: "Wireless Network Adapter", description: "Wireless Network Adapters", permission: "Allowed" },
  { id: "internal", deviceClass: "Internal Storage", description: "Internal Storage", permission: "Allowed" },
  { id: "external", deviceClass: "External Storage", description: "External Storage", permission: "Allowed" },
];

interface DeviceControlSectionProps {
  enabled: boolean;
  rules: DeviceRule[];
  exclusions: DeviceExclusion[];
  canEdit: boolean;
  onUpdateEnabled: (enabled: boolean) => void;
  onUpdateRules: (rules: DeviceRule[]) => void;
  onUpdateExclusions: (exclusions: DeviceExclusion[]) => void;
  renderSwitchTitle: (title: string, enabled: boolean) => React.ReactNode;
}

export function DeviceControlSection({
  enabled,
  rules,
  exclusions,
  canEdit,
  onUpdateEnabled,
  onUpdateRules,
  onUpdateExclusions,
  renderSwitchTitle,
}: DeviceControlSectionProps) {
  const [activeTab, setActiveTab] = useState<"rules" | "exclusions">("rules");
  const [selectedRules, setSelectedRules] = useState<string[]>([]);
  const [selectedExclusions, setSelectedExclusions] = useState<string[]>([]);
  const [filters, setFilters] = useState({ type: "", item: "", description: "", permission: "" });

  const activeRules = rules.length > 0 ? rules : DEFAULT_RULES;

  const filteredExclusions = exclusions.filter((item) =>
    item.exclusionType.toLowerCase().includes(filters.type.toLowerCase()) &&
    item.excludedItem.toLowerCase().includes(filters.item.toLowerCase()) &&
    item.description.toLowerCase().includes(filters.description.toLowerCase()) &&
    (filters.permission ? item.permission === filters.permission : true),
  );

  function toggleRule(id: string) {
    setSelectedRules((current) => current.includes(id) ? current.filter((item) => item !== id) : [...current, id]);
  }

  function toggleExclusion(id: string) {
    setSelectedExclusions((current) => current.includes(id) ? current.filter((item) => item !== id) : [...current, id]);
  }

  function addExclusion() {
    const next: DeviceExclusion = {
      id: `exclusion-${Date.now()}`,
      exclusionType: "Device ID",
      excludedItem: "USB\\VID_0781&PID_5591",
      description: "Approved removable media exception",
      permission: "Allowed",
    };
    onUpdateExclusions([next, ...exclusions]);
    setActiveTab("exclusions");
  }

  return (
    <section className="policyDetailSection policyAgentBlock wideAgent">
      {renderSwitchTitle("Device Control", enabled)}
      <p>Control removable media and peripheral usage on protected endpoints.</p>
      <label className="policyCheckboxRow">
        <input type="checkbox" checked={enabled} onChange={(e) => onUpdateEnabled(e.target.checked)} disabled={!canEdit} />
        Enable device control policy
      </label>

      {enabled && (
        <div style={{ marginTop: "1rem" }}>
          <div className="deviceTabs" style={{ display: "flex", gap: "1rem", marginBottom: "1rem" }}>
            <button 
              className={activeTab === "rules" ? "sub active" : "sub"} 
              onClick={() => setActiveTab("rules")}
              style={{ fontWeight: activeTab === "rules" ? "bold" : "normal", background: "none", border: "none", cursor: "pointer", textDecoration: activeTab === "rules" ? "underline" : "none" }}
            >
              Rules
            </button>
            <button 
              className={activeTab === "exclusions" ? "sub active" : "sub"} 
              onClick={() => setActiveTab("exclusions")}
              style={{ fontWeight: activeTab === "exclusions" ? "bold" : "normal", background: "none", border: "none", cursor: "pointer", textDecoration: activeTab === "exclusions" ? "underline" : "none" }}
            >
              Exclusions
            </button>
          </div>

          {activeTab === "rules" ? (
            <div className="deviceRulesTable" role="table" aria-label="Device control rules">
              <div role="row" className="head"><span>Device Class</span><span>Description</span><span>Permission</span></div>
              {activeRules.map((rule) => (
                <label key={rule.id} role="row" className={selectedRules.includes(rule.id) ? "selected" : ""}>
                  <span><input type="checkbox" checked={selectedRules.includes(rule.id)} onChange={() => toggleRule(rule.id)} />{rule.deviceClass}</span>
                  <span>{rule.description}</span>
                  <select 
                    value={rule.permission} 
                    disabled={!canEdit} 
                    onChange={(event) => {
                      const updated = activeRules.map((item) => 
                        item.id === rule.id ? { ...item, permission: event.target.value as DeviceRule["permission"] } : item
                      );
                      onUpdateRules(updated);
                    }}
                  >
                    <option>Allowed</option><option>Blocked</option><option>Read-only</option><option>Ask every time</option>
                  </select>
                </label>
              ))}
            </div>
          ) : (
            <>
              <div className="deviceActionBar">
                <button type="button" onClick={addExclusion} disabled={!canEdit}><Plus size={13} /> ADD <ChevronDown size={13} /></button>
                <button 
                  type="button" 
                  className="danger" 
                  disabled={!canEdit || selectedExclusions.length === 0} 
                  onClick={() => {
                    onUpdateExclusions(exclusions.filter((item) => !selectedExclusions.includes(item.id)));
                    setSelectedExclusions([]);
                  }}
                >
                  <Trash2 size={13} /> DELETE
                </button>
              </div>
              <div className="deviceFilters">
                <input value={filters.type} onChange={(event) => setFilters((current) => ({ ...current, type: event.target.value }))} placeholder="Exclusion type" />
                <input value={filters.item} onChange={(event) => setFilters((current) => ({ ...current, item: event.target.value }))} placeholder="Excluded item" />
                <input value={filters.description} onChange={(event) => setFilters((current) => ({ ...current, description: event.target.value }))} placeholder="Description" />
                <select value={filters.permission} onChange={(event) => setFilters((current) => ({ ...current, permission: event.target.value }))}><option value="">Permission</option><option>Allowed</option><option>Blocked</option><option>Read-only</option></select>
                <button type="button" onClick={() => setFilters({ type: "", item: "", description: "", permission: "" })}>Reset filters</button>
              </div>
              <div className="deviceExclusionTable" role="table" aria-label="Device control exclusions">
                <div role="row" className="head"><span><input type="checkbox" aria-label="Select all exclusions" /></span><span>Exclusion type</span><span>Excluded item</span><span>Description</span><span>Permission</span></div>
                {filteredExclusions.length === 0 ? (
                  <div className="deviceEmpty" role="row"><strong>No exclusions</strong><span>Adjust your filters or start adding exclusions.</span><button type="button" onClick={addExclusion} disabled={!canEdit}>ADD EXCLUSIONS</button></div>
                ) : filteredExclusions.map((item) => (
                  <label key={item.id} role="row">
                    <span><input type="checkbox" checked={selectedExclusions.includes(item.id)} onChange={() => toggleExclusion(item.id)} /></span>
                    <span>{item.exclusionType}</span><span>{item.excludedItem}</span><span>{item.description}</span><span>{item.permission}</span>
                  </label>
                ))}
              </div>
            </>
          )}
        </div>
      )}
    </section>
  );
}
