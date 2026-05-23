> Historical UI prompt, not current product documentation. Use [architecture.md](architecture.md), [development.md](development.md), and `apps/console/src/App.tsx` as the source of truth for the current navigation.

You are a senior frontend engineer improving the Aetherix MSP Console UI.

The current sidebar is functional but feels scattered. We want to reorganize it into clear, logical groups and enhance the overall UI polish while keeping the calm, modern green/cream aesthetic.

### Current Sidebar (Reference from screenshots)
- Top: Agentic AI Investigation
- PROTECTION: Threats Xplorer, Network, Risk Management, Policies, Reports, Quarantine
- MSP CONTROL: Companies, Accounts, Installers
- ADD-ONS: Sandbox Analyzer, Email Security, Mobile Security, Data Insights, Integrations, Configuration

### New Recommended Sidebar Structure

Implement exactly this grouped structure:

```tsx
// New Sidebar Structure
const sidebarGroups = [
  {
    title: "OVERVIEW",
    items: [
      { label: "Dashboard", icon: "LayoutDashboard", path: "/dashboard" },
      { label: "Executive Summary", icon: "BarChart3", path: "/executive-summary" },
      { label: "Health & Attack Surface", icon: "Shield", path: "/health" },
    ]
  },
  {
    title: "INCIDENTS & RESPONSE",
    items: [
      { label: "Alerts", icon: "Bell", path: "/alerts" },
      { label: "Search", icon: "Search", path: "/search" },
      { label: "Blocklist", icon: "Ban", path: "/blocklist" },
      { label: "Custom Rules", icon: "ListChecks", path: "/custom-rules" },
      { label: "Agentic AI Investigation", icon: "Brain", path: "/agentic-ai" },
      { label: "Threats Xplorer", icon: "Target", path: "/threats-xplorer" },
    ]
  },
  {
    title: "PROTECTION",
    items: [
      { label: "Policies", icon: "ShieldCheck", path: "/policies" },
      { label: "Antimalware & Behavior", icon: "Bug", path: "/antimalware" },
      { label: "Web & Email Protection", icon: "Globe", path: "/web-protection" },
      { label: "Device Control", icon: "Usb", path: "/device-control" },
      { label: "Quarantine", icon: "Archive", path: "/quarantine" },
    ]
  },
  {
    title: "RISK & EXTERNAL",
    items: [
      { label: "Risk Management", icon: "AlertTriangle", path: "/risk-management" },
      { label: "Digital Risk (DRP)", icon: "Eye", path: "/digital-risk" },
      { label: "External Attack Surface (EASM)", icon: "Globe2", path: "/easm" },
      { label: "Reports", icon: "FileText", path: "/reports" },
    ]
  },
  {
    title: "MSP CONTROL",
    items: [
      { label: "Companies", icon: "Building2", path: "/companies" },
      { label: "Accounts", icon: "Users", path: "/accounts" },
      { label: "Installers", icon: "Package", path: "/installers" },
      { label: "Policy Assignments", icon: "FileCheck", path: "/policy-assignments" },
    ]
  },
  {
    title: "ADD-ONS & INTEGRATIONS",
    items: [
      { label: "Sandbox Analyzer", icon: "FlaskConical", path: "/sandbox" },
      { label: "Email Security", icon: "Mail", path: "/email-security" },
      { label: "Mobile Security", icon: "Smartphone", path: "/mobile-security" },
      { label: "Data Insights", icon: "BarChart", path: "/data-insights" },
      { label: "Integrations", icon: "Plug", path: "/integrations" },
      { label: "Configuration", icon: "Settings", path: "/configuration" },
    ]
  }
];
```

### UI Enhancement Requirements

1. **Visual Grouping**
   - Clear section headers with subtle background (light green tint #E8F5E9 or similar)
   - Slightly larger, bold section titles
   - Consistent spacing between groups (24px recommended)

2. **Active State**
   - Strong visual indicator (dark green pill/background like current "Search" item)
   - Use the exact active styling from the current theme

3. **Icons**
   - Use Lucide React icons (already likely in the project)
   - Consistent size (18-20px)
   - Match the suggested icons above or choose close equivalents

4. **Hover & Interaction**
   - Subtle hover background (#F0F7F0 or similar)
   - Smooth transitions (150-200ms)
   - No harsh jumps

5. **Responsive Behavior**
   - On mobile/tablet: Collapsible sidebar with hamburger menu
   - Keep desktop experience clean and spacious

6. **Top Header Polish**
   - Clean logo area with small shield icon next to "Aetherix"
   - Keep "Signed in as" section at bottom (already good)

7. **Theme Consistency**
   - Maintain the current calm green/cream palette
   - Use the same font family and sizing
   - Add very subtle shadows or borders on cards for depth (optional)

### Files to Modify (Likely Locations)

- `src/components/Sidebar.tsx` (or `Sidebar/index.tsx`)
- `src/styles/globals.css` or `sidebar.module.css` (for new styling)
- `src/App.tsx` or layout file (if routing needs minor updates)

### Deliverables

1. Updated `Sidebar` component with the exact new grouped structure
2. Enhanced styling (section headers, hover states, active states, spacing)
3. Responsive behavior (collapsible on mobile)
4. Clean, professional look that feels premium and MSP-focused

### Acceptance Criteria

- Sidebar is clearly organized into 6 logical groups
- All existing menu items are preserved and properly placed
- UI feels calmer, more modern, and easier to scan
- Active state is clearly visible
- Hover interactions are smooth
- Mobile experience remains usable
- No breaking changes to routing or functionality

Start by showing me:
- The new `Sidebar.tsx` structure (with groups)
- Key CSS/Tailwind classes for section headers and active items
- Any new icon imports needed

Keep the calm, trustworthy, modern aesthetic of Aetherix. This change should make the console feel significantly more professional and organized.