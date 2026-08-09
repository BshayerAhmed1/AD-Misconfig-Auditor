# Active Directory Misconfiguration & Live MITRE ATT&CK Auditor 🛡️

An automated Active Directory (AD) security auditor written in Python. This tool parses BloodHound JSON exports, filters out inherited permission noise to eliminate false positives, and maps identified domain misconfigurations directly to live **MITRE ATT&CK Enterprise** techniques via REST API. 

It generates an interactive, self-contained **HTML Executive Dashboard** featuring real-time risk metrics and a built-in **Print-to-PDF** mechanism for reporting.

---

## 🛡️ Architecture & Core Mechanics

Traditional Active Directory audits often generate excessive noise due to inherited permissions and default administrative ACLs. This auditor implements a refined, targeted detection and reporting architecture:

* **Account Misconfiguration Detection:** Automatically identifies high-risk account properties including AS-REP Roasting targets (`dontreqpreauth`), Kerberoasting targets (`hasspn`), weak account policies (`passwordnotreqd`), and Unconstrained Delegation.
* **Inherited ACL Noise Reduction:** Filters out inherited Access Control Entries (ACEs) and default administrative groups to eliminate false positives and isolate actionable attack paths.
* **Hybrid SID Resolution Engine:** Resolves Security Identifiers (SIDs) using a multi-tiered fallback approach—mapping SIDs locally from BloodHound JSON, resolving via native Windows API (if available), and parsing well-known RID patterns (e.g., Domain Admins, Built-in Administrators).
* **Live MITRE ATT&CK Mapping:** Connects dynamically to MITRE's live Enterprise ATT&CK REST repository to fetch up-to-date technique names and clean, sanitized threat descriptions for every detected vulnerability.
* **Interactive Executive Dashboard:** Generates a dark-mode HTML dashboard featuring summary metrics cards, color-coded severity badges, and print media queries (`@media print`) for seamless one-click PDF exports.

---

## 🛠️ Tech Stack & Dependencies

* **Core Language:** Python 3.x
* **Integrations & Data:** REST API (`requests`), JSON parsing, Regular Expressions (`re`)
* **OS Interoperability:** `win32security` (optional native Windows API support)
* **Reporting & UI:** HTML5 / CSS3 (Dark Theme, Executive Metrics Grid, Print-to-PDF Styles)

---

## 🔄 Step-by-Step Audit Flow

1. **Live Threat Intelligence Fetching:**
   The engine connects to the official MITRE ATT&CK repository to pull the latest Enterprise matrix mapping data.
2. **JSON Parsing & Local Mapping:**
   Loads `users.json`, builds a local SID-to-Name map, and evaluates active account properties and ACLs.
3. **ACL Noise Filtering:**
   Filters out inherited ACEs and privileged default groups (`-512`, `-519`, `S-1-5-32-544`) to focus exclusively on direct, elevated risk vectors.
4. **Interactive Dashboard Generation:**
   Outputs `AD_Security_Audit_Report.html` containing calculated risk metrics (Critical, High, Medium) and detailed threat tables.

---

## 📊 Output & Reporting

Running the script automatically produces:
* **`AD_Security_Audit_Report.html`**: Open this file in any web browser to view the interactive dark-mode dashboard.
* **One-Click PDF Export**: Click the **"Export / Save as PDF"** button inside the dashboard header to generate a clean, professionally formatted PDF report ready for executive presentation.
