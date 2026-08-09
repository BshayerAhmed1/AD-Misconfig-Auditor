import json
import re
import requests

try:
    import win32security
    WINDOWS_API_AVAILABLE = True
except ImportError:
    WINDOWS_API_AVAILABLE = False

def fetch_live_mitre_data():
    print("[*] Connecting to MITRE ATT&CK Enterprise Repository...")
    mitre_url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    try:
        response = requests.get(mitre_url, timeout=10)
        if response.status_code == 200:
            print("[+] Successfully fetched live MITRE ATT&CK data!")
            return response.json()
    except Exception as e:
        print(f"[-] Failed to connect to MITRE. Error: {e}")
    return None

def clean_mitre_description(raw_desc):
    if not raw_desc:
        return "No description available."
    clean_text = re.sub(r'\[([^\]]+)\]\([^\)]+\)', r'\1', raw_desc)
    clean_text = re.sub(r'\(Citation:[^\)]+\)', '', clean_text)
    sentences = [s.strip() for s in clean_text.split('.') if s.strip()]
    return '. '.join(sentences[:2]) + '.' if sentences else "No description available."

def extract_mitre_details(mitre_data, technique_id):
    if not mitre_data:
        return "No Live Data", "Ensure internet connection to fetch description."
        
    for item in mitre_data.get("objects", []):
        external_references = item.get("external_references", [])
        for ref in external_references:
            if ref.get("external_id") == technique_id:
                name = item.get("name", "Unknown Technique")
                raw_desc = item.get("description", "")
                desc = clean_mitre_description(raw_desc)
                return name, desc
    return "Unknown Technique", "Details not found in current MITRE matrix."

def build_json_sid_map(users_list):
    sid_map = {}
    for user in users_list:
        props = user.get("Properties", {})
        sid = user.get("ObjectIdentifier")
        name = props.get("name") or props.get("samaccountname")
        if sid and name:
            sid_map[sid] = name
    return sid_map

def resolve_sid_hybrid(sid_string, local_sid_map):
    if sid_string in local_sid_map:
        return local_sid_map[sid_string]

    if WINDOWS_API_AVAILABLE:
        try:
            win_sid = win32security.ConvertStringSidToSid(sid_string)
            name, domain, _ = win32security.LookupAccountSid(None, win_sid)
            return f"{domain}\\{name}" if domain else name
        except Exception:
            pass

    # Built-in RIDs
    if sid_string.endswith("-500"): return "Domain Administrator"
    if sid_string.endswith("-501"): return "Guest Account"
    if sid_string.endswith("-512"): return "Domain Admins"
    if sid_string.endswith("-513"): return "Domain Users"
    if sid_string.endswith("-519"): return "Enterprise Admins"
    if sid_string == "PHANTOM.CORP-S-1-1-0" or sid_string.endswith("-1-0"): return "Everyone"
    if "S-1-5-32-548" in sid_string: return "Account Operators"
    if "S-1-5-32-544" in sid_string: return "Built-in Administrators"

    return sid_string

def generate_interactive_dashboard(findings, output_html_path="AD_Security_Audit_Report.html"):
    print(f"[*] Generating Interactive Dashboard Report: {output_html_path}...")

    total_vulns = len(findings)
    critical_count = sum(1 for f in findings if f.get('Severity') == 'CRITICAL')
    high_count = sum(1 for f in findings if f.get('Severity') == 'HIGH')
    medium_count = sum(1 for f in findings if f.get('Severity') == 'MEDIUM')

    table_rows = ""
    for idx, item in enumerate(findings, 1):
        sev = item['Severity'].upper()
        badge_class = f"badge-{sev.lower()}"
        
        table_rows += f"""
        <tr>
            <td class="code-font">#{idx}</td>
            <td><strong>{item['Target']}</strong></td>
            <td><span class="badge {badge_class}">{sev}</span></td>
            <td>{item['ExploitedBy']}</td>
            <td><code>{item['Privilege']}</code></td>
            <td><span class="mitre-tag">{item['MitreID']}</span> {item['TechName']}</td>
            <td class="desc-cell">{item['Description']}</td>
        </tr>
        """

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AD Security Audit Report</title>
    <style>
        :root {{
            --bg-color: #0b0f19;
            --card-bg: #111827;
            --text-main: #f3f4f6;
            --border-color: #1f2937;
            --critical: #ef4444;
            --high: #f97316;
            --medium: #eab308;
            --accent: #06b6d4;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-main);
            margin: 0;
            padding: 30px;
        }}
        .header-bar {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 2px solid var(--border-color);
            padding-bottom: 15px;
            margin-bottom: 25px;
        }}
        .header-title h1 {{
            margin: 0;
            font-size: 24px;
            color: var(--accent);
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        .header-title p {{
            margin: 5px 0 0 0;
            color: #9ca3af;
            font-size: 13px;
        }}
        .btn-print {{
            background: #0284c7;
            color: white;
            border: none;
            padding: 10px 18px;
            border-radius: 6px;
            font-weight: 600;
            cursor: pointer;
            transition: 0.2s;
        }}
        .btn-print:hover {{
            background: #0369a1;
        }}

        /* Dashboard Cards */
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 15px;
            margin-bottom: 25px;
        }}
        .stat-card {{
            background: var(--card-bg);
            padding: 18px;
            border-radius: 8px;
            border: 1px solid var(--border-color);
            text-align: center;
        }}
        .stat-card .label {{
            font-size: 12px;
            color: #9ca3af;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        .stat-card .number {{
            font-size: 30px;
            font-weight: bold;
            margin-top: 5px;
        }}
        .stat-card.total .number {{ color: var(--accent); }}
        .stat-card.critical .number {{ color: var(--critical); }}
        .stat-card.high .number {{ color: var(--high); }}
        .stat-card.medium .number {{ color: var(--medium); }}

        /* Table Design */
        .table-container {{
            background: var(--card-bg);
            border-radius: 8px;
            border: 1px solid var(--border-color);
            overflow: hidden;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
        }}
        th, td {{
            padding: 12px 14px;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }}
        th {{
            background-color: #1f2937;
            color: #9ca3af;
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.8px;
        }}
        tr:hover {{ background-color: #1a2332; }}
        .code-font {{ font-family: monospace; color: #9ca3af; }}
        .desc-cell {{ color: #d1d5db; max-width: 280px; font-size: 12px; line-height: 1.4; }}

        /* Badges */
        .badge {{
            padding: 3px 8px;
            border-radius: 4px;
            font-weight: bold;
            font-size: 11px;
        }}
        .badge-critical {{ background: rgba(239, 68, 68, 0.15); color: var(--critical); border: 1px solid var(--critical); }}
        .badge-high {{ background: rgba(249, 115, 22, 0.15); color: var(--high); border: 1px solid var(--high); }}
        .badge-medium {{ background: rgba(234, 179, 8, 0.15); color: var(--medium); border: 1px solid var(--medium); }}
        .mitre-tag {{
            background: #0284c7;
            color: #fff;
            padding: 2px 5px;
            border-radius: 3px;
            font-family: monospace;
            font-size: 11px;
        }}

        @media print {{
            body {{
                background-color: #ffffff !important;
                color: #000000 !important;
                padding: 10px;
            }}
            .btn-print {{ display: none; }}
            .stat-card, .table-container {{
                border: 1px solid #ccc !important;
                background: #fff !important;
            }}
            th {{
                background-color: #f3f4f6 !important;
                color: #000 !important;
            }}
            tr {{ background-color: #fff !important; }}
            td {{ color: #000 !important; border-bottom: 1px solid #ddd !important; }}
            .desc-cell {{ color: #333 !important; }}
            .header-title h1 {{ color: #000 !important; }}
        }}
    </style>
</head>
<body>

    <div class="header-bar">
        <div class="header-title">
            <h1>🛡️ Active Directory Security Audit Report</h1>
            <p>Engine: Live MITRE ATT&CK & ACL Misconfiguration Auditor</p>
        </div>
        <button class="btn-print" onclick="window.print()">🖨️ Export / Save as PDF</button>
    </div>

    <!-- Executive Dashboard Cards -->
    <div class="stats-grid">
        <div class="stat-card total">
            <div class="label">Total Threats</div>
            <div class="number">{total_vulns}</div>
        </div>
        <div class="stat-card critical">
            <div class="label">Critical Risks</div>
            <div class="number">{critical_count}</div>
        </div>
        <div class="stat-card high">
            <div class="label">High Risks</div>
            <div class="number">{high_count}</div>
        </div>
        <div class="stat-card medium">
            <div class="label">Medium Risks</div>
            <div class="number">{medium_count}</div>
        </div>
    </div>

    <!-- Vulnerabilities Table -->
    <div class="table-container">
        <table>
            <thead>
                <tr>
                    <th>#</th>
                    <th>Target Account</th>
                    <th>Severity</th>
                    <th>Exploited By / Source</th>
                    <th>Privilege / Issue</th>
                    <th>MITRE ATT&CK Mapping</th>
                    <th>Description</th>
                </tr>
            </thead>
            <tbody>
                {table_rows if findings else '<tr><td colspan="7" style="text-align:center;">No Misconfigurations Detected</td></tr>'}
            </tbody>
        </table>
    </div>

</body>
</html>
"""

    with open(output_html_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    print(f"[+] Interactive Report successfully generated: {output_html_path}")

def analyze_ad_with_live_mitre(file_path):
    print("=" * 90)
    print("   Active Directory Misconfiguration Auditor - Dashboard Edition   ")
    print("=" * 90)
    
    mitre_live_database = fetch_live_mitre_data()
    print("-" * 90)

    RIGHTS_CONFIG = {
        "GenericAll": {"id": "T1098", "severity": "CRITICAL"},
        "WriteDacl": {"id": "T1098", "severity": "CRITICAL"},
        "WriteOwner": {"id": "T1098", "severity": "HIGH"},
        "GenericWrite": {"id": "T1098", "severity": "HIGH"},
        "AllExtendedRights": {"id": "T1098", "severity": "HIGH"},
        "Owns": {"id": "T1098", "severity": "HIGH"}
    }

    findings = []

    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            data = json.load(file)
            
        users_list = data.get("data", [])
        local_sid_map = build_json_sid_map(users_list)
        
        for user in users_list:
            user_properties = user.get("Properties", {})
            target_user_name = user_properties.get("name", "Unknown")
            sam_name = user_properties.get("samaccountname", "").lower()
            is_enabled = user_properties.get("enabled", True)
            aces = user.get("Aces", [])
            
            if not is_enabled:
                continue

            # -------------------------------------------------------------------------
            # 1. (Account Properties)
            # -------------------------------------------------------------------------
            if user_properties.get("dontreqpreauth") is True:
                tech_id = "T1558.004"
                tech_name, tech_desc = extract_mitre_details(mitre_live_database, tech_id)
                findings.append({
                    "Severity": "HIGH",
                    "Target": target_user_name,
                    "ExploitedBy": "Account Misconfiguration",
                    "Privilege": "AS-REP Roasting (dontreqpreauth Enabled)",
                    "MitreID": tech_id,
                    "TechName": tech_name,
                    "Description": tech_desc
                })

            if user_properties.get("passwordnotreqd") is True:
                tech_id = "T1078"
                tech_name, tech_desc = extract_mitre_details(mitre_live_database, tech_id)
                findings.append({
                    "Severity": "CRITICAL",
                    "Target": target_user_name,
                    "ExploitedBy": "Account Policy",
                    "Privilege": "Password Not Required (passwordnotreqd)",
                    "MitreID": tech_id,
                    "TechName": tech_name,
                    "Description": tech_desc
                })

            if user_properties.get("hasspn") is True and sam_name != "krbtgt" and not sam_name.endswith("$"):
                tech_id = "T1558.003"
                tech_name, tech_desc = extract_mitre_details(mitre_live_database, tech_id)
                severity_level = "CRITICAL" if user_properties.get("admincount") else "HIGH"
                findings.append({
                    "Severity": severity_level,
                    "Target": target_user_name,
                    "ExploitedBy": "Service Principal Name (SPN)",
                    "Privilege": "Kerberoasting Target (hasspn Enabled)",
                    "MitreID": tech_id,
                    "TechName": tech_name,
                    "Description": tech_desc
                })

            if user_properties.get("unconstraineddelegation") is True:
                tech_name, tech_desc = extract_mitre_details(mitre_live_database, "T1098")
                findings.append({
                    "Severity": "CRITICAL",
                    "Target": target_user_name,
                    "ExploitedBy": "Delegation Misconfiguration",
                    "Privilege": "Unconstrained Delegation Enabled",
                    "MitreID": "T1098",
                    "TechName": "Account Manipulation (Unconstrained Delegation)",
                    "Description": "Account is trusted for unconstrained delegation, allowing TGT theft."
                })

            # -------------------------------------------------------------------------
            # 2. ACLs (Aces) 
            # -------------------------------------------------------------------------
            for ace in aces:
                right_name = ace.get("RightName")
                principal_sid = ace.get("PrincipalSID", "")
                is_inherited = ace.get("IsInherited", False)
                
                if is_inherited:
                    continue
                
                if right_name in RIGHTS_CONFIG:
                    if (principal_sid.endswith("-512") or 
                        principal_sid.endswith("-519") or 
                        "S-1-5-32-544" in principal_sid or 
                        "S-1-5-32-548" in principal_sid):
                        continue
                    
                    mapped_name = resolve_sid_hybrid(principal_sid, local_sid_map)
                    
                    technique_id = RIGHTS_CONFIG[right_name]["id"]
                    severity = RIGHTS_CONFIG[right_name]["severity"]
                    tech_name, tech_desc = extract_mitre_details(mitre_live_database, technique_id)
                    
                    findings.append({
                        "Severity": severity,
                        "Target": target_user_name,
                        "ExploitedBy": mapped_name,
                        "Privilege": right_name,
                        "MitreID": technique_id,
                        "TechName": tech_name,
                        "Description": tech_desc
                    })
                    
        print(f"[+] Complete! Processed {len(findings)} high-value active vulnerabilities.")
        
        generate_interactive_dashboard(findings)
        
    except FileNotFoundError:
        print(f"[-] Error: File '{file_path}' not found.")
    except json.JSONDecodeError:
        print("[-] Error: Invalid JSON format.")

analyze_ad_with_live_mitre("users.json")
