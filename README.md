# Threat Hunt: _Emberforge Source Leak_

## Scenario

"We have a breach. EmberForge Studios, our game development subsidiary, has been compromised. Unreleased source code is on the dark web. Lead Artist Lisa Martin reported her workstation behaving strangely after opening _____ from her desktop."

"I have a board meeting in 4 hours. Before I care about how they got in, I need to know what they took and where it went. Legal needs the scope for breach notification. The _____ team has already been notified. Get in the logs. Now."

---

## Table of Contents

[Scenario](#scenario)  
[Table of Contents](#table-of-contents)  
[Platforms and Tools](#platforms-and-tools)   
[Starting Point](#starting-point)  
- [Flag 1: Target Directory – Source of Stolen Data](#flag-1-target-directory--source-of-stolen-data)
- [Flag 2: Exfil Destination – Cloud Storage Provider](#flag-2-exfil-destination--cloud-storage-provider)
- [Flag 3: Attacker Attribution – Authentication Email](#flag-3-attacker-attribution--authentication-email)
- [Flag 4: Domain Compromise Evidence – Credential Database Access](#flag-4-domain-compromise-evidence--credential-database-access)
- [Flag 5: Exfiltration Tool – Cloud Sync Abuse](#flag-5-exfiltration-tool--cloud-sync-abuse)
- [Flag 6: Exfiltration Destination IP – Network Correlation](#flag-6-exfiltration-destination-ip--network-correlation)
- [Flag 7: Attacker Credential Exposure – Plaintext Password](#flag-7-attacker-credential-exposure--plaintext-password)
- [Flag 8: Archive Method – Living Off The Land Compression](#flag-8-archive-method--living-off-the-land-compression)
- [Flag 9: Staging Server – Attacker Infrastructure](#flag-9-staging-server--attacker-infrastructure)
- [Flag 10: Malicious File – Initial Execution](#flag-10-malicious-file--initial-execution)
- [Flag 11: Delivery Vector – Mounted Disk Image](#flag-11-delivery-vector--mounted-disk-image)
- [Flag 12: Compromised User – Patient Zero](#flag-12-compromised-user--patient-zero)
- [Flag 13: Execution Chain – Process Lineage](#flag-13-execution-chain--process-lineage)
- [Flag 14: Delivery Unpacking – Archive Extraction](#flag-14-delivery-unpacking--archive-extraction)
- [Flag 15: Dropped Payload – Primary Attack Tool](#flag-15-dropped-payload--primary-attack-tool)
- [Flag 16: C2 Domain – Command and Control Infrastructure](#flag-16-c2-domain--command-and-control-infrastructure)
- [Flag 17: Primary C2 IP – Resolved Address](#flag-17-primary-c2-ip--resolved-address)
- [Flag 18: Injection Chain – Process Injection for Defense Evasion](#flag-18-injection-chain--process-injection-for-defense-evasion)
- [Flag 19: UAC Bypass Binary – Auto-Elevation Abuse](#flag-19-uac-bypass-binary--auto-elevation-abuse)
- [Flag 20: Registry Bypass Enabler – DelegateExecute Value](#flag-20-registry-bypass-enabler--delegateexecute-value)
- [Flag 21: Stable Injection Chain – Elevated Process Injection](#flag-21-stable-injection-chain--elevated-process-injection)
- [Flag 22: Credential Dumping Process – LSASS Memory Dump](#flag-22-credential-dumping-process--lsass-memory-dump)
- [Flag 23: Dump Location – LSASS Dump File Path](#flag-23-dump-location--lsass-dump-file-path)
- [Flag 24: User Enumeration – Domain Account Discovery](#flag-24-user-enumeration--domain-account-discovery)
- [Flag 25: Privilege Enumeration – Domain Admin Group Discovery](#flag-25-privilege-enumeration--domain-admin-group-discovery)
- [Flag 26: Infrastructure Mapping – Domain Controller Discovery](#flag-26-infrastructure-mapping--domain-controller-discovery)
- [Flag 27: Tool Staging Share – Network Share Creation](#flag-27-tool-staging-share--network-share-creation)
- [Flag 28: Firewall Manipulation – Inbound SMB Rule](#flag-28-firewall-manipulation--inbound-smb-rule)
- [Flag 29: Post-Escalation Parent – Injected System Process](#flag-29-post-escalation-parent--injected-system-process)
- [Flag 30: Beacon Distribution – Tool Transfer via Admin Share](#flag-30-beacon-distribution--tool-transfer-via-admin-share)
- [Flag 31: LOLBin Tool Staging – Certutil Download Cradle](#flag-31-lolbin-tool-staging--certutil-download-cradle)
- [Flag 32: Remote Execution Evidence – Temporary Service Creation](#flag-32-remote-execution-evidence--temporary-service-creation)
- [Flag 33: First Command on Server – Initial Beacon Check](#flag-33-first-command-on-server--initial-beacon-check)
- [Flag 34: Failed Lateral Movement – NTLM Authentication Failures](#flag-34-failed-lateral-movement--ntlm-authentication-failures)
- [Flag 35: DC Arrival and Credential Extraction – Domain Controller Compromise](#flag-35-dc-arrival-and-credential-extraction--domain-controller-compromise)
- [Flag 36: Backdoor Account – Persistence via Fake Service Account](#flag-36-backdoor-account--persistence-via-fake-service-account)
- [Flag 37: Backdoor Credentials – Plaintext Password Exposure](#flag-37-backdoor-credentials--plaintext-password-exposure)
- [Flag 38: Privilege Assignment – Domain Admin Group Addition](#flag-38-privilege-assignment--domain-admin-group-addition)
- [Flag 39: Exposed Credential – Network Drive Mapping Password](#flag-39-exposed-credential--network-drive-mapping-password)
- [Flag 40: Scheduled Task – Persistence via Fake Windows Update Task](#flag-40-scheduled-task--persistence-via-fake-windows-update-task)
- [Flag 41: Remote Access Tool – Silent AnyDesk Installation](#flag-41-remote-access-tool--silent-anydesk-installation)
- [Flag 42: Remote Access Configuration – AnyDesk Config File Path](#flag-42-remote-access-configuration--anydesk-config-file-path)
- [Flag 43: Anti-Forensics Tool – Event Log Clearing](#flag-43-anti-forensics-tool--event-log-clearing)
- [Flag 44: Cleared Logs – Event Log Targets](#flag-44-cleared-logs--event-log-targets)  
[Logical Flow & Analyst Reasoning](#logical-flow--analyst-reasoning)  
[MITRE ATT&CK Mapping](#mitre-attck-mapping)  
[Key Findings](#key-findings)  
[Recommendations for Remediation](#recommendations-for-remediation)  


---

## Platforms and Tools

**Analysis Environment:**

- Microsoft Sentinel (Log Analytics Workspace — law-cyber-range)
- Kusto Query Language (KQL)

**Log Sources Analysed:**

- Sysmon Operational logs
- Windows Security Event logs
- Custom log table — EmberForgeX_CL

---

## Starting Point

**Objective:**  
Confirm access to the investigation environment by identifying the custom log table containing all Sysmon and Windows Security telemetry for the EmberForge investigation.

**Flag Value:**  
`EmberForgeX_CL`

**What to Hunt:**  
Navigate to the Logs section in Microsoft Sentinel and look under Custom Logs in the left panel to identify the table containing the investigation data.

**Detection Strategy:**  
The custom log table `EmberForgeX_CL` was identified in the `law-cyber-range` workspace under Custom Logs. Access was confirmed by running a basic query against the table and verifying telemetry was present within the investigation window.

**Evidence:**  
<p align="center">
  <img width="274" height="425" alt="Untitled Diagram-Page-1 drawio" src="https://github.com/user-attachments/assets/0fbc6c42-2bde-4cd3-b145-6d39359af97c" />
</p>

**Why This Matters:**  
The `_CL` suffix denotes a Custom Log table ingested via API in Azure Monitor and Microsoft Sentinel. All Sysmon and Windows Security telemetry for the three EmberForge hosts is contained within this single table, making it the starting point for every query in this investigation.

---

 ### Flag 1: Target Directory – Source of Stolen Data

**Objective:**  
Identify the directory that was the source of stolen data by analyzing compression commands used by the attacker to package files before exfiltration.

**Flag Value:**  
`C:\GameDev`

**What to Hunt:**  
Look for compression tool usage in process creation events (EventCode 1), particularly `Compress-Archive`, `7z`, `WinRAR`, or similar utilities. The `-Path` argument reveals the source directory being targeted.

**Detection Strategy:**  
I filtered process creation events for known compression tools and sorted chronologically to identify what data was being packaged. A PowerShell `Compress-Archive` command revealed the attacker archiving the entire `C:\GameDev` directory into a zip file staged at `C:\Users\Public\gamedev.zip`.

**KQL Query:**  
```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "1"
| where CommandLine_s has_any ("Compress-Archive", "7z", "zip", "rar", "tar")
| project UtcTime_s, Computer, User_s, Image_s, CommandLine_s, ParentImage_s
| sort by UtcTime_s asc
```

**Evidence:**  
<p align="center">
  <img width="892" height="283" alt="Q01" src="https://github.com/user-attachments/assets/eb0b5b30-a73b-4fad-ad4e-51d25f1cd9af" />
</p>

**Why This Matters:**  
The `Compress-Archive` command with `-Path C:\GameDev` confirms the attacker specifically targeted the game development directory — likely containing source code, assets, and proprietary project files. The archive was immediately staged at `C:\Users\Public\gamedev.zip` for exfiltration, indicating a deliberate and pre-planned data theft operation.

---

### Flag 2: Exfil Destination – Cloud Storage Provider

**Objective:**  
Identify the cloud storage provider used by the attacker to exfiltrate the stolen data.

**Flag Value:**  
`MEGA`

**What to Hunt:**  
Look for exfiltration tools in process creation events (EventCode 1), particularly `rclone.exe`, which is commonly abused by attackers to upload data to cloud storage providers. The command line arguments reveal both the destination service and configuration details.

**Detection Strategy:**  
The same query from Flag 1 surfaced `rclone.exe` being executed immediately after the compression step. The command line argument `mega:exfil` reveals MEGA as the destination cloud provider, with authentication handled via a pre-staged config file at `C:\Users\Public\rclone.conf`.

**KQL Query:**  
```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "1"
| where CommandLine_s has_any ("Compress-Archive", "7z", "zip", "rar", "tar")
| project UtcTime_s, Computer, User_s, Image_s, CommandLine_s, ParentImage_s
| sort by UtcTime_s asc
```

**Evidence:**  
<p align="center">
  <img width="761" height="282" alt="Q02" src="https://github.com/user-attachments/assets/d1e19236-8eff-479f-9c06-35832c2936fd" />
</p>

**Why This Matters:**  
`rclone.exe` is a legitimate cloud sync tool increasingly abused by threat actors for exfiltration because it blends in with normal cloud traffic. The `mega:exfil` argument confirms MEGA cloud storage as the destination, and the pre-staged config file at `C:\Users\Public\rclone.conf` suggests the attacker planned this exfiltration in advance. 

---

### Flag 3: Attacker Attribution – Authentication Email

**Objective:**  
Identify the email account used to authenticate to the cloud storage service by examining credentials exposed in the rclone command line.

**Flag Value:**  
`jwilson.vhr@proton.me`

**What to Hunt:**  
Look for rclone executions where credentials are passed directly as command line arguments using `--mega-user` and `--mega-pass` flags rather than via a config file.

**Detection Strategy:**  
I searched raw event data for rclone executions referencing MEGA. One command line invocation exposed credentials directly as arguments, revealing both the email address and password used to authenticate to MEGA — a classic OPSEC mistake by the attacker.

**KQL Query:**  
```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where Raw_s contains "rclone"
| where Raw_s contains "mega"
| project UtcTime_s, Computer, CommandLine_s, Raw_s
| sort by UtcTime_s asc
```

**Evidence:**  
<p align="center">
  <img width="1104" height="323" alt="Q3" src="https://github.com/user-attachments/assets/2baa5478-b54c-498e-86a8-9e267cd1b0d5" />
</p>

**Why This Matters:**  
Passing credentials directly in command line arguments is a significant OPSEC failure. Sysmon EventCode 1 captures full command lines, meaning the attacker's MEGA account `jwilson.vhr@proton.me` and password were logged in plaintext. This provides direct attribution evidence and an immediate IOC for law enforcement or further investigation.

---

### Flag 4: Domain Compromise Evidence – Credential Database Access

**Objective:**  
Identify the file accessed by the attacker on the Domain Controller using volume shadow copy techniques to extract domain credentials.

**Flag Value:**  
`ntds.dit`

**What to Hunt:**  
Look for volume shadow copy activity (vssadmin, diskshadow) on the Domain Controller combined with references to the Active Directory credential database.

**Detection Strategy:**  
I searched process creation events on the Domain Controller for volume shadow copy commands. The attacker used VSS techniques to create a shadow copy of the C: drive, allowing them to access the locked ntds.dit file which stores all domain account credentials.

**KQL Query:**  
```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where Raw_s has_any ("ntds", "vssadmin", "shadow", "diskshadow")
| project UtcTime_s, Computer, EventCode_s, CommandLine_s, Raw_s
| sort by UtcTime_s asc
```

**Evidence:**  
<p align="center">
  <img width="994" height="170" alt="Q4" src="https://github.com/user-attachments/assets/ffb66b54-6047-4400-8930-b1bb581286ce" />
</p>

**Why This Matters:**  
The ntds.dit file contains the hashed credentials of every account in the Active Directory domain. Accessing it via volume shadow copy is a well-documented technique that bypasses the OS lock on the file. A successful extraction means the attacker potentially has access to every domain account, making this a full domain compromise.

---

### Flag 5: Exfiltration Tool – Cloud Sync Abuse

**Objective:**  
Identify the legitimate cloud synchronisation tool abused by the attacker to exfiltrate data externally.

**Flag Value:**  
`rclone.exe`

**What to Hunt:**  
Look for cloud sync tools executing on any host within the investigation window, particularly those running from unusual locations like `C:\Users\Public` rather than standard installation directories.

**Detection Strategy:**  
I searched process creation events across all hosts for known cloud sync tools. `rclone.exe` was found executing multiple times on `EC2AMAZ-16V3AU4` from `C:\Users\Public\rclone.exe`, a non-standard path indicating it was dropped by the attacker rather than legitimately installed. It was executed with different argument combinations, suggesting some attempts failed before a successful exfiltration method was established.

**KQL Query:**  
```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "1"
| where CommandLine_s contains "rclone"
| project UtcTime_s, Computer, User_s, Image_s, CommandLine_s, ParentImage_s
| sort by UtcTime_s asc
```

**Evidence:**  
<p align="center">
  <img width="770" height="165" alt="Q5" src="https://github.com/user-attachments/assets/6e0b120b-4af9-4a4e-be07-cce16d3cf91c" />
</p>

**Why This Matters:**  
`rclone.exe` is a legitimate open source cloud sync tool increasingly abused by threat actors for exfiltration because it supports dozens of cloud providers and blends in with normal network traffic. Its execution from `C:\Users\Public` under `NT AUTHORITY\SYSTEM` with a parent process of `update.exe` confirms it was attacker-deployed rather than legitimately installed.

---

### Flag 6: Exfiltration Destination IP – Network Correlation

**Objective:**  
Identify the IP address that received the stolen data by correlating rclone's process activity with outbound network connections.

**Flag Value:**  
`66.203.125.15`

**What to Hunt:**  
Correlate EventCode 3 (network connections) with the rclone process on the server host to identify the destination IP address used during the upload.

**Detection Strategy:**  
I filtered network connection events on `EC2AMAZ-16V3AU4` for connections initiated by `rclone.exe`. The connection was made over port 443 to `bt5.api.mega.co.nz`, resolving to `66.203.125.15`, confirming the destination of the exfiltrated data was MEGA's API infrastructure.

**KQL Query:**  
```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "3"
| where Image_s contains "rclone"
| project UtcTime_s, Computer, Image_s, DestinationIp_s, DestinationPort_s, DestinationHostname_s
| sort by UtcTime_s asc
```

**Evidence:**  
<p align="center">
  <img width="783" height="61" alt="Q6" src="https://github.com/user-attachments/assets/305a428f-bb1c-4bc3-b377-3d6672d8e48c" />
</p>

**Why This Matters:**  
Correlating process activity with network connections confirms the exfiltration path end-to-end. The use of port 443 over HTTPS to MEGA's API infrastructure means the traffic would blend in with normal encrypted web traffic, making it difficult to detect without process-level telemetry like Sysmon EventCode 3.

---

### Flag 7: Attacker Credential Exposure – Plaintext Password

**Objective:**  
Identify the plaintext password exposed in the rclone command line during one of the attacker's authentication troubleshooting attempts.

**Flag Value:**  
`Summer2024!`

**What to Hunt:**  
Compare all rclone executions and look for instances where credentials were passed directly as command line arguments rather than via a config file.

**Detection Strategy:**  
I compared all rclone executions across the investigation window. Most executions used `--config C:\Users\Public\rclone.conf` to handle authentication. However one execution at `23:08:28` passed credentials directly via `--mega-user` and `--mega-pass` flags, exposing both the email address and plaintext password in the Sysmon process creation log.

**KQL Query:**  
```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "1"
| where CommandLine_s contains "rclone"
| project UtcTime_s, Computer, User_s, CommandLine_s
| sort by UtcTime_s asc
```

**Evidence:**  
<p align="center">
  <img width="928" height="145" alt="Q7" src="https://github.com/user-attachments/assets/b1112e22-3176-49d0-92b7-98befe64157a" />
</p>

**Why This Matters:**  
Passing credentials directly in command line arguments is a significant OPSEC failure. Windows logs full command lines via Sysmon EventCode 1, meaning any credential passed as an argument is captured in plaintext. This exposed password combined with the email from Flag 3 provides direct attribution evidence and actionable IOCs for further investigation.

---

### Flag 8: Archive Method – Living Off The Land Compression

**Objective:**  
Identify the built-in PowerShell cmdlet used by the attacker to compress stolen data before exfiltration.

**Flag Value:**  
`Compress-Archive`

**What to Hunt:**  
Look for PowerShell process creation events using built-in compression cmdlets rather than third-party tools like 7-Zip or WinRAR.

**Detection Strategy:**  
I filtered process creation events for compression activity across all hosts. Rather than using a third-party tool, the attacker used the built-in PowerShell `Compress-Archive` cmdlet to package `C:\GameDev` into `gamedev.zip`, staging it at `C:\Users\Public` prior to exfiltration. This is a Living Off The Land technique as it uses native OS functionality to avoid detection.

**KQL Query:**  
```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "1"
| where CommandLine_s contains "Compress-Archive"
| project UtcTime_s, Computer, User_s, CommandLine_s, ParentImage_s
| sort by UtcTime_s asc
```

**Evidence:**  
<p align="center">
  <img width="744" height="178" alt="Q8" src="https://github.com/user-attachments/assets/2e1d1d28-6f3e-4d11-92ac-f034a25f42b8" />
</p>

**Why This Matters:**  
Living Off The Land techniques abuse built-in OS tools to avoid triggering alerts based on known malicious binaries. `Compress-Archive` is a native PowerShell cmdlet meaning no additional tools need to be downloaded, reducing the attacker's footprint. Detection requires behavioural analysis of what is being compressed and from where, rather than signature-based detection.

---

### Flag 9: Staging Server – Attacker Infrastructure

**Objective:**  
Identify the external staging server used by the attacker to download tools and utilities onto compromised hosts.

**Flag Value:**  
`sync.cloud-endpoint.net`

**What to Hunt:**  
Look for download commands across all hosts referencing the same external domain, particularly certutil or PowerShell download cradles pulling executables from attacker-controlled infrastructure.

**Detection Strategy:**  
I searched process creation events across all hosts for download activity. Multiple commands across the environment referenced the same staging server `sync.cloud-endpoint.net` on port 8080, used to deliver tools including `update.exe` and `AnyDesk.exe` via certutil and PowerShell download cradles.

**KQL Query:**  
```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "1"
| where CommandLine_s contains "cloud-endpoint"
| project UtcTime_s, Computer, User_s, CommandLine_s
| sort by UtcTime_s asc
```

**Evidence:**  
<p align="center">
  <img width="967" height="155" alt="Q9" src="https://github.com/user-attachments/assets/54adca53-577f-412c-b2dc-3d1a91cf9c95" />
</p>

**Why This Matters:**  
Identifying attacker-controlled infrastructure is critical for containment and attribution. The domain `sync.cloud-endpoint.net` was used consistently across multiple hosts to deliver tooling, confirming it as the attacker's primary staging server. This domain should be immediately blocked at the perimeter and submitted as an IOC for threat intelligence sharing.

---

### Flag 10: Malicious File – Initial Execution

**Objective:**  
Identify the first malicious file executed on the workstation by tracing the process chain back to Lisa's initial interaction.

**Flag Value:**  
`review.dll`

**What to Hunt:**  
Look for Windows utilities loading files from unusual locations on the workstation, particularly from removable media or non-standard paths launched by explorer.exe indicating user interaction.

**Detection Strategy:**  
I filtered process creation events on the workstation `EC2AMAZ-B9GHHO6` for Lisa's account, focusing on Windows utilities commonly abused to load malicious files. At `21:27:03`, `rundll32.exe` was used to load `review.dll` from a D: drive with the export `StartW`, with `explorer.exe` as the parent process confirming Lisa opened it directly.

**KQL Query:**  
```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "1"
| where Computer contains "B9GHHO6"
| where Image_s has_any ("mshta.exe", "wscript.exe", "rundll32.exe", "regsvr32.exe", "cscript.exe")
| project UtcTime_s, User_s, Image_s, CommandLine_s, ParentImage_s, ParentCommandLine_s
| sort by UtcTime_s asc
```

**Evidence:**  
<p align="center">
  <img width="548" height="204" alt="Q10" src="https://github.com/user-attachments/assets/35de7ef0-577f-4175-a081-4800a756cfa8" />
</p>

**Why This Matters:**  
Loading a DLL via `rundll32.exe` is a classic Living Off The Land technique that abuses a legitimate Windows binary to execute malicious code. The D: drive path suggests the file arrived via removable media or a mounted drive. The `StartW` export is a common entry point used by malicious DLLs, and the `explorer.exe` parent confirms this was a user-initiated action — Lisa was likely socially engineered into opening the file.

---

### Flag 11: Delivery Vector – Mounted Disk Image

**Objective:**  
Identify how the malicious file was delivered to the workstation by examining the drive letter of the malicious file path.

**Flag Value:**  
`D:`

**What to Hunt:**  
Look at the full path of the malicious file identified in Flag 10. A non-C: drive letter indicates the file arrived via a mounted disk image such as an ISO, IMG, or VHD file.

**Detection Strategy:**  
The malicious `review.dll` was loaded from `D:\review.dll` rather than from the C: drive. A D: drive appearing in a user session without a physical disk being present indicates a mounted disk image. ISO files in particular bypass Windows Mark of the Web protections, meaning the DLL would not carry a zone identifier warning users it came from the internet.

**KQL Query:**  
```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "1"
| where Computer contains "B9GHHO6"
| where CommandLine_s contains "review.dll"
| project UtcTime_s, User_s, Image_s, CommandLine_s, ParentImage_s
| sort by UtcTime_s asc
```

**Evidence:**  
<p align="center">
  <img width="560" height="172" alt="Q11" src="https://github.com/user-attachments/assets/9d90d49e-27bd-4de7-b108-629d947a9c2a" />
</p>

**Why This Matters:**  
Delivering malware inside ISO or IMG files is a well established technique for bypassing Mark of the Web security warnings. When a user downloads and mounts a disk image, files inside it do not inherit the zone identifier that would trigger SmartScreen warnings. This suggests Lisa was likely sent a phishing email with an ISO attachment or download link, and was socially engineered into mounting and executing its contents.

---

### Flag 12: Compromised User – Patient Zero

**Objective:**  
Identify the user account that executed the malicious payload, establishing patient zero for the incident.

**Flag Value:**  
`lmartin`

**What to Hunt:**  
Check the User field in the process creation event for the malicious `rundll32.exe` execution identified in Flag 10.

**Detection Strategy:**  
I examined the User field of the earliest malicious process creation event on the workstation. The `rundll32.exe` execution loading `review.dll` was performed under the account `EMBERFORGE\lmartin`, confirming Lisa Martin as patient zero and the entry point for the entire compromise.

**KQL Query:**  
```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "1"
| where Computer contains "B9GHHO6"
| where CommandLine_s contains "review.dll"
| project UtcTime_s, User_s, Image_s, CommandLine_s, ParentImage_s
| sort by UtcTime_s asc
```

**Evidence:**  
<p align="center">
  <img width="951" height="64" alt="Q12" src="https://github.com/user-attachments/assets/fe2e2972-b6a8-44c8-a184-1fa7ae80630b" />
</p>

**Why This Matters:**  
Identifying patient zero is critical for scoping the breach and understanding whether the attack was targeted or opportunistic. Lisa Martin's account was the entry point for the entire compromise, with the attacker subsequently pivoting from her workstation to the server and Domain Controller. The CISO's question about whether Lisa was specifically targeted can now be investigated further by examining the delivery mechanism and any prior reconnaissance activity.

---

### Flag 13: Execution Chain – Process Lineage

**Objective:**  
Trace the full execution chain from Lisa's user action through to the malicious file being loaded.

**Flag Value:**  
`explorer.exe > rundll32.exe > review.dll`

**What to Hunt:**  
Examine the parent process fields in the malicious process creation event to reconstruct the full execution chain from user interaction to payload execution.

**Detection Strategy:**  
I examined the Image, ParentImage, and CommandLine fields of the malicious execution event at `21:27:03`. The chain shows `explorer.exe` as the parent of `rundll32.exe`, confirming Lisa directly interacted with the file through Windows Explorer. `rundll32.exe` then loaded `review.dll` via the `StartW` export, completing the execution chain.

**KQL Query:**  
```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "1"
| where Computer contains "B9GHHO6"
| where CommandLine_s contains "review.dll"
| project UtcTime_s, User_s, Image_s, CommandLine_s, ParentImage_s, ParentCommandLine_s
| sort by UtcTime_s asc
```

**Evidence:**  
<p align="center">
  <img width="570" height="202" alt="Q13" src="https://github.com/user-attachments/assets/ed784a3f-fd85-4daa-99b7-4f5efa5a0e88" />
</p>

**Why This Matters:**  
The execution chain confirms this was a user-initiated action rather than an automated or remote execution. Lisa directly opened the malicious file through Windows Explorer, triggering `rundll32.exe` to load `review.dll`. This chain is consistent with a phishing or social engineering attack where the victim is manipulated into opening a malicious file delivered inside a mounted disk image.

---

### Flag 14: Delivery Unpacking – Archive Extraction

**Objective:**  
Identify the compression tool and extraction path used to unpack the malicious archive before the DLL was executed.

**Flag Value:**  
`7zG.exe > C:\Users\lmartin.EMBERFORGE\Downloads\EmberForge_Review\`

**What to Hunt:**  
Look for archive extraction activity on the workstation under Lisa's account prior to the malicious DLL execution, focusing on the output path used during extraction.

**Detection Strategy:**  
I searched process creation events on the workstation for compression tool activity under Lisa's account prior to the `rundll32.exe` execution at `21:27:03`. At `21:24:04`, `7zG.exe` was used to extract an archive to `C:\Users\lmartin.EMBERFORGE\Downloads\EmberForge_Review\`, with `explorer.exe` as the parent confirming Lisa initiated the extraction manually.

**KQL Query:**  
```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "1"
| where Computer contains "B9GHHO6"
| where User_s contains "lmartin"
| where Image_s contains "7z"
| project UtcTime_s, User_s, Image_s, CommandLine_s, ParentImage_s
| sort by UtcTime_s asc
```

**Evidence:**  
<p align="center">
  <img width="981" height="190" alt="Q14" src="https://github.com/user-attachments/assets/3d4794c4-8d28-4f8a-98ba-4b9b33b6537c" />
</p>

**Why This Matters:**  
The extraction step reveals the full delivery chain. The malicious DLL was packaged inside an archive named to appear legitimate, likely themed around an EmberForge review or project. Lisa extracted the archive to her Downloads folder using 7-Zip, then opened the contents which triggered `rundll32.exe` to load `review.dll`. This is consistent with a spear phishing attack using a weaponised archive delivered to a targeted employee.

---

### Flag 15: Dropped Payload – Primary Attack Tool

**Objective:**  
Identify the executable dropped by the malicious DLL shortly after initial execution, which became the attacker's primary tool for the rest of the operation.

**Flag Value:**  
`C:\Users\Public\update.exe`

**What to Hunt:**  
Look for file creation events in world-writable directories on the workstation shortly after the initial DLL execution, particularly executables dropped by rundll32.exe.

**Detection Strategy:**  
I searched file creation events on the workstation for executables appearing in world-writable directories after the initial DLL execution at `21:27:03`. At `21:36:34`, `rundll32.exe` dropped `update.exe` into `C:\Users\Public`, a world-writable directory commonly abused by attackers. This binary subsequently appeared as the parent process for all further malicious activity across all three hosts.

**KQL Query:**  
```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "11"
| where Computer contains "B9GHHO6"
| where TargetFilename_s has_any ("Public", "Temp", "ProgramData", "AppData")
| where TargetFilename_s endswith ".exe"
| project UtcTime_s, Computer, Image_s, TargetFilename_s
| sort by UtcTime_s asc
```

**Evidence:**  
<p align="center">
  <img width="753" height="131" alt="Q15" src="https://github.com/user-attachments/assets/328a387d-cf8f-41ad-9a00-2bbe0b521d6e" />
</p>

**Why This Matters:**  
`C:\Users\Public` is a world-writable directory meaning any process regardless of privilege level can write files there. Dropping a payload named `update.exe` is a masquerading technique designed to blend in with legitimate software update processes. This binary became the attacker's persistent foothold on the workstation and the parent process for all subsequent tool deployment, lateral movement, and exfiltration activity across the entire environment.

---

### Flag 16: C2 Domain – Command and Control Infrastructure

**Objective:**  
Identify the command and control domain the malware used to communicate with the attacker.

**Flag Value:**  
`cdn.cloud-endpoint.net`

**What to Hunt:**  
Search DNS query events (EventCode 22) on the workstation for queries made by the malicious `update.exe` process, focusing on domains designed to blend in with legitimate cloud traffic.

**Detection Strategy:**  
I filtered DNS query events on the workstation for queries made by `update.exe`. The process repeatedly queried `cdn.cloud-endpoint.net` beginning at `21:40:24`, approximately 13 minutes after the initial payload was dropped. The subdomain `cdn` is designed to mimic legitimate content delivery network traffic, making it blend in with normal cloud communications.

**KQL Query:**  
```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "22"
| where Computer contains "B9GHHO6"
| where Image_s contains "update.exe"
| project UtcTime_s, Computer, Image_s, QueryName_s
| sort by UtcTime_s asc
```

**Evidence:**  
<p align="center">
  <img width="809" height="204" alt="Q16" src="https://github.com/user-attachments/assets/970ccc14-da48-4b33-9a34-65b80e391681" />
</p>

**Why This Matters:**  
The C2 domain `cdn.cloud-endpoint.net` shares the same base domain as the staging server `sync.cloud-endpoint.net` identified in Flag 9, confirming they are part of the same attacker-controlled infrastructure. The `cdn` subdomain is deliberately chosen to blend in with legitimate content delivery network traffic. The malware also queried the Domain Controller `EC2AMAZ-EEU3IA2` indicating early internal reconnaissance was occurring simultaneously with C2 beaconing.

---

### Flag 17: Primary C2 IP – Resolved Address

**Objective:**  
Identify the IP address that `cdn.cloud-endpoint.net` resolved to during the malware's C2 communications.

**Flag Value:**  
`104.21.30.237`

**What to Hunt:**  
Parse the QueryResults field from EventCode 22 raw XML for DNS queries to `cdn.cloud-endpoint.net` to extract the resolved IP addresses.

**Detection Strategy:**  
I parsed the Raw_s field of DNS query events for `cdn.cloud-endpoint.net` on the workstation. The domain consistently resolved to two IPs — `104.21.30.237` and `172.67.174.46` — across multiple processes including `rundll32.exe`, `update.exe` and `spoolsv.exe`, indicating the C2 infrastructure is hosted behind Cloudflare.

**KQL Query:**  
```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "22"
| where Computer contains "B9GHHO6"
| where Raw_s contains "cdn.cloud-endpoint.net"
| parse Raw_s with * "QueryResults'>" QueryResults "<" *
| extend CleanIP = extract(@"::ffff:(\d+\.\d+\.\d+\.\d+)", 1, QueryResults)
| project UtcTime_s, Computer, QueryName_s, CleanIP
| sort by UtcTime_s asc
```

**Evidence:**  
<p align="center">
  <img width="678" height="144" alt="Q17" src="https://github.com/user-attachments/assets/34aaa12e-b010-453c-b4ac-061f4afdf644" />
</p>

**Why This Matters:**  
The two resolved IPs belong to Cloudflare's infrastructure, indicating the attacker is hiding their true origin behind Cloudflare's reverse proxy. This is a common technique to obscure attacker infrastructure and make takedown requests more difficult. Both IPs should be blocked at the perimeter and the domain submitted as an IOC immediately.

---

### Flag 18: Injection Chain – Process Injection for Defense Evasion

**Objective:**  
Identify the process injection chain used by the attacker to hide malicious activity inside a legitimate Windows process.

**Flag Value:**  
`rundll32.exe > notepad.exe`

**What to Hunt:**  
Search for CreateRemoteThread events (EventCode 8) on the workstation to identify processes injecting code into other processes.

**Detection Strategy:**  
I searched EventCode 8 on the workstation for CreateRemoteThread activity. Two injection chains were identified — `rundll32.exe` injecting into `notepad.exe` during initial execution, and `update.exe` injecting into `spoolsv.exe` to establish a persistent foothold inside a legitimate Windows print spooler process, making the malicious activity harder to detect.

**KQL Query:**  
```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "8"
| where Computer contains "B9GHHO6"
| parse Raw_s with * "SourceImage'>" SourceImage "<" *
| parse Raw_s with * "TargetImage'>" TargetImage "<" *
| project UtcTime_s, Computer, SourceImage, TargetImage
| sort by UtcTime_s asc
```

**Evidence:**  
<p align="center">
  <img width="855" height="232" alt="Q18 corrected" src="https://github.com/user-attachments/assets/448a179f-3fd9-4efa-976b-dfbc3195c954" />
</p>

**Why This Matters:**  
Process injection via CreateRemoteThread allows the attacker to execute malicious code inside a legitimate Windows process, hiding it from casual inspection. Injecting into `spoolsv.exe` is particularly effective as it is a trusted system process that runs under SYSTEM privileges and maintains persistent network connections, providing both privilege escalation and a persistent C2 channel that blends in with normal system activity.

---

### Flag 19: UAC Bypass Binary – Auto-Elevation Abuse

**Objective:**  
Identify the trusted Windows binary abused by the attacker to bypass UAC and gain elevated privileges without triggering a UAC prompt.

**Flag Value:**  
`fodhelper.exe`

**What to Hunt:**  
Look for registry modifications to the `ms-settings\shell\open\command` key, which is read by `fodhelper.exe` when it auto-elevates. Setting this key to a malicious executable causes it to run with elevated privileges when fodhelper launches.

**Detection Strategy:**  
I searched EventCode 13 registry modification events on the workstation. At `21:38:33`, `reg.exe` modified `ms-settings\shell\open\command` to point to `C:\Users\Public\update.exe`, followed immediately by setting `DelegateExecute` to empty — the exact two-step pattern required for the fodhelper UAC bypass technique.

**KQL Query:**  
```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:38:50) .. datetime(2026-01-30 21:40:00))
| where EventCode_s == "1"
| where Computer contains "B9GHHO6"
| project UtcTime_s, Computer, User_s, Image_s, CommandLine_s, ParentImage_s
| sort by UtcTime_s asc
```

**Evidence:**  
<p align="center">
  <img width="871" height="170" alt="Q19" src="https://github.com/user-attachments/assets/58e6f6d3-a7fb-4c6f-ac41-8406c298ba99" />
</p>

**Why This Matters:**  
The fodhelper UAC bypass is a well documented technique that abuses the auto-elevation behaviour of `fodhelper.exe` to execute arbitrary code with high integrity without triggering a UAC prompt. By pointing the `ms-settings` shell command to `update.exe`, the attacker gained elevated privileges silently. This explains how the attacker was subsequently able to perform SYSTEM-level operations across the environment without the user being prompted to approve elevation.

---

### Flag 20: Registry Bypass Enabler – DelegateExecute Value

**Objective:**  
Identify the specific registry value name that enables the UAC bypass hijack.

**Flag Value:**  
`DelegateExecute`

**What to Hunt:**  
Look for the second registry modification made in quick succession alongside the payload path setting, specifically targeting the `ms-settings\shell\open\command` key.

**Detection Strategy:**  
I examined the two registry modifications made at `21:38:33` and `21:38:50`. The first set the payload path to `C:\Users\Public\update.exe`. The second created the `DelegateExecute` value set to empty, which is the specific trigger that causes `fodhelper.exe` to look up and execute the `ms-settings` shell command with elevated privileges.

**KQL Query:**  
```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "13"
| where Computer contains "B9GHHO6"
| where TargetObject_s contains "ms-settings"
| project UtcTime_s, Computer, Image_s, TargetObject_s, Details_s
| sort by UtcTime_s asc
```

**Evidence:**  
<p align="center">
  <img width="856" height="170" alt="Q20" src="https://github.com/user-attachments/assets/d246a810-a905-4e6a-946f-13d04fbd3ca0" />
</p>

**Why This Matters:**  
The `DelegateExecute` value is the key trigger for the fodhelper UAC bypass. When this value exists under `ms-settings\shell\open\command`, Windows redirects execution through the COM elevation mechanism, causing the associated command to run at high integrity without a UAC prompt. Its presence alongside a malicious payload path is a high-fidelity indicator of this specific bypass technique.

---

### Flag 21: Stable Injection Chain – Elevated Process Injection

**Objective:**  
Identify the second injection chain used by the attacker after the UAC bypass to establish long-term stability in a SYSTEM-level process.

**Flag Value:**  
`update.exe > spoolsv.exe (NT AUTHORITY\SYSTEM)`

**What to Hunt:**  
Search for CreateRemoteThread events after the UAC bypass, focusing on injections targeting processes running under NT AUTHORITY\SYSTEM to identify privilege escalation via injection.

**Detection Strategy:**  
I searched EventCode 8 after the UAC bypass at `21:38:50`. At `21:56:44`, `update.exe` injected into `spoolsv.exe` running under `NT AUTHORITY\SYSTEM`, a higher privileged security context than the original user session. This gave the attacker a stable SYSTEM-level foothold inside a trusted Windows process that persists across user sessions.

**KQL Query:**  
```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:38:50) .. datetime(2026-01-31 00:00))
| where EventCode_s == "8"
| where Computer contains "B9GHHO6"
| parse Raw_s with * "SourceImage'>" SourceImage "<" *
| parse Raw_s with * "TargetImage'>" TargetImage "<" *
| parse Raw_s with * "TargetUser'>" TargetUser "<" *
| project UtcTime_s, Computer, SourceImage, TargetImage, TargetUser
| sort by UtcTime_s asc
```

**Evidence:**  
<p align="center">
  <img width="936" height="176" alt="Q21" src="https://github.com/user-attachments/assets/d6d9b538-0283-4465-8843-40c0d6febcd0" />
</p>

**Why This Matters:**  
Injecting into `spoolsv.exe` running as `NT AUTHORITY\SYSTEM` gave the attacker the highest available privilege level on the workstation. This SYSTEM context was then used to perform all subsequent operations including lateral movement, tool deployment and credential access. The injection also provides stability as `spoolsv.exe` runs continuously as a Windows service, surviving user logoffs and persisting until the system is rebooted or the process is killed.

---

### Flag 22: Credential Dumping Process – LSASS Memory Dump

**Objective:**  
Identify the process that dumped LSASS memory to disk to extract credentials from every logged-in user session.

**Flag Value:**  
`update.exe`

**What to Hunt:**  
Search for file creation events targeting LSASS dump files, since the dumping tool used direct syscalls bypassing API monitoring meaning EventCode 10 ProcessAccess events will not be present.

**Detection Strategy:**  
I searched EventCode 11 file creation events on the workstation for dump files. At `21:48:13`, `update.exe` created `C:\Windows\System32\lsass.dmp`, confirming it as the process responsible for dumping LSASS memory. The use of direct syscalls to bypass API monitoring means traditional LSASS access detection would have missed this, making file creation monitoring the only detection opportunity.

**KQL Query:**  
```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "11"
| where Computer contains "B9GHHO6"
| where TargetFilename_s has_any (".dmp", "lsass", "dump")
| project UtcTime_s, Computer, Image_s, TargetFilename_s
| sort by UtcTime_s asc
```

**Evidence:**  
<p align="center">
  <img width="776" height="93" alt="Q22" src="https://github.com/user-attachments/assets/4ac164e3-c28b-4c65-9ae3-af75f00ba0bd" />
</p>

**Why This Matters:**  
LSASS holds credentials for every currently logged-in user including plaintext passwords, NTLM hashes and Kerberos tickets. Dumping it to disk allows offline credential extraction using tools like Mimikatz. The use of direct syscalls to bypass API monitoring represents a sophisticated evasion technique that defeats many EDR solutions, making Sysmon file creation monitoring a critical detection control for this technique.

---

### Flag 23: Dump Location – LSASS Dump File Path

**Objective:**  
Identify the full path where the LSASS memory dump was written to disk.

**Flag Value:**  
`C:\Windows\System32\lsass.dmp`

**What to Hunt:**  
Check the TargetFilename field in the file creation events identified in Flag 22 to find the exact path where the dump file was written.

**Detection Strategy:**  
I examined the TargetFilename field of the file creation events from Flag 22. The dump was written to `C:\Windows\System32\lsass.dmp` — a location that attempts to blend in with legitimate system files by placing the dump directly inside the System32 directory rather than a more obvious location like the Desktop or Downloads folder.

**KQL Query:**  
```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "11"
| where Computer contains "B9GHHO6"
| where TargetFilename_s has_any (".dmp", "lsass", "dump")
| project UtcTime_s, Computer, Image_s, TargetFilename_s
| sort by UtcTime_s asc
```

**Evidence:**  
<p align="center">
  <img width="807" height="207" alt="Q23" src="https://github.com/user-attachments/assets/b8a4841b-b131-49de-832a-9e5bafc73f0d" />
</p>

**Why This Matters:**  
Writing the dump file to `C:\Windows\System32` is a deliberate evasion technique designed to hide it among thousands of legitimate system files. Monitoring for dump file creation in system directories is a high-fidelity detection opportunity that should be implemented as an alert rule in any mature SOC environment.

---

### Flag 24: User Enumeration – Domain Account Discovery

**Objective:**  
Identify the first command used by the attacker to enumerate all user accounts in the domain.

**Flag Value:**  
`net user /domain`

**What to Hunt:**  
Search for domain enumeration commands on the workstation, particularly net commands querying domain user accounts.

**Detection Strategy:**  
I filtered process creation events on the workstation for domain enumeration commands. At `21:34:32`, `rundll32.exe` executed `net user /domain` under Lisa's account, querying all user accounts in the emberforge.local domain. This was the first command in the attacker's discovery sequence, occurring just 7 minutes after the initial DLL execution.

**KQL Query:**  
```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "1"
| where Computer contains "B9GHHO6"
| where CommandLine_s has_any ("net user", "net group", "whoami", "nltest", "dsquery", "Get-AD")
| project UtcTime_s, Computer, User_s, CommandLine_s, ParentImage_s
| sort by UtcTime_s asc
```

**Evidence:**  
<p align="center">
  <img width="992" height="59" alt="Q24" src="https://github.com/user-attachments/assets/8121a13a-6a32-485a-aa0b-664f3f8defde" />
</p>

**Why This Matters:**  
`net user /domain` is one of the most commonly used domain enumeration commands, returning a full list of all domain user accounts. Executed within minutes of initial infection this confirms the attacker immediately began mapping the environment. Combined with subsequent enumeration commands this tells the CISO that the attacker had full visibility of the domain user base, meaning every account should be treated as potentially targeted.

---

### Flag 25: Privilege Enumeration – Domain Admin Group Discovery

**Objective:**  
Identify the command used by the attacker to enumerate members of the highest privilege group in the domain.

**Flag Value:**  
`net group "Domain Admins" /domain`

**What to Hunt:**  
Search for group enumeration commands immediately after the user enumeration command identified in Flag 24, focusing on queries targeting privileged groups.

**Detection Strategy:**  
I filtered process creation events on the workstation for group enumeration commands after `21:34:32`. Just 12 seconds after enumerating all domain users, `rundll32.exe` executed `net group "Domain Admins" /domain` under Lisa's account, identifying every member of the Domain Admins group — the highest privilege accounts in the domain.

**KQL Query:**  
```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:34:32) .. datetime(2026-01-30 21:40:00))
| where EventCode_s == "1"
| where Computer contains "B9GHHO6"
| where CommandLine_s has_any ("net group", "net localgroup", "Get-ADGroupMember")
| project UtcTime_s, Computer, User_s, CommandLine_s, ParentImage_s
| sort by UtcTime_s asc
```

**Evidence:**  
<p align="center">
  <img width="992" height="170" alt="Q25" src="https://github.com/user-attachments/assets/67e41185-2007-4147-8e3c-1e1f480e0f43" />
</p>

**Why This Matters:**  
Querying Domain Admins immediately after user enumeration confirms the attacker was specifically hunting for high value accounts to target. Knowing who the Domain Admins are allows the attacker to focus credential theft and lateral movement efforts on the accounts that would give them full control of the domain. This 12 second gap between commands suggests automated or scripted reconnaissance rather than manual execution.

---

### Flag 26: Infrastructure Mapping – Domain Controller Discovery

**Objective:**  
Identify the command used by the attacker to locate critical domain infrastructure.

**Flag Value:**  
`nltest /dclist:emberforge.local`

**What to Hunt:**  
Search for infrastructure discovery commands immediately after the group enumeration command identified in Flag 25, focusing on commands that locate domain controllers.

**Detection Strategy:**  
I filtered process creation events on the workstation for infrastructure mapping commands after `21:34:44`. At `21:35:07`, `rundll32.exe` executed `nltest /dclist:emberforge.local` under Lisa's account, enumerating all Domain Controllers in the emberforge.local domain. This completed a rapid three-command reconnaissance sequence spanning just 35 seconds.

**KQL Query:**  
```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:34:44) .. datetime(2026-01-30 21:40:00))
| where EventCode_s == "1"
| where Computer contains "B9GHHO6"
| where CommandLine_s has_any ("nltest", "net view", "ping", "nslookup", "dclist")
| project UtcTime_s, Computer, User_s, CommandLine_s, ParentImage_s
| sort by UtcTime_s asc
```

**Evidence:**  
<p align="center">
  <img width="974" height="164" alt="Q26" src="https://github.com/user-attachments/assets/49b1cb97-7001-41d2-9c8b-8b19217538e0" />
</p>

**Why This Matters:**  
`nltest /dclist` is a standard command for enumerating Domain Controllers in a domain. Knowing the location of the Domain Controllers is a critical step before lateral movement, as they are the primary targets for credential theft and domain compromise. This command completed a rapid automated reconnaissance sequence — users, Domain Admins, Domain Controllers — all within 35 seconds of each other, confirming scripted post-exploitation behaviour consistent with a mature threat actor.

---

### Flag 27: Tool Staging Share – Network Share Creation

**Objective:**  
Identify the command used by the attacker to create a network share on the workstation for use as a tool distribution point before lateral movement.

**Flag Value:**  
`cmd.exe /c "net share tools=C:\Users\Public /grant:everyone,full"`

**What to Hunt:**  
Search for network share creation commands on the workstation, particularly those granting full access to everyone and sharing world-writable directories.

**Detection Strategy:**  
I filtered process creation events on the workstation for share creation commands. At `22:51:36`, `spoolsv.exe` — the previously injected process — executed `net share tools=C:\Users\Public /grant:everyone,full`, creating a fully open network share pointing to `C:\Users\Public` where all attacker tools were staged. This share was then used to distribute tools to other hosts during lateral movement.

**KQL Query:**  
```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "1"
| where Computer contains "B9GHHO6"
| where CommandLine_s contains "net share"
| project UtcTime_s, Computer, User_s, CommandLine_s, ParentImage_s
| sort by UtcTime_s asc
```

**Evidence:**  
<p align="center">
  <img width="1017" height="200" alt="Q27 corrected" src="https://github.com/user-attachments/assets/efa55cd9-e4fc-4f09-bcbe-b813431afb7d" />
</p>

**Why This Matters:**  
Creating a fully open network share from the compromised workstation allowed the attacker to distribute tools to other hosts without needing to download them from external infrastructure again. The `/grant:everyone,full` permission means any authenticated user on the network could access the share. This is a classic lateral movement staging technique that also serves as a persistence mechanism for tool redeployment if any tools are removed from other hosts.

---

### Flag 28: Firewall Manipulation – Inbound SMB Rule

**Objective:**  
Identify the name given to the firewall rule added by the attacker to allow inbound connections needed for lateral movement.

**Flag Value:**  
`SMB`

**What to Hunt:**  
Search for netsh firewall rule creation commands on the workstation, particularly those opening inbound ports associated with lateral movement protocols.

**Detection Strategy:**  
I filtered process creation events on the workstation for firewall modification commands. At `22:54:09`, `spoolsv.exe` executed a netsh command adding an inbound firewall rule named `SMB` allowing TCP port 445, the port used for SMB file sharing and a key protocol for lateral movement techniques such as PsExec.

**KQL Query:**  
```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "1"
| where Computer contains "B9GHHO6"
| where CommandLine_s has_any ("netsh", "New-NetFirewallRule", "advfirewall")
| project UtcTime_s, Computer, User_s, CommandLine_s, ParentImage_s
| sort by UtcTime_s asc
```

**Evidence:**  
<p align="center">
  <img width="1169" height="170" alt="Q28 redo" src="https://github.com/user-attachments/assets/9a35a3fc-7257-48a1-8ed7-e821dd7edc95" />
</p>

**Why This Matters:**  
Opening inbound TCP port 445 allows SMB connections to the workstation from other hosts on the network. This was a prerequisite for the PsExec-style lateral movement seen later in the investigation, where the attacker used SMB to push commands and tools to other hosts. The rule was created by the injected `spoolsv.exe` process under `NT AUTHORITY\SYSTEM`, confirming the attacker had full system-level control of the workstation at this point.

---

### Flag 29: Post-Escalation Parent – Injected System Process

**Objective:**  
Identify the parent process responsible for executing all subsequent attacker commands after the beacon migrated to a SYSTEM-level process.

**Flag Value:**  
`spoolsv.exe`

**What to Hunt:**  
Examine the parent process field of lateral movement commands including share creation, file copies and firewall modifications to identify the common parent process.

**Detection Strategy:**  
I examined the ParentImage field of the lateral movement commands identified in Flags 27 and 28. Both the network share creation and firewall rule addition were executed as child processes of `spoolsv.exe`, confirming it as the attacker's stable post-escalation execution parent. This is consistent with the injection identified in Flag 21 where `update.exe` injected into `spoolsv.exe` running as `NT AUTHORITY\SYSTEM`.

**KQL Query:**  
```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "1"
| where Computer contains "B9GHHO6"
| where ParentImage_s contains "spoolsv"
| project UtcTime_s, Computer, User_s, Image_s, CommandLine_s, ParentImage_s
| sort by UtcTime_s asc
```

**Evidence:**  
<p align="center">
  <img width="1176" height="282" alt="Q29" src="https://github.com/user-attachments/assets/82982840-5a4d-4023-8c97-ba136c440489" />
</p>

**Why This Matters:**  
All post-escalation attacker activity on the workstation was executed through the injected `spoolsv.exe` process, confirming it as the stable SYSTEM-level foothold. This process chain is a critical pivot point in the investigation — any command with `spoolsv.exe` as a parent after the injection at `21:56:44` should be treated as attacker activity. This pattern provides a high-fidelity detection opportunity for hunting similar compromises across the environment.

---

### Flag 30: Beacon Distribution – Tool Transfer via Admin Share

**Objective:**  
Identify the full command used by the attacker to push their primary tool to the server via Windows admin shares.

**Flag Value:**  
`cmd.exe /c copy C:\Users\Public\update.exe \\10.1.57.66\C$\Users\Public\update.exe`

**What to Hunt:**  
Search for file copy commands targeting admin shares (C$) on remote hosts, executed by the injected spoolsv.exe process on the workstation.

**Detection Strategy:**  
I examined commands executed by `spoolsv.exe` on the workstation. At `22:14:55`, the attacker copied `update.exe` from the workstation to the server at `10.1.57.66` via the C$ admin share, distributing their primary beacon to the server without needing to download it from external infrastructure again.

**KQL Query:**  
```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "1"
| where Computer contains "B9GHHO6"
| where CommandLine_s contains "C$"
| project UtcTime_s, Computer, User_s, CommandLine_s, ParentImage_s
| sort by UtcTime_s asc
```

**Evidence:**  
<p align="center">
  <img width="1009" height="169" alt="Q30" src="https://github.com/user-attachments/assets/bbb91e43-beb5-43b2-a251-812178e08892" />
</p>

**Why This Matters:**  
Using Windows admin shares (C$) for lateral movement is a well established technique that abuses legitimate Windows file sharing functionality. The admin share `C$` is only accessible to administrators, confirming the attacker had domain admin level credentials at this point — likely obtained from the LSASS dump in Flag 22. This technique leaves minimal network signatures as it uses standard SMB traffic on port 445.

---

### Flag 31: LOLBin Tool Staging – Certutil Download Cradle

**Objective:**  
Identify the built-in Windows utility abused to download tools from the attacker's staging infrastructure onto the server.

**Flag Value:**  
`certutil.exe > http://sync.cloud-endpoint.net:8080/update.exe`

**What to Hunt:**  
Search for certutil or other LOLBin download cradle commands on the server referencing the attacker's staging infrastructure.

**Detection Strategy:**  
I searched process creation events on the server for download commands referencing the staging server identified in Flag 9. `certutil.exe` was used multiple times to download both `update.exe` and `AnyDesk.exe` from `sync.cloud-endpoint.net:8080`, abusing a legitimate Windows certificate utility as a download cradle.

**KQL Query:**  
```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "1"
| where Computer contains "16V3AU4"
| where CommandLine_s contains "certutil"
| project UtcTime_s, Computer, User_s, CommandLine_s, ParentImage_s
| sort by UtcTime_s asc
```

**Evidence:**  
<p align="center">
  <img width="979" height="167" alt="Q31" src="https://github.com/user-attachments/assets/64997979-5fb2-4e5b-b43f-b76cd488fff4" />
</p>

**Why This Matters:**  
`certutil.exe` is a legitimate Windows binary used for certificate management that can also download files from URLs, making it a commonly abused Living Off The Land binary. Its use bypasses application whitelisting controls that block unknown executables since it is a trusted signed Microsoft binary. The non-standard port 8080 on the staging server helps avoid detection by security tools that only monitor standard HTTP port 80 traffic.

---

### Flag 32: Remote Execution Evidence – Temporary Service Creation

**Objective:**  
Identify the randomly named temporary service created on the server by the attacker's remote execution tool.

**Flag Value:**  
`MzLblBFm`

**What to Hunt:**  
Search EventCode 7045 service installation events on the server for randomly named 8-character services created via the PsExec-style execution pattern using %COMSPEC%.

**Detection Strategy:**  
I searched EventCode 7045 raw event data on the server `EC2AMAZ-16V3AU4` for randomly named services. The first random service `MzLblBFm` was created at `22:07:45` using the classic PsExec service execution pattern — commands written to temporary batch files, executed, then deleted. Multiple random service names followed as the attacker executed successive commands remotely.

**KQL Query:**  
```kql
EmberForgeX_CL
| where TimeGenerated between (datetime(2026-01-01) .. now())
| where EventCode_s == "7045"
| where Computer contains "16V3AU4"
| parse Raw_s with * "ServiceName'>" ServiceName "<" *
| parse Raw_s with * "/C " ActualCommand " ^&gt;" *
| where ServiceName != "AnyDesk Service"
| project UtcTime_s, Computer, ServiceName, ActualCommand
| sort by UtcTime_s asc
```

**Evidence:**  
<p align="center">
  <img width="350" height="323" alt="Q32 redo" src="https://github.com/user-attachments/assets/26d7565d-baa1-41e0-8932-d83190cf91aa" />
</p>

**Why This Matters:**  
PsExec-style lateral movement creates temporary Windows services with random names to execute commands on remote systems. The random 8-character service name is a telltale indicator of this technique — legitimate services never have randomly generated names. The pattern of writing commands to temporary batch files and deleting them afterwards is a deliberate anti-forensics measure. EventCode 7045 monitoring is a critical detection control for this lateral movement technique.

---

### Flag 33: First Command on Server – Initial Beacon Check

**Objective:**  
Identify the very first command executed by the attacker on the server after remote execution was established.

**Flag Value:**  
`whoami`

**What to Hunt:**  
Examine the earliest temporary service creation event on the server and extract the command embedded in the ImagePath field.

**Detection Strategy:**  
I examined the earliest EventCode 7045 service creation on the server `EC2AMAZ-16V3AU4` at `22:07:45`. The ImagePath of the first service `MzLblBFm` contained the command `cd`, a simple directory check used as an initial beacon confirmation to verify remote execution was working before proceeding with further commands.

**KQL Query:**  
```kql
EmberForgeX_CL
| where TimeGenerated between (datetime(2026-01-01) .. now())
| where EventCode_s == "7045"
| where Computer contains "16V3AU4"
| parse Raw_s with * "ServiceName'>" ServiceName "<" *
| parse Raw_s with * "echo " FirstCommand " ^&gt;" *
| where ServiceName != "AnyDesk Service"
| project UtcTime_s, Computer, ServiceName, FirstCommand
| sort by UtcTime_s asc
```

**Evidence:**  
<p align="center">
  <img width="560" height="117" alt="Q33 corrected" src="https://github.com/user-attachments/assets/8b0ad71c-ef4b-49d9-ab93-925a7e574230" />
</p>

**Why This Matters:**  
The `cd` command is consistently the first command executed on newly compromised hosts via PsExec-style remote execution. It serves as a simple connectivity and execution confirmation test before the attacker proceeds with further activity. This predictable pattern is a useful detection opportunity — a `cd` command executed via a randomly named temporary service is a near-certain indicator of PsExec-style lateral movement.

---

### Flag 34: Failed Lateral Movement – NTLM Authentication Failures

**Objective:**  
Identify the protocol used in the attacker's first unreliable lateral movement attempts by examining repeated authentication failures on the server.

**Flag Value:**  
`NTLM`

**What to Hunt:**  
Search EventCode 4625 failed logon events on the server for repeated authentication failures from an internal host, examining the AuthenticationPackageName field to identify the protocol.

**Detection Strategy:**  
I searched EventCode 4625 failed logon events on the server `EC2AMAZ-16V3AU4`. Multiple repeated NTLM authentication failures were recorded from source IP `10.1.173.145` using LogonType 3 (network logon), indicating the attacker's initial lateral movement attempts via NTLM were consistently failing before switching to PsExec-style service execution.

**KQL Query:**  
```kql
EmberForgeX_CL
| where TimeGenerated between (datetime(2026-01-01) .. now())
| where EventCode_s == "4625"
| where Computer contains "16V3AU4"
| parse Raw_s with * "AuthenticationPackageName'>" AuthProtocol "<" *
| parse Raw_s with * "IpAddress'>" SourceIP "<" *
| summarize FailureCount = count() by Computer, AuthProtocol, SourceIP
| sort by FailureCount desc
```

**Evidence:**  
<p align="center">
  <img width="756" height="70" alt="Q34 redo" src="https://github.com/user-attachments/assets/f8d98d3e-d3e7-4e09-a0fc-4e912213cbe1" />
</p>

**Why This Matters:**  
Repeated NTLM authentication failures from an internal host are a strong indicator of lateral movement attempts using pass-the-hash or credential spraying techniques. The failures suggest the NTLM hash obtained from the LSASS dump was not working reliably, forcing the attacker to pivot to PsExec-style service execution instead. This pattern of failed authentication followed by successful alternative execution is a common attacker behaviour worth alerting on.

---

### Flag 35: DC Arrival and Credential Extraction – Domain Controller Compromise

**Objective:**  
Identify the first command executed on the Domain Controller and the tool used to extract the Active Directory database.

**Flag Value:**  
`whoami > vssadmin.exe`

**What to Hunt:**  
Search EventCode 7045 service creation events on the Domain Controller, parsing the ImagePath field to extract the actual commands hidden inside the PsExec-style command wrapper.

**Detection Strategy:**  
I searched EventCode 7045 events on the Domain Controller `EC2AMAZ-EEU3IA2`. The same PsExec-style remote execution pattern used on the server was applied to the DC. The first command `vssadmin list shadows` enumerated existing shadow copies, followed immediately by `vssadmin.exe` being used to create a shadow copy and extract `ntds.dit`.

**KQL Query:**  
```kql
EmberForgeX_CL
| where TimeGenerated between (datetime(2026-01-01) .. now())
| where EventCode_s == "1"
| where Computer contains "EEU3IA2"
| where CommandLine_s has_any ("vssadmin", "ntds", "shadow", "copy")
| project UtcTime_s, Computer, Image_s, CommandLine_s, ParentImage_s
| sort by UtcTime_s asc
```

**Evidence:**  
<p align="center">
  <img width="850" height="336" alt="Untitled Diagram-Page-3 drawio" src="https://github.com/user-attachments/assets/076d320c-57d8-4e87-a901-158252f73284" />
</p>

**Why This Matters:**  
Reaching the Domain Controller and extracting `ntds.dit` represents a full domain compromise. Every account credential in the domain is now in the attacker's hands. This is the worst case scenario for any organisation — complete domain level access means every system, every user, and every service account must be treated as compromised until credentials are reset across the entire environment.

---

### Flag 36: Backdoor Account – Persistence via Fake Service Account

**Objective:**  
Identify the backdoor account created by the attacker on the Domain Controller designed to blend in with legitimate service accounts.

**Flag Value:**  
`svc_backup`

**What to Hunt:**  
Search EventCode 4720 account creation events on the Domain Controller for newly created accounts, particularly those named to resemble legitimate service accounts.

**Detection Strategy:**  
I searched EventCode 4720 account creation events on the Domain Controller `EC2AMAZ-EEU3IA2`. The account `svc_backup` was created under `NT AUTHORITY\SYSTEM` context, designed to blend in with legitimate service accounts by using the `svc_` naming convention commonly used for service accounts in enterprise environments.

**KQL Query:**  
```kql
EmberForgeX_CL
| where TimeGenerated between (datetime(2026-01-01) .. now())
| where EventCode_s == "4720"
| parse Raw_s with * "TargetUserName'>" Username "<" *
| parse Raw_s with * "SubjectUserName'>" CreatedBy "<" *
| parse Raw_s with * "TargetDomainName'>" Domain "<" *
| project UtcTime_s, Computer, Username, Domain, CreatedBy
| sort by UtcTime_s asc
```

**Evidence:**  
<p align="center">
  <img width="805" height="151" alt="Q36" src="https://github.com/user-attachments/assets/75625b60-681e-439d-be8f-472b35ac1dbc" />
</p>

**Why This Matters:**  
Creating a backdoor account named `svc_backup` is a deliberate masquerading technique. The `svc_` prefix mimics legitimate Windows service accounts, making it easy to overlook during manual review. This account provides the attacker with persistent domain access even if all other footholds are removed. Every new account creation on a Domain Controller should be treated as suspicious unless verified through a formal change management process.

---

### Flag 37: Backdoor Credentials – Plaintext Password Exposure

**Objective:**  
Identify the plaintext password used to create the backdoor account, exposed in the command line arguments.

**Flag Value:**  
`P@ssw0rd123!`

**What to Hunt:**  
Search process creation events on the Domain Controller for net user commands referencing the backdoor account identified in Flag 36.

**Detection Strategy:**  
I searched process creation events on the Domain Controller for commands referencing `svc_backup`. At `23:38:11`, the account was created with the password `P@ssw0rd123!` passed directly as a command line argument. Immediately after at `23:39:37`, the account was added to Domain Admins — giving the attacker persistent domain admin level access.

**KQL Query:**  
```kql
EmberForgeX_CL
| where TimeGenerated between (datetime(2026-01-01) .. now())
| where EventCode_s == "1"
| where Computer contains "EEU3IA2"
| where CommandLine_s contains "svc_backup"
| project UtcTime_s, Computer, CommandLine_s
| sort by UtcTime_s asc
```

**Evidence:**  
<p align="center">
  <img width="1179" height="271" alt="Q37" src="https://github.com/user-attachments/assets/bb7d6810-96f6-426d-9ef7-f37243a77039" />
</p>

**Why This Matters:**  
Passing passwords as command line arguments is a severe OPSEC failure — Sysmon EventCode 1 captures full command lines in plaintext, permanently logging the credential. The immediate addition of `svc_backup` to Domain Admins confirms the attacker's intent to maintain persistent privileged access to the domain. This account combined with the previously extracted `ntds.dit` gives the attacker multiple redundant paths back into the environment.

---

### Flag 38: Privilege Assignment – Domain Admin Group Addition

**Objective:**  
Identify the privileged group the attacker added the backdoor account to in order to gain elevated domain privileges.

**Flag Value:**  
`Domain Admins`

**What to Hunt:**  
Search process creation events on the Domain Controller for group membership commands referencing the backdoor account identified in Flag 36.

**Detection Strategy:**  
I examined the commands following the account creation at `23:38:11`. Just 86 seconds later at `23:39:37`, the attacker added `svc_backup` to the `Domain Admins` group using `net group "Domain Admins" svc_backup /add /domain`, granting the backdoor account the highest level of privilege in the domain.

**KQL Query:**  
```kql
EmberForgeX_CL
| where TimeGenerated between (datetime(2026-01-01) .. now())
| where EventCode_s == "1"
| where Computer contains "EEU3IA2"
| where CommandLine_s contains "svc_backup"
| project UtcTime_s, Computer, CommandLine_s
| sort by UtcTime_s asc
```

**Evidence:**  
<p align="center">
  <img width="1177" height="261" alt="Q38" src="https://github.com/user-attachments/assets/67d0d3fa-2336-4534-8a17-8ee17cf944cc" />
</p>

**Why This Matters:**  
Adding `svc_backup` to Domain Admins gives the attacker a persistent domain admin account that survives even if all other footholds are removed. Combined with the `ntds.dit` extraction, the exposed password in command line logs, and the deceptive service account naming convention, this represents a comprehensive persistence strategy. Any new Domain Admin account additions should trigger an immediate alert and investigation.

---

### Flag 39: Exposed Credential – Network Drive Mapping Password

**Objective:**  
Identify the plaintext password exposed in the network drive mapping command used by the attacker on the Domain Controller.

**Flag Value:**  
`EmberForge2024!`

**What to Hunt:**  
Search process creation events on the Domain Controller for net use commands containing authentication credentials passed as plaintext arguments.

**Detection Strategy:**  
I searched process creation events on the Domain Controller for network drive mapping commands. At `23:45:25`, the attacker mapped drive Z: to `\\10.1.173.145\tools` — the workstation's tool share identified in Flag 27 — using the domain Administrator account with the password `EmberForge2024!` passed in plaintext. The drive was deleted at `23:49:31` after tools were retrieved.

**KQL Query:**  
```kql
EmberForgeX_CL
| where TimeGenerated between (datetime(2026-01-01) .. now())
| where EventCode_s == "1"
| where Computer contains "EEU3IA2"
| where CommandLine_s has_any ("net use", "Map")
| project UtcTime_s, Computer, CommandLine_s
| sort by UtcTime_s asc
```

**Evidence:**  
<p align="center">
  <img width="1303" height="146" alt="Q39" src="https://github.com/user-attachments/assets/1c2e337d-6e43-4244-9244-190a899b44d7" />
</p>

**Why This Matters:**  
The domain Administrator password being passed in plaintext confirms the attacker successfully cracked or decrypted credentials from the `ntds.dit` dump. This means the highest privileged account in the domain is fully compromised. The connection back to `10.1.173.145` — the workstation — confirms lateral movement was bidirectional between the workstation and Domain Controller.

---

### Flag 40: Scheduled Task – Persistence via Fake Windows Update Task

**Objective:**  
Identify the scheduled task created by the attacker to ensure their payload survives reboots.

**Flag Value:**  
`WindowsUpdate`

**What to Hunt:**  
Search process creation events across all hosts for scheduled task creation commands, particularly those referencing the attacker's primary payload and using names designed to look legitimate.

**Detection Strategy:**  
I searched process creation events for schtasks commands across all hosts. The task `WindowsUpdate` was created multiple times on both the workstation and Domain Controller, configured to run `C:\Users\Public\update.exe` as SYSTEM on startup. The name `WindowsUpdate` was deliberately chosen to blend in with legitimate Windows update tasks.

**KQL Query:**  
```kql
EmberForgeX_CL
| where TimeGenerated between (datetime(2026-01-01) .. now())
| where EventCode_s == "1"
| where CommandLine_s has_any ("schtasks", "Register-ScheduledTask")
| project UtcTime_s, Computer, User_s, CommandLine_s
| sort by UtcTime_s asc
```

**Evidence:**  
<p align="center">
  <img width="1256" height="160" alt="Q40" src="https://github.com/user-attachments/assets/e3f20b6e-5b22-4347-92db-e03e07980b0e" />
</p>

**Why This Matters:**  
The `WindowsUpdate` scheduled task ensures `update.exe` runs as SYSTEM on every reboot, providing persistent access that survives password resets. To answer the CISO's question — rebuilding machines and resetting passwords alone is not sufficient. The scheduled task, backdoor account `svc_backup`, AnyDesk installation, and extracted `ntds.dit` represent multiple redundant persistence mechanisms that must all be addressed before the environment can be considered clean.

---

### Flag 41: Remote Access Tool – Silent AnyDesk Installation

**Objective:**  
Identify the legitimate remote management application installed by the attacker for persistent unattended access.

**Flag Value:**  
`AnyDesk`

**What to Hunt:**  
Search process creation events across all hosts for silent installation commands of remote access tools, particularly those installed from world-writable directories.

**Detection Strategy:**  
I searched process creation events across all hosts for remote access tool installation commands. AnyDesk was downloaded from the attacker's staging server, silently installed on multiple hosts using `--install` and `--silent` flags, and configured with a custom unattended access password hash to allow the attacker to connect without user interaction.

**KQL Query:**  
```kql
EmberForgeX_CL
| where TimeGenerated between (datetime(2026-01-01) .. now())
| where EventCode_s == "1"
| where CommandLine_s contains "AnyDesk"
| project UtcTime_s, Computer, User_s, CommandLine_s, ParentImage_s
| sort by UtcTime_s asc
```

**Evidence:**  
<p align="center">
  <img width="1259" height="285" alt="Q41" src="https://github.com/user-attachments/assets/437dc540-a7ce-4a61-919a-3a5bbac86724" />
</p>

**Why This Matters:**  
AnyDesk is a legitimate remote desktop tool that blends in with normal business software, making it difficult to detect without process-level telemetry. The attacker configured it with a custom password hash for unattended access, meaning they could connect to any compromised host at any time without requiring user interaction or credentials. This represents a persistent remote access channel that operates independently of all other footholds and would survive password resets and scheduled task removal.

---

### Flag 42: Remote Access Configuration – AnyDesk Config File Path

**Objective:**  
Identify the full path of the remote access tool's configuration file that the attacker read and modified.

**Flag Value:**  
`C:\ProgramData\AnyDesk\system.conf`

**What to Hunt:**  
Search process creation events for commands reading or writing to the AnyDesk configuration file across all compromised hosts.

**Detection Strategy:**  
I searched process creation events for commands referencing the AnyDesk configuration file. The attacker read `system.conf` using a `type` command and then modified it by appending an unattended access password hash, enabling passwordless remote access. This activity was observed on both the workstation and server.

**KQL Query:**  
```kql
EmberForgeX_CL
| where TimeGenerated between (datetime(2026-01-01) .. now())
| where EventCode_s == "1"
| where CommandLine_s contains "system.conf"
| project UtcTime_s, Computer, User_s, CommandLine_s
| sort by UtcTime_s asc
```

**Evidence:**  
<p align="center">
  <img width="1191" height="271" alt="Q42" src="https://github.com/user-attachments/assets/6b8eae69-0bbd-4fd7-a754-1c770d943685" />
</p>

**Why This Matters:**  
Modifying `system.conf` to include a custom unattended access password hash allows the attacker to connect to compromised hosts via AnyDesk without any user interaction or visible prompt. This configuration change persists across reboots and survives credential resets, representing a stealthy persistent remote access channel.

---

### Flag 43: Anti-Forensics Tool – Event Log Clearing

**Objective:**  
Identify the built-in Windows utility used by the attacker to clear event logs on the Domain Controller.

**Flag Value:**  
`wevtutil`

**What to Hunt:**  
Search process creation events on the Domain Controller for event log clearing commands using built-in Windows utilities.

**Detection Strategy:**  
I searched process creation events on the Domain Controller for log clearing commands. At `23:50:49`, the attacker used `wevtutil cl Security` to clear the Security event log, followed by `wevtutil cl System` at `23:51:06` to clear the System event log. Both commands were executed multiple times, confirming a deliberate attempt to destroy forensic evidence.

**KQL Query:**  
```kql
EmberForgeX_CL
| where TimeGenerated between (datetime(2026-01-01) .. now())
| where EventCode_s == "1"
| where Computer contains "EEU3IA2"
| where CommandLine_s has_any ("wevtutil", "Clear-EventLog", "eventlog")
| project UtcTime_s, Computer, User_s, CommandLine_s
| sort by UtcTime_s asc
```

**Evidence:**  
<p align="center">
  <img width="1211" height="209" alt="Q43" src="https://github.com/user-attachments/assets/f3488a77-3684-4ccc-8004-7fe70d5bbdb2" />
</p>

**Why This Matters:**  
`wevtutil` is a built-in Windows command line utility for managing event logs. Using it to clear Security and System logs destroys evidence of logon events, service installations, and other attacker activity. However because Sysmon logs are stored separately and were forwarded to Sentinel before deletion, the clearing activity itself was captured — answering the CISO's question that yes, the attacker attempted to cover their tracks, but the Sysmon telemetry pipeline preserved the evidence.

---

### Flag 44: Cleared Logs – Event Log Targets

**Objective:**  
Identify the two event logs cleared by the attacker on the Domain Controller.

**Flag Value:**  
`Security, System`

**What to Hunt:**  
Examine the wevtutil commands identified in Flag 43 to determine which specific event logs were targeted for clearing.

**Detection Strategy:**  
I examined the wevtutil commands on the Domain Controller from Flag 43. Two logs were specifically targeted — the Security log containing authentication, account management and privilege use events, and the System log containing service installation and system activity events. Both were cleared multiple times confirming deliberate anti-forensics activity.

**KQL Query:**  
```kql
EmberForgeX_CL
| where TimeGenerated between (datetime(2026-01-01) .. now())
| where EventCode_s == "1"
| where Computer contains "EEU3IA2"
| where CommandLine_s contains "wevtutil"
| project UtcTime_s, Computer, User_s, CommandLine_s
| sort by UtcTime_s asc
```

**Evidence:**  
<p align="center">
  <img width="1235" height="227" alt="Untitled Diagram-Page-2 drawio" src="https://github.com/user-attachments/assets/31931c27-aed4-4fb2-964d-cb2dde2a93b0" />
</p>

**Why This Matters:**  
The Security log was targeted to destroy evidence of logon events, account creation, privilege escalation and group membership changes. The System log was targeted to destroy evidence of service installations used during lateral movement. Clearing both logs represents a systematic attempt to remove the most forensically valuable Windows event sources. The fact that Sysmon telemetry was forwarded to Sentinel before deletion preserved the evidence and allowed this investigation to proceed.

---

## Logical Flow & Analyst Reasoning

**Flag 0 — Environment Access:**  
Confirmed access to the `EmberForgeX_CL` custom log table in the 
`law-cyber-range` Sentinel workspace, establishing the starting point 
for the investigation.

**Flag 1 — Target Directory:**  
Hunting compression commands surfaced a PowerShell `Compress-Archive` 
command targeting `C:\GameDev`, revealing the stolen data source 
immediately.

**Flag 2 — Exfil Destination:**  
The `mega:exfil` argument in the rclone command confirmed MEGA cloud 
storage as the destination for the stolen data.

**Flag 3 — Attacker Attribution:**  
The attacker passed MEGA credentials directly in the command line, 
exposing the email address `jwilson.vhr@proton.me` as a direct 
attribution lead.

**Flag 4 — Domain Compromise Evidence:**  
Volume shadow copy commands on the Domain Controller confirmed the 
attacker extracted `ntds.dit`, representing a full domain credential 
compromise.

**Flag 5 — Exfil Tool:**  
`rclone.exe` was identified as the exfiltration tool, executed multiple 
times from `C:\Users\Public` under `NT AUTHORITY\SYSTEM` with 
`update.exe` as the parent process.

**Flag 6 — Exfil Destination IP:**  
Correlating rclone network connections confirmed `66.203.125.15` as the 
MEGA API endpoint that received the stolen data over port 443.

**Flag 7 — Attacker Credential Exposure:**  
Comparing all rclone executions revealed one instance where the password 
`Summer2024!` was passed directly as a command line argument — a 
significant OPSEC failure captured permanently in Sysmon logs.

**Flag 8 — Archive Method:**  
The built-in PowerShell `Compress-Archive` cmdlet was used to package 
the stolen data, a Living Off The Land technique that avoids detection 
based on known malicious binaries.

**Flag 9 — Staging Server:**  
Multiple download commands across all three hosts referenced the same 
external domain `sync.cloud-endpoint.net`, confirming it as the 
attacker's primary tool distribution infrastructure.

**Flag 10 — Malicious File:**  
Tracing the earliest malicious process on the workstation revealed 
`rundll32.exe` loading `review.dll` from a D: drive with `explorer.exe` 
as the parent, confirming user-initiated execution.

**Flag 11 — Delivery Vector:**  
The D: drive path of the malicious DLL indicated delivery via a mounted 
disk image such as an ISO, a technique that bypasses Windows Mark of the 
Web protections.

**Flag 12 — Compromised User:**  
The User field of the malicious execution event confirmed `lmartin` as 
patient zero — the entry point for the entire compromise.

**Flag 13 — Execution Chain:**  
The full process lineage of `explorer.exe > rundll32.exe > review.dll` 
confirmed Lisa directly opened the malicious file through Windows 
Explorer.

**Flag 14 — Delivery Unpacking:**  
A 7-Zip extraction event preceding the DLL execution confirmed the 
malware arrived inside an archive named to appear like a legitimate 
EmberForge project review file.

**Flag 15 — Dropped Payload:**  
`rundll32.exe` dropped `update.exe` into `C:\Users\Public` shortly after 
the initial DLL execution, which subsequently became the parent process 
for all malicious activity across the environment.

**Flag 16 — C2 Domain:**  
DNS query events from `update.exe` consistently resolved 
`cdn.cloud-endpoint.net`, confirming it as the C2 domain — sharing the 
same base infrastructure as the staging server.

**Flag 17 — Primary C2 IP:**  
Parsing the QueryResults field of DNS events confirmed `104.21.30.237` 
as the primary resolved IP, hosted behind Cloudflare to obscure the 
attacker's true infrastructure.

**Flag 18 — Injection Chain:**  
CreateRemoteThread events confirmed `rundll32.exe` injected code into 
`notepad.exe`, migrating malicious execution into a legitimate process 
to evade detection.

**Flag 19 — UAC Bypass Binary:**  
Registry modifications to the `ms-settings\shell\open\command` key 
identified the fodhelper UAC bypass technique, allowing the attacker 
to elevate privileges without triggering a UAC prompt.

**Flag 20 — Registry Bypass Enabler:**  
The `DelegateExecute` value set immediately after the payload path 
modification was the specific trigger that activates the fodhelper 
bypass mechanism.

**Flag 21 — Stable Injection Chain:**  
After UAC bypass, `update.exe` injected into `spoolsv.exe` running as 
`NT AUTHORITY\SYSTEM`, establishing a privileged stable foothold that 
persisted across user sessions.

**Flag 22 — Credential Dumping Process:**  
File creation events revealed `update.exe` wrote `lsass.dmp` to disk 
using direct syscalls to bypass API monitoring, evading traditional 
LSASS access detection.

**Flag 23 — Dump Location:**  
The LSASS dump was written to `C:\Windows\System32\lsass.dmp`, 
deliberately placed among legitimate system files to avoid detection 
during manual review.

**Flag 24 — User Enumeration:**  
`net user /domain` was the first discovery command executed, querying 
all domain accounts within minutes of initial infection confirming 
scripted reconnaissance.

**Flag 25 — Privilege Enumeration:**  
Just 12 seconds after user enumeration, `net group "Domain Admins" 
/domain` identified the highest privileged accounts in the domain, 
confirming automated post-exploitation tooling.

**Flag 26 — Infrastructure Mapping:**  
`nltest /dclist:emberforge.local` completed a rapid three-command 
reconnaissance sequence, locating the Domain Controllers before lateral 
movement began.

**Flag 27 — Tool Staging Share:**  
The injected `spoolsv.exe` created a fully open network share pointing 
to `C:\Users\Public`, establishing the workstation as a tool 
distribution point for lateral movement.

**Flag 28 — Firewall Manipulation:**  
A firewall rule named `SMB` was added to allow inbound TCP port 445, 
enabling the PsExec-style lateral movement that followed.

**Flag 29 — Post-Escalation Parent:**  
Every lateral movement command on the workstation had `spoolsv.exe` as 
its parent process, confirming it as the stable SYSTEM-level execution 
host after the UAC bypass.

**Flag 30 — Beacon Distribution:**  
`update.exe` was copied to the server via the C$ admin share, 
distributing the primary implant without requiring another external 
download.

**Flag 31 — LOLBin Tool Staging:**  
`certutil.exe` was abused as a download cradle to pull tools from 
`sync.cloud-endpoint.net:8080`, a Living Off The Land technique that 
bypasses application whitelisting controls.

**Flag 32 — Remote Execution Evidence:**  
The first randomly named service `MzLblBFm` on the server confirmed 
PsExec-style lateral movement, identifiable by its random 8-character 
name and batch file execution pattern.

**Flag 33 — First Command on Server:**  
`whoami` was the first command executed on the server, confirming the 
consistent attacker pattern of verifying execution context immediately 
upon compromising a new host.

**Flag 34 — Failed Lateral Movement:**  
Repeated NTLM authentication failures from the workstation IP confirmed 
the attacker's initial lateral movement method was unreliable before 
switching to PsExec-style execution.

**Flag 35 — DC Arrival and Credential Extraction:**  
The same `whoami` first-command pattern confirmed DC arrival, followed 
immediately by `vssadmin.exe` beginning the shadow copy credential 
extraction sequence.

**Flag 36 — Backdoor Account:**  
EventCode 4720 on the Domain Controller revealed the creation of 
`svc_backup`, a backdoor account named to blend in with legitimate 
service accounts.

**Flag 37 — Backdoor Credentials:**  
The `net user` command creating `svc_backup` passed the password 
`P@ssw0rd123!` directly as a command line argument, permanently logging 
it in Sysmon telemetry.

**Flag 38 — Privilege Assignment:**  
`svc_backup` was added to Domain Admins just 86 seconds after creation, 
giving the attacker a persistent domain admin backdoor independent of 
all other footholds.

**Flag 39 — Exposed Credential:**  
A network drive mapping command on the DC exposed the domain 
Administrator password `EmberForge2024!` in plaintext, confirming the 
attacker had successfully cracked credentials from the ntds.dit dump.

**Flag 40 — Scheduled Task:**  
A scheduled task named `WindowsUpdate` was created on both the 
workstation and Domain Controller to run `update.exe` as SYSTEM on 
startup, ensuring persistence across reboots.

**Flag 41 — Remote Access Tool:**  
AnyDesk was silently installed across multiple hosts and configured with 
a custom unattended access password hash, providing the attacker a 
persistent remote access channel independent of all other footholds.

**Flag 42 — Remote Access Configuration:**  
The AnyDesk configuration file at `C:\ProgramData\AnyDesk\system.conf` 
was read and modified to enable unattended access, allowing the attacker 
to connect without any user interaction.

**Flag 43 — Anti-Forensics Tool:**  
`wevtutil` was used to clear Security and System event logs on the 
Domain Controller, confirming a deliberate attempt to destroy forensic 
evidence before leaving.

**Flag 44 — Cleared Logs:**  
The Security and System logs were both targeted and cleared multiple 
times, destroying authentication records and service installation events 
— however Sysmon telemetry forwarded to Sentinel preserved the 
evidence.

---

## Key Findings

**Full Domain Compromise:**  
The attacker achieved complete domain compromise by extracting `ntds.dit` from 
the Domain Controller via volume shadow copy, obtaining the hashed credentials 
of every account in the `emberforge.local` domain. The subsequent exposure of 
the domain Administrator password `EmberForge2024!` in plaintext confirmed 
successful offline credential cracking.

**Targeted Attack Against a Specific Employee:**  
The delivery of a malicious ISO file named to mimic a legitimate EmberForge 
project review file confirms this was a targeted spearphishing attack against 
`lmartin` specifically. The attacker had prior knowledge of EmberForge's internal 
project naming conventions, suggesting pre-attack reconnaissance.

**Proprietary Source Code Exfiltrated:**  
The entire `C:\GameDev` directory was compressed and uploaded to MEGA cloud 
storage via `rclone.exe`. The attacker's MEGA account `jwilson.vhr@proton.me` 
and password `Summer2024!` were exposed in plaintext in Sysmon logs, providing 
direct attribution evidence.

**Three Hosts Fully Compromised:**  
All three hosts in the `emberforge.local` environment were compromised — the 
workstation `EC2AMAZ-B9GHHO6`, the server `EC2AMAZ-16V3AU4`, and the Domain 
Controller `EC2AMAZ-EEU3IA2`. Each host had `update.exe` deployed, AnyDesk 
installed, and a `WindowsUpdate` scheduled task created for persistent access.

**Multiple Redundant Persistence Mechanisms:**  
The attacker established at least five independent persistence mechanisms — the 
`WindowsUpdate` scheduled task, the `svc_backup` backdoor domain admin account, 
AnyDesk remote access on all three hosts, process injection into `spoolsv.exe`, 
and the `ms-settings` registry modification. Rebuilding machines and resetting 
passwords alone is insufficient without addressing all five mechanisms.

**Anti-Forensics Attempted but Failed:**  
The attacker cleared the Security and System event logs on the Domain Controller 
using `wevtutil` in an attempt to destroy forensic evidence. However Sysmon 
telemetry was forwarded to Microsoft Sentinel before the logs were cleared, 
preserving the complete attack chain and allowing full reconstruction of the 
incident.

**Attacker Infrastructure Identified:**  
Two attacker-controlled domains were identified — `cdn.cloud-endpoint.net` for 
C2 communications and `sync.cloud-endpoint.net` for tool staging — both hosted 
behind Cloudflare infrastructure to obscure the attacker's true origin. These 
domains should be immediately blocked and submitted as IOCs for threat 
intelligence sharing.

**OPSEC Failures Provide Attribution Leads:**  
The attacker made several significant OPSEC mistakes — exposing MEGA credentials 
in command line arguments, passing the domain Administrator password in plaintext 
in a `net use` command, and leaving attacker-controlled email addresses in rclone 
configuration files. These mistakes provide actionable attribution evidence for 
law enforcement engagement.

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Initial Access | Phishing: Spearphishing Attachment | T1566.001 |
| Initial Access | Phishing: Spearphishing via ISO | T1566 |
| Execution | Signed Binary Proxy Execution: Rundll32 | T1218.011 |
| Execution | Command and Scripting Interpreter: PowerShell | T1059.001 |
| Execution | Command and Scripting Interpreter: Windows Command Shell | T1059.003 |
| Execution | System Services: Service Execution | T1569.002 |
| Persistence | Scheduled Task/Job: Scheduled Task | T1053.005 |
| Persistence | Create Account: Domain Account | T1136.002 |
| Persistence | Remote Access Software | T1219 |
| Persistence | Boot or Logon Autostart Execution: Registry Run Keys | T1547.001 |
| Privilege Escalation | Abuse Elevation Control Mechanism: Bypass UAC | T1548.002 |
| Privilege Escalation | Process Injection: Remote Thread Injection | T1055.003 |
| Defense Evasion | Process Injection: Remote Thread Injection | T1055.003 |
| Defense Evasion | Masquerading: Match Legitimate Name or Location | T1036.005 |
| Defense Evasion | Indicator Removal: Clear Windows Event Logs | T1070.001 |
| Defense Evasion | Signed Binary Proxy Execution: Rundll32 | T1218.011 |
| Defense Evasion | Obfuscated Files or Information | T1027 |
| Credential Access | OS Credential Dumping: LSASS Memory | T1003.001 |
| Credential Access | OS Credential Dumping: NTDS | T1003.003 |
| Discovery | Account Discovery: Domain Account | T1087.002 |
| Discovery | Permission Groups Discovery: Domain Groups | T1069.002 |
| Discovery | Remote System Discovery | T1018 |
| Lateral Movement | Remote Services: SMB/Windows Admin Shares | T1021.002 |
| Lateral Movement | Remote Service Session Hijacking | T1563 |
| Collection | Archive Collected Data: Archive via Utility | T1560.001 |
| Command and Control | Application Layer Protocol: Web Protocols | T1071.001 |
| Command and Control | Ingress Tool Transfer | T1105 |
| Command and Control | Domain Fronting | T1090.004 |
| Exfiltration | Exfiltration to Cloud Storage | T1567.002 |
| Impact | Data Theft | T1565 |

---

## Recommendations for Remediation

### Immediate Actions (0-24 Hours)

**Isolate Compromised Hosts:**  
Immediately isolate all three hosts — `EC2AMAZ-B9GHHO6`, `EC2AMAZ-16V3AU4`, 
and `EC2AMAZ-EEU3IA2` — from the network to prevent further lateral movement 
or data exfiltration.

**Disable Compromised Accounts:**  
Immediately disable the backdoor account `svc_backup` and remove it from the 
Domain Admins group. Treat the domain Administrator account as fully compromised 
and reset its password immediately.

**Reset All Domain Credentials:**  
As `ntds.dit` was successfully extracted, all domain account passwords must be 
reset — including service accounts, administrator accounts, and user accounts. 
The krbtgt account password should be reset twice to invalidate all existing 
Kerberos tickets.

**Block Attacker Infrastructure:**  
Block the following IOCs at the perimeter firewall and DNS level immediately:
- `cdn.cloud-endpoint.net`
- `sync.cloud-endpoint.net`
- `104.21.30.237`
- `172.67.174.46`
- `66.203.125.15`
- `jwilson.vhr@proton.me`

**Remove Persistence Mechanisms:**  
Delete the `WindowsUpdate` scheduled task on all hosts, uninstall AnyDesk from 
all compromised hosts, and remove the `C:\ProgramData\AnyDesk` directory and 
configuration files.

---

### Short Term Actions (24-72 Hours)

**Rebuild Compromised Hosts:**  
All three compromised hosts should be rebuilt from clean images. Do not attempt 
to remediate in place as the depth of compromise makes it impossible to 
guarantee full removal of all attacker tooling.

**Remove Malicious Files:**  
Ensure the following files are removed from all hosts before rebuilding:
- `C:\Users\Public\update.exe`
- `C:\Users\Public\rclone.exe`
- `C:\Users\Public\rclone.conf`
- `C:\Users\Public\gamedev.zip`
- `C:\Users\Public\AnyDesk.exe`
- `C:\Users\Public\af.exe`
- `C:\Windows\System32\lsass.dmp`

**Audit Domain Admin Group:**  
Review all members of the Domain Admins group and remove any accounts that 
should not have that level of access. Implement a formal process requiring 
change management approval for any future Domain Admin group membership changes.

**Notify Legal and Affected Parties:**  
The exfiltration of `C:\GameDev` source code constitutes a data breach. Legal 
should be notified immediately to begin breach notification procedures. Consider 
notifying law enforcement given the attribution evidence available.

---

### Long Term Actions (1-4 Weeks)

**Implement Email Filtering for ISO Attachments:**  
Block or quarantine ISO, IMG, and VHD file attachments at the email gateway to 
prevent future ISO-based delivery of malware. This directly addresses the initial 
access vector used in this attack.

**Deploy Application Whitelisting:**  
Prevent execution of unsigned binaries from world-writable directories such as 
`C:\Users\Public` by implementing application whitelisting via AppLocker or 
Windows Defender Application Control.

**Enable PowerShell Constrained Language Mode:**  
Restrict PowerShell execution to constrained language mode to prevent abuse of 
built-in cmdlets like `Compress-Archive` for malicious purposes.

**Implement LSASS Protection:**  
Enable LSA Protection and Credential Guard to prevent future LSASS memory 
dumping attacks. This would have prevented the credential theft identified in 
Flag 22.

**Deploy Privileged Access Workstations:**  
Require all Domain Admin activity to be performed from dedicated Privileged 
Access Workstations that are isolated from standard user activity, reducing the 
risk of credential theft from compromised endpoints.

**Implement Tiered Administration:**  
Adopt a tiered administration model separating Domain Admin, Server Admin, and 
Workstation Admin credentials to limit the blast radius of future compromises.

**Alert on High Fidelity IOCs:**  
Implement the following detection rules in Microsoft Sentinel:
- Random 8-character service name creation (EventCode 7045)
- Execution from `C:\Users\Public` (EventCode 1)
- `net share` commands creating open shares (EventCode 1)
- `vssadmin` execution on Domain Controllers (EventCode 1)
- New Domain Admin group membership additions (EventCode 4732)
- `wevtutil cl` event log clearing commands (EventCode 1)
- rclone execution with cloud storage arguments (EventCode 1)
- AnyDesk installation from non-standard paths (EventCode 11)

**Security Awareness Training:**  
Provide targeted phishing awareness training to all staff with a focus on ISO 
file delivery, social engineering techniques, and the risks of opening unexpected 
attachments — directly addressing the initial access vector used against 
`lmartin` in this incident.
