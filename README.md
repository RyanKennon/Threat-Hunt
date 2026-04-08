# Threat-Hunt

### Flag 1: Target Directory – Source of Stolen Data
**Objective:**  
Identify the directory that was the source of stolen data by analyzing compression commands used by the attacker to package files before exfiltration.  
**Flag Value:**  
C:\GameDev  
**What to Hunt:**  
Look for compression tool usage in process creation events (EventCode 1), particularly Compress-Archive, 7z, WinRAR, or similar utilities. The -Path argument reveals the source directory being targeted.  
**Detection Strategy:**  
I filtered process creation events for known compression tools and sorted chronologically to identify what data was being packaged. A PowerShell Compress-Archive command revealed the attacker archiving the entire C:\GameDev directory into a zip file staged at C:\Users\Public\gamedev.zip.  
**KQL Query:**  
`EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "1"
| where CommandLine_s has_any ("Compress-Archive", "7z", "zip", "rar", "tar")
| project UtcTime_s, Computer, User_s, Image_s, CommandLine_s, ParentImage_s
| sort by UtcTime_s asc`  
**Evidence:**  

**Why This Matters:**  
The `Compress-Archive` command with `-Path C:\GameDev` confirms the attacker 
specifically targeted the game development directory — likely containing source 
code, assets, and proprietary project files.  

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
*(Insert Sentinel screenshot here)*

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
*(Insert Sentinel screenshot here)*

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
*(Insert Sentinel screenshot here)*

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
*(Insert Sentinel screenshot here)*

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
*(Insert Sentinel screenshot here)*

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
*(Insert Sentinel screenshot here)*

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
*(Insert Sentinel screenshot here)*

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
*(Insert Sentinel screenshot here)*

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
*(Insert Sentinel screenshot here)*

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
*(Insert Sentinel screenshot here)*

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
*(Insert Sentinel screenshot here)*

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
*(Insert Sentinel screenshot here)*

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
*(Insert Sentinel screenshot here)*

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
*(Insert Sentinel screenshot here)*

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
*(Insert Sentinel screenshot here)*

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
*(Insert Sentinel screenshot here)*

**Why This Matters:**  
The two resolved IPs belong to Cloudflare's infrastructure, indicating the attacker is hiding their true origin behind Cloudflare's reverse proxy. This is a common technique to obscure attacker infrastructure and make takedown requests more difficult. Both IPs should be blocked at the perimeter and the domain submitted as an IOC immediately.

---

### Flag 18: Injection Chain – Process Injection for Defense Evasion

**Objective:**  
Identify the process injection chain used by the attacker to hide malicious activity inside a legitimate Windows process.

**Flag Value:**  
`update.exe > spoolsv.exe`

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
*(Insert Sentinel screenshot here)*

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
*(Insert Sentinel screenshot here)*

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
*(Insert Sentinel screenshot here)*

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
*(Insert Sentinel screenshot here)*

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
*(Insert Sentinel screenshot here)*

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
*(Insert Sentinel screenshot here)*

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
*(Insert Sentinel screenshot here)*

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
*(Insert Sentinel screenshot here)*

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
*(Insert Sentinel screenshot here)*

**Why This Matters:**  
`nltest /dclist` is a standard command for enumerating Domain Controllers in a domain. Knowing the location of the Domain Controllers is a critical step before lateral movement, as they are the primary targets for credential theft and domain compromise. This command completed a rapid automated reconnaissance sequence — users, Domain Admins, Domain Controllers — all within 35 seconds of each other, confirming scripted post-exploitation behaviour consistent with a mature threat actor.

---

### Flag 27: Tool Staging Share – Network Share Creation

**Objective:**  
Identify the command used by the attacker to create a network share on the workstation for use as a tool distribution point before lateral movement.

**Flag Value:**  
`net share tools=C:\Users\Public /grant:everyone,full`

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
| where CommandLine_s has_any ("net share", "New-SmbShare")
| project UtcTime_s, Computer, User_s, CommandLine_s, ParentImage_s
| sort by UtcTime_s asc
```

**Evidence:**  
*(Insert Sentinel screenshot here)*

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
*(Insert Sentinel screenshot here)*

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
*(Insert Sentinel screenshot here)*

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
*(Insert Sentinel screenshot here)*

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
*(Insert Sentinel screenshot here)*

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
| where EventCode_s == "7045"
| where Computer contains "16V3AU4"
| project UtcTime_s, Computer, Raw_s
| sort by UtcTime_s asc
```

**Evidence:**  
*(Insert Sentinel screenshot here)*

**Why This Matters:**  
PsExec-style lateral movement creates temporary Windows services with random names to execute commands on remote systems. The random 8-character service name is a telltale indicator of this technique — legitimate services never have randomly generated names. The pattern of writing commands to temporary batch files and deleting them afterwards is a deliberate anti-forensics measure. EventCode 7045 monitoring is a critical detection control for this lateral movement technique.

---

### Flag 33: First Command on Server – Initial Beacon Check

**Objective:**  
Identify the very first command executed by the attacker on the server after remote execution was established.

**Flag Value:**  
`cd`

**What to Hunt:**  
Examine the earliest temporary service creation event on the server and extract the command embedded in the ImagePath field.

**Detection Strategy:**  
I examined the earliest EventCode 7045 service creation on the server `EC2AMAZ-16V3AU4` at `22:07:45`. The ImagePath of the first service `MzLblBFm` contained the command `cd`, a simple directory check used as an initial beacon confirmation to verify remote execution was working before proceeding with further commands.

**KQL Query:**  
```kql
EmberForgeX_CL
| where EventCode_s == "7045"
| where Computer contains "16V3AU4"
| extend EventTime = todatetime(UtcTime_s)
| project EventTime, Computer, Raw_s
| sort by EventTime asc
```

**Evidence:**  
*(Insert Sentinel screenshot here)*

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
| where EventCode_s == "4625"
| where Computer contains "16V3AU4"
| project UtcTime_s, Computer, Caller_User_Name_s, src_ip_s, LogonType_s, Raw_s
| sort by UtcTime_s asc
```

**Evidence:**  
*(Insert Sentinel screenshot here)*

**Why This Matters:**  
Repeated NTLM authentication failures from an internal host are a strong indicator of lateral movement attempts using pass-the-hash or credential spraying techniques. The failures suggest the NTLM hash obtained from the LSASS dump was not working reliably, forcing the attacker to pivot to PsExec-style service execution instead. This pattern of failed authentication followed by successful alternative execution is a common attacker behaviour worth alerting on.

---

