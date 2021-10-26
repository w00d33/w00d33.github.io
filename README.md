# Notes on DFIR, Threat Hunting, and Malware Analysis

## Table of Contents

Incident Response
  * [Incident Response Process](#incident-response-process)
  * [Incident Response Hierarchy of Needs](#incident-response-hierarchy-of-needs)
  * [Attack Lifecycle](#attack-lifecycle)
  * [SANS Windows Forensic Analysis Poster](#sans-windows-forensic-analysis-poster)
Hunting
  * [Common Malware Names](#common-malware-names)
  * [Common Malware Locations](#common-malware-locations)
  * [Living of the Land Binaries](#living-of-the-land-binaries)

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

## SANS Windows Forensic Analysis Poster
* [Link](https://github.com/w00d33/w00d33.github.io/blob/main/_files/SANS_Windows_Forensics_Poster.pdf)

## Common Malware Names
* [The typographical and homomorphic abuse of svchost.exe, and other popular file names](https://www.hexacorn.com/blog/2015/12/18/the-typographical-and-homomorphic-abuse-of-svchost-exe-and-other-popular-file-names/)

## Common Malware Locations
* [Digging for Malware: Suspicious Filesystem Geography](http://www.malicious-streams.com/resources/articles/DGMW1_Suspicious_FS_Geography.html)

## Living of the Land Binaries
* [LOLBAS Project](https://lolbas-project.github.io/)

## Persitence Locations

### AutoStart
```
Common Autostart Locations

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

### DLL Hijacking

DLL Search Order Hijacking
- Place malicious file ahead of DLL in search order
- Windows looks at Application directory prior to Windows/System32 folder
- Look at exe's import table

Phantom DLL Hijacking
- Find DLLs that applications attempt to load, but doesn't exist

DLL Side Loading
- WinSXS provides a new version of a legit DLL