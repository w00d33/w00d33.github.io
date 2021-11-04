## SourceTypes

- Windows Event Logs = velwineventlog



## Lateral Movement

### Tracking Mounted Shares
- Filter by EventID 5140 to identify any shreas mounted during the time period the log represents
- Identify Account Names
- Identify different shares accounts are mounting
- Identify non-user admin accounts (requires intel on domains admin account naming convention)
- Identify mappings to adminitrative accounts remotely
- 5140: A network share object was accessed
- 5142: A network share object was added
- 5143: A network share object was modified
- 5144: A network share object was deleted
- 5145: A network share object was checked to see whether client can be granted desired access


<br>

```r
sourcetype=velwineventlog EventID="5140" EventData.SubjectUserName!="ANONYMOUS LOGON" EventData.SubjectUserName!="*$" EventData.IpAddress!=127.0.0.1
NOT [ | inputlookup admin_accounts.csv | rename account_name as EventData.SubjectUserName | fields EventData.SubjectUserName]
| stats values(EventData.IpAddress) as "Source IP" values(EventData.ShareName) as "Target Share Path" values(System.Computer) as "Target Hostname" count by EventData.SubjectUserName
| rename EventData.SubjectUserName as "Source User"
| sort 0 - count
```

<br>

**Sankey Visulization**

```r
sourcetype=velwineventlog EventID="5140" EventData.SubjectUserName!="ANONYMOUS LOGON" EventData.SubjectUserName!="*$*" EventData.IpAddress!=127.0.0.1
NOT [ | inputlookup admin_accounts.csv | rename account_name as EventData.SubjectUserName | fields EventData.SubjectUserName]
| stats  count by EventData.SubjectUserName EventData.IpAddress System.Computer EventData.ShareName
| appendpipe [stats count by EventData.SubjectUserName EventData.IpAddress | rename EventData.SubjectUserName as source, EventData.IpAddress as target]
| appendpipe [stats count by EventData.IpAddress System.Computer | rename EventData.IpAddress as source, System.Computer as target]
| appendpipe [stats count by System.Computer EventData.ShareName | rename System.Computer as source, EventData.ShareName as target]
|  search source=*
|  fields source target count
```

### Identify Suspicious Services
- Filter for EventIF 4697
- Filter out Computer Accounts "ends with $"
- Record Paths and Filenames

```r
sourcetype=velwineventlog EventID="4697" EventData.SubjectUserName!="*$"
|  replace 2 with "Automatic" in EventData.ServiceStartType
|  replace 3 with "Manual" in EventData.ServiceStartType
|  stats values(EventData.ServiceStartType) as "Service Start Type" values(EventData.ServiceName) as "Service Name" values(EventData.ServiceAccount) as "Service Account" values(EventData.SubjectUserName) as "Source User" values(System.Computer) as "Target Hostname" count by EventData.ServiceFileName
| rename EventData.ServiceFileName as "Service File Name"
| sort num(count)
```

### Suspicious Scheduled Tasks
- Filter for 106 Events
| replace 200 with "Scheduled Task Executed" in EventID | replace 201 with "Scheduled Task Completed" in EventID

Registered Tasks
```r
sourcetype=velwineventlog EventID IN (106)
| replace 106 with "Scheduled Task Registered" in EventID | replace 200 with "Scheduled Task Executed" in EventID | replace 201 with "Scheduled Task Completed" in EventID 
| stats values(EventData.UserContext) as "User Context" values(System.Security.UserID) as "Ran As" values(EventID) as "Event" values(System.Computer) as "Target Hostname" count by EventData.TaskName
| sort num(count)
```
<br>

Executed/Completed Tasks
```r
sourcetype=velwineventlog EventID IN (106) EventData.UserContext!="*$$"
| replace 106 with "Scheduled Task Registered" in EventID | replace 200 with "Scheduled Task Executed" in EventID | replace 201 with "Scheduled Task Completed" in EventID 
| stats values(EventData.UserContext) as "User Context" values(System.Security.UserID) as "SID" values(EventID) as "Event" values(System.Computer) as "Target Hostname" count by EventData.TaskName
| sort num(count)
```

### Event Log Cleared
- EventID 1102 (Security)
- EventID 104 (System)

## Run As
- Provides explicit credentials
- Recorded on both Source and Destination

```r
sourcetype=velwineventlog EventID="4648" EventData.SubjectUserName!="*$"
| eval TargetIP = 'EventData.IpAddress' + ":" + 'EventData.IpPort'
| rex field=EventData.ProcessName "(?<ProcessName>[^\\\]+)$"
| rex field=EventData.TargetServerName "(?<TargetHostname>[^\.]+)"
| rex field=System.Computer "(?<SourceHostname>[^\.]+)"
| stats values(EventData.SubjectUserName) as "Source User" values(SourceHostname) as "Source Hostname" values(EventData.TargetUserName) as "Target User" values(TargetHostname) as "Target Hostname" values(TargetIP) as "Target IP" count by EventData.ProcessName
| sort num(count)
```

<br>

**Sankey Diagram**

```r
sourcetype=velwineventlog EventID="4648" EventData.SubjectUserName!="*$"  EventData.ProcessName!=""
| eval TargetIP = 'EventData.IpAddress' + ":" + 'EventData.IpPort'
| rex field=EventData.ProcessName "(?<ProcessName>[^\\\]+)$"
| rex field=EventData.TargetServerName "(?<TargetHostname>[^\.]+)"
| rex field=System.Computer "(?<SourceHostname>[^\.]+)"
| stats  count by SourceHostname ProcessName EventData.TargetUserName TargetHostname
| appendpipe  [stats  count by SourceHostname ProcessName | rename  SourceHostname as source, ProcessName as target]  
| appendpipe  [stats  count by ProcessName EventData.TargetUserName  | rename  ProcessName as source, EventData.TargetUserName as target]  
| appendpipe  [stats  count by EventData.TargetUserName TargetHostname  | rename EventData.TargetUserName as source, TargetHostname as target]
| search source=*  
| fields  source target count
```