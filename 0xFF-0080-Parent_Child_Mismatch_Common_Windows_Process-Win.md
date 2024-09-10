# Parent Child Mismatch Common Windows Process

## Metadata
**ID:** 0xFF-0080-Parent_Child_Mismatch_Common_Windows_Process-Win

**OS:** WindowsEndpoint, WindowsServer

**FP Rate:** High

---

## ATT&CK Tags

| Tactic | Technique | Subtechnique | Technique Name |
|---|---|---| --- |
| TA0005 - Defense Evasion | T1036 | 003 | Masquerading - Rename System Utilities|

## Utilized Data Sources

| Log Provider | Event ID | Event Name | ATT&CK Data Source | ATT&CK Data Component|
|---------|---------|----------|---------|---------|
|MicrosoftThreatProtection|ProcessCreated||Process|Process Creation|
|MicrosoftThreatProtection|CreateRemoteThreadApiCall||Process|OS API Execution|
---

## Technical description of the attack
This query searches for execution of common Windows processes such as winlogon.exe and then verifies whether the parent process matches the expected parent process.


## Permission required to execute the technique
User

## Detection description
Attackers attempt to avoid detection by using masquerading techniques to pretend that processes are part of the Windows operating system.


## Considerations
None.


## False Positives
Some legitimate security tools might cause uncommon parent-child relationships to occur.


## Suggested Response Actions
Investigate why the process is running with an unexpected parent process.


## Detection Blind Spots
If an attacker uses 'parent id' spoofing this rule can be bypassed.


## References
* https://www.andreafortuna.org/2017/06/15/standard-windows-processes-a-brief-reference/
* https://github.com/FalconForceTeam/FalconFriday/blob/master/Defense%20Evasion/T1036.005-WIN-001.md
* https://digital-forensics.sans.org/media/SANS_Poster_2018_Hunt_Evil_FINAL.pdf

---
## Detection

**Language:** Kusto

**Platform:** M365 Security

**Query:**
```C#
let timeframe = 2*1h;
let ProcessRelations=datatable(ImageFile:string,ExpectedParent:dynamic) [
    "smss.exe", dynamic(["smss.exe", "ntoskrnl.exe", "system"]),
    "csmss.exe", dynamic(["smss.exe"]),
    "wininit.exe", dynamic(["smss.exe"]),
    "winlogon.exe", dynamic(["smss.exe"]),
    "services.exe", dynamic(["wininit.exe"]),
    "lsaiso.exe", dynamic(["wininit.exe"]),
    "lsass.exe", dynamic(["wininit.exe"]),
    "userinit.exe", dynamic(["winlogon.exe"]),
    "svchost.exe", dynamic(["services.exe", "msmpeng.exe"]),
    "runtimebroker.exe", dynamic(["svchost.exe"]),
    "taskhostw.exe", dynamic(["svchost.exe"])
];
let suspiciousChild=DeviceProcessEvents
| where ingestion_time() >= ago(timeframe)
| where ActionType =~ "ProcessCreated"
| extend ImageFile = tolower(FileName)
| extend ParentFile = tolower(InitiatingProcessFileName)
| lookup kind=inner ProcessRelations on ImageFile
| where not(set_has_element(ExpectedParent,ParentFile))
// Begin environment-specific filter.
// End environment-specific filter.
| summarize arg_min(Timestamp,*), DeviceCount=dcount(DeviceId) by ImageFile, ParentFile;
DeviceEvents
| where ingestion_time() >= ago(timeframe)
| where ActionType =~ "CreateRemoteThreadApiCall"
| where InitiatingProcessFileName =~ "werfault.exe"
| join kind=rightanti suspiciousChild on DeviceId,$left.ProcessId == $right.InitiatingProcessId, $left.FileName==$right.InitiatingProcessFileName
```

---

## Version History
| Version | Date | Impact | Notes |
|---------|------|--------|------|
| 2.2  | 2024-06-06| minor | Added a filter for "ProcessCreated" actiontype, as MDE is rolling out other actiontypes as well. |
| 2.1  | 2023-12-04| major | Extend Sentinel entity mapping. |
| 2.0  | 2023-01-27| major | Added a filter to remove false positives due to application crashes. |
| 1.1  | 2022-02-22| minor | Use ingestion_time for event selection and include de-duplication logic. |
| 1.0  | 2021-03-19| major | Initial version. |