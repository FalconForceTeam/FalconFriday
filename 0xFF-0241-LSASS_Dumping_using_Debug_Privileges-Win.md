# LSASS Dumping using Debug Privileges

## Metadata
**ID:** 0xFF-0241-LSASS_Dumping_using_Debug_Privileges-Win

**OS:** WindowsEndpoint, WindowsServer

---

## ATT&CK Tags

| Tactic | Technique | Subtechnique | Technique Name |
|---|---|---| --- |
| TA0006 - Credential Access | T1003 | 001 | OS Credential Dumping - LSASS Memory|
| TA0002 - Execution | T1106 |  | Native API|

## Utilized Data Sources

| Log Provider | Table Name | Event ID | Event Name | ATT&CK Data Source | ATT&CK Data Component|
|---------|---------|---------|----------|---------|---------|
|MicrosoftThreatProtection|DeviceEvents|OpenProcessApiCall||Process|Process Access|
---

## Detection description
This query searches for a process that requests the `SeDebugPrivilege` privilege and opens LSASS memory using specific permission 0x1fffff which represents `PROCESS_ALL_ACCESS`.



## Permission required to execute the technique
Administrator


## Description of the attack
Attackers can extract credentials from LSASS memory by performing a memory dump of the LSASS process. Many methods of dumping LSASS memory require the `SeDebugPrivilege` privilege and use the `WriteMiniDump` function which opens the targeted process using `PROCESS_ALL_ACCESS` permissions.


## Considerations
None.


## False Positives
There are some applications that perform these actions for legitimate purposes. One example is Procmon by Sysinternals.


## Suggested Response Actions
Investigate what triggered the LSASS memory access. Investigate the system for other signs of compromise.


## Detection Blind Spots
Some tools can be modified to change the indicators of compromise by altering the permissions used when the LSASS process is opened.


## References
* https://github.com/analyticsearch/NihilistGuy
* https://downloads.volatilityfoundation.org//omfw/2012/OMFW2012_Gurkok.pdf

---
## Detection

**Language:** Kusto

**Platform:** M365 Security

**Query:**
```C#
let timeframe = 2*1h;
let SeDebugPrivilege = binary_shift_left(1, 20); // Value for SeDebugPrivilege is 2**20 = 0x100000.
let LSASSOpen=materialize (
    DeviceEvents
    | where ingestion_time() >= ago(timeframe)
    | where ActionType == "OpenProcessApiCall"
    | where FileName =~ "lsass.exe"
    | extend AccessRights=parse_json(AdditionalFields).DesiredAccess
    | where AccessRights == 0x1fffff // PROCESS_ALL_ACCESS.
    | summarize by DeviceId, InitiatingProcessId, InitiatingProcessSHA1
);
DeviceEvents
| where ingestion_time() >= ago(timeframe)
| where ActionType == "ProcessPrimaryTokenModified"
| where isnotempty(InitiatingProcessSHA1)
// Look for processes that request debug privilege that also opened LSASS
| where InitiatingProcessSHA1 in ((LSASSOpen | project InitiatingProcessSHA1)) // Speeds up the query.
| lookup kind=inner LSASSOpen on DeviceId, InitiatingProcessSHA1, InitiatingProcessId
// Check that debug privilege is enabled.
| extend AdditionalFields=parse_json(AdditionalFields)
| extend CurrentTokenPrivEnabled = toint(AdditionalFields.CurrentTokenPrivEnabled)
| extend OriginalTokenPrivEnabled = toint(AdditionalFields.OriginalTokenPrivEnabled)
// Value for SeDebugPrivilege is 2**20 = 0x100000.
// Refer to https://downloads.volatilityfoundation.org//omfw/2012/OMFW2012_Gurkok.pdf for numeric values for privileges.
| extend DebugPrivCurrent = binary_and(CurrentTokenPrivEnabled,SeDebugPrivilege) == SeDebugPrivilege
| extend DebugPrivOrig = binary_and(OriginalTokenPrivEnabled,SeDebugPrivilege) == SeDebugPrivilege
// Check for processes that have debug privilege after the event, but did not have it before.
| where not(DebugPrivOrig) and DebugPrivCurrent
| extend CleanCmdLine = parse_command_line(InitiatingProcessCommandLine, "windows")
| where not(InitiatingProcessFileName =~ "tasklist.exe" and CleanCmdLine has_any ("/m", "-m"))
| extend HostName=tostring(split(DeviceName,".")[0]),DnsDomain=iif(DeviceName contains ".", substring(DeviceName, indexof(DeviceName, ".") + 1, strlen(DeviceName)),"")
| project-reorder Timestamp, DeviceId, InitiatingProcessFileName
// Begin environment-specific filter.
// End environment-specific filter.
```

---

## Version History
| Version | Date | Impact | Notes |
|---------|------|--------|------|
| 1.6  | 2025-05-28| minor | Added an entity mapping for Sentinel. |
| 1.5  | 2025-03-21| minor | Additional performance improvement made for very large environments. |
| 1.4  | 2023-05-04| minor | Updated broken URL in documentation. |
| 1.3  | 2022-12-13| minor | Removed records with empty SHA1 to avoid false positives. |
| 1.2  | 2022-11-07| minor | Added extra filters for false positives caused by a specific commandline argument of tasklist. |
| 1.1  | 2022-02-22| minor | Use ingestion_time for event selection and include de-duplication logic. |
| 1.0  | 2022-02-02| major | Initial version. |