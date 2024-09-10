Note: You are viewing an old, archived version of this content. The latest version is available in the ['main' branch](https://github.com/FalconForceTeam/FalconFriday/blob/main/0xFF-0488-ADWS_Connection_from_Process_Injection_Target-Win.md).

# AWDS Connection from Process Injection Target

## Metadata
**ID:** ADWS_Connection_from_Process_Injection_Target-Win

**OS:** WindowsEndpoint, WindowsServer

**FP Rate:** Medium

---

## ATT&CK Tags

| Tactic | Technique | Subtechnique | Technique Name |
|---|---|---| --- |
| TA0009 - Collection | T1119 |  | Automated Collection|
| TA0007 - Discovery | T1087 | 002 | Account Discovery - Domain Account|
| TA0005 - Defense Evasion | T1055 | 002 | Process Injection - Portable Executable Injection|

## Utilized Data Sources

| Log Provider | Event ID | Event Name | ATT&CK Data Source | ATT&CK Data Component|
|---------|---------|----------|---------|---------|
|MicrosoftThreatProtection|ConnectionSuccess||Network Traffic|Network Connection Creation|
|MicrosoftThreatProtection|CreateRemoteThreadApiCall||Process|Process Access|
|MicrosoftThreatProtection|MemoryRemoteProtect||Process|Process Access|
|MicrosoftThreatProtection|NtAllocateVirtualMemoryApiCall||Process|Process Access|
|MicrosoftThreatProtection|NtAllocateVirtualMemoryRemoteApiCall||Process|Process Access|
|MicrosoftThreatProtection|NtMapViewOfSectionRemoteApiCall||Process|Process Access|
|MicrosoftThreatProtection|SetThreadContextRemoteApiCall||Process|Process Access|
|MicrosoftThreatProtection|QueueUserApcRemoteApiCall||Process|Process Access|
---

## Technical description of the attack
The query first collects all network connections to the Active Directory Web Services (ADWS) service. It then searches for processes that inject into a process that makes a connection to ADWS. This can be used to detect process injection into a process that is used to query Active Directory.


## Permission required to execute the technique
User

## Detection description
ADWS is a Windows service that allows Active Directory to be queried via a web service. While this service is not
malicious by itself, it can be used by attackers to query Active Directory from compromised machines. An attacker
might inject code into a legitimate process and use that process to connect to ADWS.


## Considerations
None.


## False Positives
None expected.


## Suggested Response Actions
Investigate the suspicious connection:
* Is the process that made the connection expected to connect to ADWS?
* Are there any other signs of compromise on the affected machine?


## Detection Blind Spots
This detection will only detect the ADWS connection if it is combined with process injection. If the attacker uses a different method to connect to ADWS, this detection will not trigger.


## References
* https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/dd391908(v=ws.10)

---
## Detection

**Language:** Kusto

**Platform:** M365 Security

**Query:**
```C#
let timeframe = 2*1h;
let ADWSConnections=(
    DeviceNetworkEvents
    | where ingestion_time() >= ago(timeframe)
    | where ActionType == "ConnectionSuccess"
    | where RemotePort == 9389
    | extend InitiatingProcessFileName=tolower(InitiatingProcessFileName)
);
let ADWSFileNames=materialize(
    ADWSConnections
    | distinct InitiatingProcessFileName
);
// Look for processes that inject into a process that makes an ADWS connection.
let InjectorProcesses=materialize(
    DeviceEvents
    | where ingestion_time() >= ago(timeframe)
    | where not(isempty(FileName))
    // Look for actions associated with process injection.
    | where ActionType in~ ("CreateRemoteThreadApiCall", "MemoryRemoteProtect","NtAllocateVirtualMemoryApiCall", "NtAllocateVirtualMemoryRemoteApiCall", "NtMapViewOfSectionRemoteApiCall", "NtProtectVirtualMemoryApiCall", "SetThreadContextRemoteApiCall", "QueueUserApcRemoteApiCall")
    | where FileName in~ (ADWSFileNames)
    | where not(InitiatingProcessFolderPath startswith @"c:\program files\vmware\vmware tools" and InitiatingProcessFileName =~ "vmtoolsd.exe")
    | where not(InitiatingProcessFolderPath =~ @"C:\Windows\System32" and InitiatingProcessFileName =~ "csrss.exe")
    | where not(InitiatingProcessFolderPath =~ @"C:\Windows\System32\csrss.exe")
    | where not(InitiatingProcessFolderPath startswith @"c:\program files\microsoft azure ad sync\" and InitiatingProcessFileName =~ "miiserver.exe")
    | extend FileName=tolower(FileName)
    | lookup kind=inner ADWSConnections on DeviceId, $left.ProcessId == $right.InitiatingProcessId, $left.FileName == $right.InitiatingProcessFileName
    // Begin environment-specific filter.
    // End environment-specific filter.
    | project DeviceId, ProcessId, FileName, InjectorProcessId=InitiatingProcessId, InjectorFileName=InitiatingProcessFileName, InjectorActionType=ActionType
);
// Find ADWS connections from processes that were injected into by another process.
ADWSConnections
| lookup kind=inner InjectorProcesses on DeviceId, $left.InitiatingProcessId == $right.ProcessId, $left.InitiatingProcessFileName == $right.FileName
| summarize arg_min(Timestamp,*), InjectionMethods=make_set(InjectorActionType) by DeviceId, DeviceName, InitiatingProcessId, InitiatingProcessFileName
// Begin environment-specific filter.
// End environment-specific filter.
```

---

## Version History
| Version | Date | Impact | Notes |
|---------|------|--------|------|
| 1.1  | 2024-01-15| minor | Publish this as part of new FalconFriday blog. |
| 1.0  | 2023-11-27| major | Initial version. |