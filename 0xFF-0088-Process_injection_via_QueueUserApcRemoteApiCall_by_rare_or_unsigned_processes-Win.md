# Process injection via QueueUserApcRemoteApiCall by rare or unsigned processes

## Metadata
**ID:** 0xFF-0088-Process_injection_via_QueueUserApcRemoteApiCall_by_rare_or_unsigned_processes-Win

**OS:** WindowsEndpoint, WindowsServer

**FP Rate:** Low

---

## ATT&CK Tags

| Tactic | Technique | Subtechnique | Technique Name |
|---|---|---| --- |
| TA0004 - Privilege Escalation | T1055 | 002 | Process Injection - Portable Executable Injection|
| TA0004 - Privilege Escalation | T1055 | 004 | Process Injection - Asynchronous Procedure Call|
| TA0005 - Defense Evasion | T1055 | 002 | Process Injection - Portable Executable Injection|
| TA0005 - Defense Evasion | T1055 | 004 | Process Injection - Asynchronous Procedure Call|
| TA0002 - Execution | T1106 |  | Native API|

## Utilized Data Sources

| Log Provider | Event ID | Event Name | ATT&CK Data Source | ATT&CK Data Component|
|---------|---------|----------|---------|---------|
|MicrosoftThreatProtection|QueueUserApcRemoteApiCall||Process|Process Access|
---

## Technical description of the attack
This query searches for unsigned processes with a low GlobalPrevalence that inject into other processes. This technique is commonly used by multiple attacker toolkits.


## Permission required to execute the technique
User

## Detection description
This rule detects the use of the QueueUserApcRemoteApiCall API call that is registered by MDE. There is a legitimate use for this. However, when executed by a rare binary which is unsigned as well this should be very uncommon. Also any Office process which uses this API will be flagged by this rule.


## Considerations
Processes can be injected into in various different ways. This detection only focuses on the variant utilizing the QueueUserApcRemoteApiCall API call.


## False Positives
None expected.


## Suggested Response Actions
Validate the InitiatingProcessFolderPath and InitiatingProcessFileName and its commandline for known behavior. Investigate the host for other suspicious behavior. A common side signal for this would be a handle to the process with PROCESS_VM_WRITE permissions. Currently, MDE only records this for the lsass.exe process.


## Detection Blind Spots
The process injection could be coming from
- A DLL started by Rundll32.
- A DLL which is hijacked, running inside a trusted process.
- A COM object which lives inside a trusted process, such as dllhost.exe.
- Using AppInit_DLL to load your malicious DLL inside a trusted process.
- Use shims to load your malicious DLL inside a trusted process.


## References

---
## Detection

**Language:** Kusto

**Platform:** M365 Security

**Query:**
```C#
let timeframe = 2*1h;
let default_global_prevalence = 0;
let QueueUserApcRemote = DeviceEvents
| where ingestion_time() >= ago(timeframe)
| where ActionType =~ "QueueUserApcRemoteApiCall"
| distinct InitiatingProcessSHA1
// FileProfile is case-sensitive and works on lower-case hashes.
| extend InitiatingProcessSHA1=tolower(InitiatingProcessSHA1)
| invoke FileProfile(InitiatingProcessSHA1, 1000)
| where not(ProfileAvailability =~ "Error")
| where coalesce(GlobalPrevalence,default_global_prevalence) < 1000 or isempty(GlobalPrevalence) or SoftwareName startswith "Microsoft Office";
DeviceEvents
| where ingestion_time() >= ago(timeframe)
| where ActionType =~ "QueueUserApcRemoteApiCall"
| where InitiatingProcessSHA1 in~ ((QueueUserApcRemote | project InitiatingProcessSHA1))
| join kind=leftouter QueueUserApcRemote on InitiatingProcessSHA1
// Begin environment-specific filter.
// End environment-specific filter.
```

---

## Version History
| Version | Date | Impact | Notes |
|---------|------|--------|------|
| 1.4  | 2024-06-28| minor | Modified the usage of FileProfile to exclude results if the call to the FileProfile API has failed. |
| 1.3  | 2023-01-03| minor | Lowered the case of hashes that are fed to the FileProfile function due to case sensitivity. |
| 1.2  | 2022-11-01| minor | Use default_global_prevalence variable to allow customizing handling of empty GlobalPrevalence |
| 1.1  | 2022-02-22| minor | Use ingestion_time for event selection and include de-duplication logic. |
| 1.0  | 2021-04-09| major | Initial version. |