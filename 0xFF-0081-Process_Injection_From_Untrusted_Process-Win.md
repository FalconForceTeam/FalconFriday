# Process Injection From Untrusted Process

## Metadata
**ID:** 0xFF-0081-Process_Injection_From_Untrusted_Process-Win

**OS:** WindowsServer, WindowsEndpoint

**FP Rate:** Medium

---

## ATT&CK Tags

| Tactic | Technique | Subtechnique | Technique Name |
|---|---|---| --- |
| TA0004 - Privilege Escalation | T1055 | 002 | Process Injection - Portable Executable Injection|
| TA0005 - Defense Evasion | T1055 | 002 | Process Injection - Portable Executable Injection|
| TA0002 - Execution | T1106 |  | Native API|

## Utilized Data Sources

| Log Provider | Event ID | Event Name | ATT&CK Data Source | ATT&CK Data Component|
|---------|---------|----------|---------|---------|
|MicrosoftThreatProtection|CreateRemoteThreadApiCall||Process|Process Access|
---

## Technical description of the attack
This query searches for processes performing remote process injection via the CreateRemoteThread API call. It filters out programs that inject into their own process or into a process from the same directory. It then finds suspicious processes based on the global prevalence.


## Permission required to execute the technique
User

## Detection description
This query identifies uncommon binaries performing process injection into other processes.


## Considerations
None.


## False Positives
Some legitimate software uses process injection, for example, when performing debugging.


## Suggested Response Actions
This incident is very hard to investigate without any context. The best approach is to look on the MDE timeline around the time of the injection event to understand what has happened. Generally, when an injection happens from an untrusted process to a trusted process, an attacker is trying to move away from an untrusted process to prevent triggering other detection rules based on prevalence. In case of a process injection, the source binary that performs the injection is the most interesting binary to investigate.


## Detection Blind Spots
There are many different methods to perform process injection. This query only identifies process injection using the CreateRemoteThread method.


## References
* https://medium.com/falconforce/falconfriday-process-injection-and-malicious-cpl-files-0xff03-8ba1ee5da64?source=friends_link&sk=1ed3672c2e7961dac11c1472cb5757e8

---
## Detection

**Language:** Kusto

**Platform:** M365 Security

**Query:**
```C#
let timeframe = 2*1h;
let default_global_prevalence = 0;
let allDeviceEvents = materialize(
DeviceEvents
| where ingestion_time() >= ago(timeframe)
| where ActionType =~ "CreateRemoteThreadApiCall" and ProcessId != InitiatingProcessId
| where not(InitiatingProcessFolderPath startswith FolderPath) // Exclude injection into processes in the same directory.
);
let suspiciousCRTSHA1 = allDeviceEvents
| where not(isempty(InitiatingProcessSHA1)) // Only with a valid SHA1.
| summarize MachineCount=dcount(DeviceId)  by InitiatingProcessSHA1
// Take 1000 of the most unique hashes, as files with high prevalence are very likely to be legitly signed.
| top 1000 by MachineCount asc
// FileProfile is case sensistive and works on lower-case hashes
| extend InitiatingProcessSHA1=tolower(InitiatingProcessSHA1)
| invoke FileProfile(InitiatingProcessSHA1, 1000)
| where not(ProfileAvailability =~ "Error")
| where coalesce(GlobalPrevalence,default_global_prevalence) < 200 or ((isempty(Signer) or not(IsCertificateValid)) and coalesce(GlobalPrevalence,default_global_prevalence) < 500);
let suspiciousCRTSMD5 = allDeviceEvents
// In some rare edge cases, the SHA1 is empty while MD5 is there. Get those as well.
| where isempty(InitiatingProcessSHA1) and isnotempty(InitiatingProcessMD5)
| summarize MachineCount=dcount(DeviceId)  by InitiatingProcessMD5
// Take 1000 of the most unique hashes, as files with high prevalence are very likely to be legitly signed.
| top 1000 by MachineCount asc
// FileProfile is case-sensitive and works on lower-case hashes.
| extend InitiatingProcessMD5=tolower(InitiatingProcessMD5)
| invoke FileProfile(InitiatingProcessMD5, 1000)
| where not(ProfileAvailability =~ "Error")
| where coalesce(GlobalPrevalence,default_global_prevalence) < 200 or ((isempty(Signer) or not(IsCertificateValid)) and coalesce(GlobalPrevalence,default_global_prevalence) < 500);
DeviceEvents
| where ingestion_time() >= ago(timeframe)
| where ActionType =~ "CreateRemoteThreadApiCall" and ProcessId != InitiatingProcessId
| extend InitiatingProcessMD5=tolower(InitiatingProcessMD5), InitiatingProcessSHA1=tolower(InitiatingProcessSHA1)
| where InitiatingProcessSHA1 in~ ((suspiciousCRTSHA1 | project InitiatingProcessSHA1)) or
  InitiatingProcessMD5 in ((suspiciousCRTSMD5 | project InitiatingProcessMD5))
// Work around the Defender limitation where FolderPath for CreateRemoteThreadApiCall does not contain FileName where it does for other events.
| extend InjectionTarget=strcat(FolderPath,@"\",FileName)
// Begin environment-specific filter.
// End environment-specific filter.
| summarize arg_min(Timestamp, *), InjectionTargets=make_set(InjectionTarget) by DeviceId, InitiatingProcessFolderPath // Show only the first invocation per device.
| extend InjectionSource=InitiatingProcessFolderPath, InjectionCommandLine=InitiatingProcessCommandLine
| project-reorder Timestamp, InjectionSource, InjectionCommandLine, InjectionTargets
```

---

## Version History
| Version | Date | Impact | Notes |
|---------|------|--------|------|
| 1.8  | 2024-06-28| minor | Modified the usage of FileProfile to exclude results if the call to the FileProfile API has failed. |
| 1.7  | 2023-01-03| minor | Lowered the case of hashes that are fed to the FileProfile function due to case sensitivity. |
| 1.6  | 2022-11-01| minor | Use default_global_prevalence variable to allow customizing handling of empty GlobalPrevalence |
| 1.5  | 2022-06-28| minor | Fixed a bug which in very rare cases could lead to false negatives. In some edge cases, a DeviceEvent doesn't have a SHA1 for a process, but does have an MD5. This edge case is now handled. |
| 1.4  | 2022-06-24| minor | Fixed a bug which introduced false positives due to empty InitiatingProcessSHA1. |
| 1.3  | 2022-06-24| minor | Added a new jinja variable which can (dis)allow process injections in the same folder. This is useful to disable in a clean environment to reduce the false negative rate. |
| 1.2  | 2022-05-20| minor | Updated the response plan. |
| 1.1  | 2022-02-22| minor | Use ingestion_time for event selection and include de-duplication logic. |
| 1.0  | 2021-01-29| major | Initial version. |