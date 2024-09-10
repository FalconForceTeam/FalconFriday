# Process injection via NtAllocateVirtualMemoryRemote by rare or unsigned processes

## Metadata
**ID:** 0xFF-0086-Process_injection_via_NtAllocateVirtualMemoryRemote_by_rare_or_unsigned_processes-Win

**OS:** WindowsEndpoint, WindowsServer

**FP Rate:** Low

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
|MicrosoftThreatProtection|NtAllocateVirtualMemoryRemoteApiCall||Process|Process Access|
---

## Technical description of the attack
This query searches for unsigned processes with a low GlobalPrevalence that inject into other processes. This technique is commonly used by multiple attacker toolkits.


## Permission required to execute the technique
User

## Detection description
This rule detects the use of the NtAllocateVirtualMemoryRemote API call that is registered by MDE. There is a legitimate use for this. However, when executed by a rare binary which is unsigned as well this should be very uncommon.


## Considerations
Processes can be injected into in various different ways. This detection only focusses on the variant utilizing the NtAllocateVirtualMemoryRemote API call.


## False Positives
None expected.


## Suggested Response Actions
Validate the InitiatingProcessFolderPath and InitiatingProcessFileName and its command-line for known behavior. Investigate the host for other suspicious behavior. A common side signal for this would be a handle to the process with PROCESS_VM_WRITE permissions. Currently, MDE only records this for the lsass.exe process.


## Detection Blind Spots
When the GlobalPrevalence of the used tool is too high this detection will not pick it up. The same is true for software signed with a validated certificate. Additionally, when an attacker injects into a valid signed and common process through another method they will hide in the common signals.


## References

---
## Detection

**Language:** Kusto

**Platform:** M365 Security

**Query:**
```C#
let timeframe = 2*1h;
let default_global_prevalence = 0;
let remoteAlloc = DeviceEvents
| where ingestion_time() >= ago(timeframe)
| where ActionType =~ "NtAllocateVirtualMemoryRemoteApiCall"
| where InitiatingProcessFileName !~ FileName
| where not(isempty(InitiatingProcessSHA1))
// FileProfile is case-sensitive and works on lower-case hashes.
| extend InitiatingProcessSHA1=tolower(InitiatingProcessSHA1)
| summarize count(), make_set(InitiatingProcessFileName) ,make_set(FileName) by InitiatingProcessSHA1
| invoke FileProfile(InitiatingProcessSHA1, 1000)
| where not(ProfileAvailability =~ "Error")
| where (coalesce(GlobalPrevalence,default_global_prevalence) <= 200 or isempty(GlobalPrevalence)) and IsCertificateValid != 1;
DeviceEvents
| where ingestion_time() >= ago(timeframe)
// FileProfile is case-sensitive and works on lower-case hashes.
| extend InitiatingProcessSHA1=tolower(InitiatingProcessSHA1)
| where InitiatingProcessSHA1 in ((remoteAlloc | project InitiatingProcessSHA1)) and ActionType =~ "NtAllocateVirtualMemoryRemoteApiCall"
| join kind=leftouter remoteAlloc on InitiatingProcessSHA1
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