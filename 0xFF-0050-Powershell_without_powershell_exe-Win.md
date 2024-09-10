# PowerShell without powershell.exe

## Metadata
**ID:** 0xFF-0050-Powershell_without_powershell_exe-Win

**OS:** WindowsEndpoint, WindowsServer

**FP Rate:** Medium

---

## ATT&CK Tags

| Tactic | Technique | Subtechnique | Technique Name |
|---|---|---| --- |
| TA0002 - Execution | T1059 | 001 | Command and Scripting Interpreter - PowerShell|

## Utilized Data Sources

| Log Provider | Event ID | Event Name | ATT&CK Data Source | ATT&CK Data Component|
|---------|---------|----------|---------|---------|
|MicrosoftThreatProtection|ImageLoaded||Module|Module Load|
---

## Technical description of the attack
This query detects the use of PowerShell through "system.management.automation.dll" which is invoked by a process with a low global prevalence (i.e., fairly unique binary).


## Permission required to execute the technique
User

## Detection description
Attackers often use PowerShell to execute malicious payloads. The usage of PowerShell can be obfuscated by not using powershell.exe directly, but instead using the "system.management.automation.dll" which implements the PowerShell run-time. When this alert triggers it might indicate a user is using PowerShell while attempting to hide from detection.


## Considerations
None.


## False Positives
Many legitimate programs will use the "system.management.automation.dll". This might lead to false positives that require filtering.


## Suggested Response Actions
None.


## Detection Blind Spots
If an attacker injects into a process that is allow-listed this could be used to avoid detection.


## References

---
## Detection

**Language:** Kusto

**Platform:** M365 Security

**Query:**
```C#
let timeframe = 2*1h;
let default_global_prevalence = 0;
let suspiciousProcs = materialize(
DeviceImageLoadEvents
| where FileName =~ "system.management.automation.dll" or FileName =~ "system.management.automation.ni.dll" and not(isempty(InitiatingProcessSHA1))
| summarize count() by InitiatingProcessSHA1
// FileProfile is case-sensitive and works on lower-case hashes.
| extend InitiatingProcessSHA1=tolower(InitiatingProcessSHA1)
| invoke FileProfile(InitiatingProcessSHA1, 1000)
| where not(ProfileAvailability =~ "Error")
| where not(IsRootSignerMicrosoft) and not(isempty(IsCertificateValid))
| where (IsCertificateValid and coalesce(GlobalPrevalence,default_global_prevalence) < 200) or (not(IsCertificateValid) and coalesce(GlobalPrevalence,default_global_prevalence) < 500));
DeviceImageLoadEvents
| where ingestion_time() >= ago(timeframe)
// FileProfile is case-sensitive and works on lower-case hashes.
| extend InitiatingProcessSHA1=tolower(InitiatingProcessSHA1)
| where InitiatingProcessSHA1 in~ ((suspiciousProcs | project InitiatingProcessSHA1)) and FileName startswith "System.Management.Automation"
| join kind=inner suspiciousProcs on InitiatingProcessSHA1
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
| 1.0  | 2021-02-26| major | Initial version. |