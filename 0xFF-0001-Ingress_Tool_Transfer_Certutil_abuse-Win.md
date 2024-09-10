# Ingress Tool Transfer - Certutil abuse

## Metadata
**ID:** 0xFF-0001-Ingress_Tool_Transfer_Certutil_abuse-Win

**OS:** WindowsEndpoint, WindowsServer

**FP Rate:** Low

---

## ATT&CK Tags

| Tactic | Technique | Subtechnique | Technique Name |
|---|---|---| --- |
| TA0011 - Command and Control | T1105 |  | Ingress Tool Transfer|

## Utilized Data Sources

| Log Provider | Event ID | Event Name | ATT&CK Data Source | ATT&CK Data Component|
|---------|---------|----------|---------|---------|
|MicrosoftThreatProtection|ProcessCreated||Command|Command Execution|
---

## Technical description of the attack
This query searches for invocations of certutil, including renamed versions with specific command line parameters that indicate using certutil as a tool to download files.


## Permission required to execute the technique
User

## Detection description
Certutil is a very commonly abused tool to download or execute malware.


## Considerations
N/A.


## False Positives
Some legitimate use of certutil to download files is expected. However, this should be relatively rare.


## Suggested Response Actions
Contact the user to verify if certutil usage was legitimate, or - if not - may have been part of an attack.


## Detection Blind Spots
An attacker might be able to further obfuscate the command line parameters of certutil to avoid detection.


## References
* https://medium.com/falconforce/falconfriday-detecting-certutil-and-suspicious-code-compilation-0xff02-cfe8fb5e159e
* https://lolbas-project.github.io/lolbas/Binaries/Certutil/

---
## Detection

**Language:** Kusto

**Platform:** M365 Security

**Query:**
```C#
// Set the timespan for the query.
let timeframe = 2*1h;
DeviceProcessEvents
| where ingestion_time() >= ago(timeframe)
| where ActionType =~ "ProcessCreated"
// Get all executions by processes with a SHA1 hash that is or was named certutil.
| where FileName =~ "certutil.exe" or ProcessVersionInfoOriginalFileName =~ "certutil.exe"
// Create a new field called CleanProcessCommandLine which gets populated with the value of ProcessCommandLine as Windows parses it for execution,
// removing any potential command line obfuscation.
| extend CleanProcessCommandLine=parse_command_line(ProcessCommandLine, "windows")
// Search for de-obfuscated commands used.
| where CleanProcessCommandLine has_any ("decode", "encode", "verify","url")
// Urlcache is the documented attribute, only url is also accepted.
// Verifyctl is the documented attribute, only verify is also accepted.
// Filter Defender deployment.
| where ProcessCommandLine !contains @"C:\Temp\MDATPDeploy\MDATPClientAnalyzer\Tools\winatp.cer"
| where not(ProcessCommandLine contains "-verify" and (ProcessCommandLine endswith ".cer" or ProcessCommandLine endswith ".cer\""))
// Begin environment-specific filter.
// End environment-specific filter.
| order by Timestamp
//| project Timestamp, CleanProcessCommandLine, ProcessCommandLine, SHA1
```

---

## Version History
| Version | Date | Impact | Notes |
|---------|------|--------|------|
| 2.2  | 2023-06-23| minor | Removed match on ProcessCommandLine to avoid false-positives. |
| 2.1  | 2022-02-22| minor | Use ingestion_time for event selection and include de-duplication logic. |
| 2.0  | 2021-02-25| major | Rewritten to use ProcessVersionInfoOriginalFileName instead of a list of hashes. |
| 1.0  | 2021-02-16| major | Initial version. |