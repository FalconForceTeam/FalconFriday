# Possible Defender tampering commands

## Metadata
**ID:** 0xFF-0035-Possible-Defender-tampering-commands-Win

**OS:** WindowsEndpoint, WindowsServer

**FP Rate:** Low

---

## ATT&CK Tags

| Tactic | Technique | Subtechnique | Technique Name |
|---|---|---| --- |
| TA0005 - Defense Evasion | T1562 | 001 | Impair Defenses - Disable or Modify Tools|

## Utilized Data Sources

| Log Provider | Event ID | Event Name | ATT&CK Data Source | ATT&CK Data Component|
|---------|---------|----------|---------|---------|
|MicrosoftThreatProtection|ProcessCreated||Command|Command Execution|
|MicrosoftThreatProtection|PowerShellCommand||Script|Script Execution|
---

## Technical description of the attack
This query combines known process commandlines with DeviceEvents with a specific PowerShell command.

## Permission required to execute the technique
User

## Detection description
Based on FalconForce research on malware behavior, this query looks for the most prevalent commands in malware infections that attempt to bypass Defender or disable it. The commands included in this detection are most frequently used functions in a malware set of over 200.000 samples.


## Considerations
Filtering should be done as exact as possible. Consider including the InitiatingProcessFolderPath, ProcessCommandLine, InitiatingProcessVersionInfoCompanyName and possibly more information where repetitive.


## False Positives
In some cases, for example, installing a different anti-virus product might raise events. Make sure these cases are intentional, since this is also a known technique for evasion.


## Suggested Response Actions
Review the InitiatingProcess and ProcessCommandLine for suspicious paths. Validate with the user whether the action was deliberate.


## Detection Blind Spots
None currently known.


## References
* https://medium.com/falconforce/falconfriday-av-manipulation-0xff0e-67ed4387f9ab?source=friends_link&sk=3c7c499797bbb4d74879e102ef3ecf8f

---
## Detection

**Language:** Kusto

**Platform:** M365 Security

**Query:**
```C#
let timeframe = 2*1h;
let ManipulationCommand=dynamic(["Set-MpPreference","WinDefend","WSCSVC", "security center"]);
let processes=DeviceProcessEvents
| where ingestion_time() >= ago(timeframe)
| where ActionType contains "ProcessCreated"
| where FileName has_any ("powershell", "sc.exe", "net.exe", "net1.exe")
| extend cmdline = parse_command_line(ProcessCommandLine, "windows")
| where cmdline has_any (ManipulationCommand)
| where not(ProcessCommandLine contains "-DisableRealtimeMonitoring $false")
| where not(cmdline contains "WinDefend" and cmdline[array_index_of(cmdline, "WinDefend")-1] in~ ("start", "query")) // Filter out sc (start|query) WinDefend.
| where not(cmdline contains "WSCSVC" and cmdline[array_index_of(cmdline, "WinDefend")-1] in~ ("start", "query")) // Filter out sc (start|query) WSCSVC.
| where not(FileName matches regex @"net\d?\.exe" and cmdline[array_index_of(cmdline, "security center")-1] in~ ("start")); // Filter out net start "security center".
let powershell=DeviceEvents
| where ingestion_time() >= ago(timeframe)
| where ActionType contains "PowerShellCommand" and AdditionalFields contains "Set-MpPreference"
| where not(isempty(InitiatingProcessCommandLine));
union processes,powershell
// Begin environment-specific filter.
// End environment-specific filter.
```

---

## Version History
| Version | Date | Impact | Notes |
|---------|------|--------|------|
| 1.4  | 2024-06-06| minor | Added a filter for "ProcessCreated" actiontype, as MDE is rolling out other actiontypes as well. |
| 1.3  | 2022-02-22| minor | Use ingestion_time for event selection and include de-duplication logic. |
| 1.2  | 2021-03-12| minor | Updated query to be more resilient. |
| 1.1  | 2021-03-11| major | Reworked query a bit and added filters. |
| 1.0  | 2021-02-20| major | Initial version. |