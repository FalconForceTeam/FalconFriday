# Process Injection Initiated By MMC

## Metadata
**ID:** 0xFF-0546-Process_Injection_Initiated_By_MMC-Win

**OS:** WindowsEndpoint, WindowsServer

**FP Rate:** Low

---

## ATT&CK Tags

| Tactic | Technique | Subtechnique | Technique Name |
|---|---|---| --- |
| TA0005 - Defense Evasion | T1218 | 014 | System Binary Proxy Execution - MMC|
| TA0005 - Defense Evasion | T1055 |  | Process Injection|

## Utilized Data Sources

| Log Provider | Event ID | Event Name | ATT&CK Data Source | ATT&CK Data Component|
|---------|---------|----------|---------|---------|
|MicrosoftThreatProtection|QueueUserApcRemoteApiCall||Process|OS API Execution|
|MicrosoftThreatProtection|CreateRemoteThreadApiCall||Process|OS API Execution|
|MicrosoftThreatProtection|NtMapViewOfSectionRemoteApiCall||Process|OS API Execution|
|MicrosoftThreatProtection|MemoryRemoteProtect||Process|Process Access|
|MicrosoftThreatProtection|NtAllocateVirtualMemoryRemoteApiCall||Process|Process Access|
|MicrosoftThreatProtection|ReadProcessMemoryApiCall||Process|Process Access|
|MicrosoftThreatProtection|SetThreadContextRemoteApiCall||Process|Process Access|
---

## Technical description of the attack
This query searches for suspicious behavior initiated by MMC. This is done by looking at a number of actions that are commonly associated with process injection.


## Permission required to execute the technique
User

## Detection description
Attackers are known to use malicious MSC files to deliver payloads to victims. MSC files are Microsoft Management Console (MMC) files that can be used to run administrative tools. Attackers can use MSC files to deliver malicious payloads to victims by tricking them into opening the file. Since a user is likely to close the MMC console after opening the file, attackers may use process injection to ensure that the malicious code continues to run in the background.


## Considerations
None.


## False Positives
Some legitimate MMC snap-ins may perform actions that are similar to process injection. These will require additional filtering.


## Suggested Response Actions
Investigate the MSC file that was loaded by MMC:
* Check if the file is common within the environment.
* Check if the file was recently downloaded or created.
Investigate the machine and user that initiated the alert:
* Check if there are any signs of compromise on the affected machine or user account.


## Detection Blind Spots
Not all process injection techniques can be detected by MDE.


## References
* https://www.elastic.co/security-labs/grimresource

---
## Detection

**Language:** Kusto

**Platform:** M365 Security

**Query:**
```C#
let timeframe = 2*1h;
DeviceEvents
| where ingestion_time() >= ago(timeframe)
| where InitiatingProcessFileName =~ "mmc.exe"
// Look for actions associated with process injection.
| where ActionType in~ ("CreateRemoteThreadApiCall", "MemoryRemoteProtect", "NtAllocateVirtualMemoryRemoteApiCall", "NtMapViewOfSectionRemoteApiCall","ReadProcessMemoryApiCall", "SetThreadContextRemoteApiCall", "QueueUserApcRemoteApiCall")
| extend ParsedCommandLine=parse_command_line(InitiatingProcessCommandLine, "windows")
// When a .msc file is opened in MMC, the file path is passed as an argument to MMC.
// Based on testing this is the first argument in the command line. In some cases a command-line switch /32 is passed as the first argument
// and the file path is the second argument. This is handled by the iif statement below.
| extend MscFile=ParsedCommandLine[1]
| extend MscFile=iif(MscFile startswith "/", ParsedCommandLine[2], MscFile)
// Begin environment-specific filter.
// End environment-specific filter.
```

---

## Version History
| Version | Date | Impact | Notes |
|---------|------|--------|------|
| 1.0  | 2024-06-27| major | Initial version. |