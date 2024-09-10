# Likely lateral movement with SharpRDP

## Metadata
**ID:** 0xFF-0039-Likely_lateral_movement_with_SharpRDP-Win

**OS:** WindowsEndpoint, WindowsServer

**FP Rate:** Medium

---

## ATT&CK Tags

| Tactic | Technique | Subtechnique | Technique Name |
|---|---|---| --- |
| TA0008 - Lateral Movement | T1021 | 001 | Remote Services - Remote Desktop Protocol|

## Utilized Data Sources

| Log Provider | Event ID | Event Name | ATT&CK Data Source | ATT&CK Data Component|
|---------|---------|----------|---------|---------|
|MicrosoftThreatProtection|ProcessCreated||Command|Command Execution|
|MicrosoftThreatProtection|LogonSuccess||Logon Session|Logon Session Creation|
---

## Technical description of the attack
This query searches for child processes created by taskmgr, where taskmgr was not invoked interactively using /1,/2/,3 or /4.


## Permission required to execute the technique
User

## Detection description
SharpRDP is an attack tool that allows attackers to perform remote command execution through RDP without the need to have real-time manual interaction by simulating keystrokes on the target system. This allows an attacker to (asynchronously) run the binary on an already compromised system, which in turn will connect to the target system and execute a set of keystrokes.


## Considerations
N/A.


## False Positives
This query will also trigger if the user manually uses taskmgr to run a command directly after logging in via RDP.


## Suggested Response Actions
Contact the user and verify if they used RDP to log in to the remote system and execute the specific command.


## Detection Blind Spots
SharpRDP contains multiple techniques to launch a command. This query only detects the 'taskmgr' method of launching commands.


## References
* https://posts.specterops.io/revisiting-remote-desktop-lateral-movement-8fb905cb46c3

---
## Detection

**Language:** Kusto

**Platform:** M365 Security

**Query:**
```C#
let timeframe = 2*1h;
let executions = DeviceProcessEvents
| where ingestion_time() >= ago(timeframe)
| where ActionType =~ "ProcessCreated"
| where InitiatingProcessFileName contains "taskmgr"
// Begin environment-specific filter.
// End environment-specific filter.
| where not(InitiatingProcessCommandLine has_any ("/1","/2","/3","/4"))
| where not(FolderPath =~ @"c:\Windows\system32\WerFault.exe" and ProcessCommandLine contains "-u -p")
| where not(FolderPath =~ @"c:\windows\system32\mmc.exe" and ProcessCommandLine contains @"C:\WINDOWS\System32\services.msc")
| where not(FolderPath =~ @"c:\windows\system32\resmon.exe");
executions
| join kind=leftsemi  (DeviceLogonEvents
| where LogonType in~ ('Unlock', 'RemoteInteractive') and not (LogonType =~ 'Unlock' and RemoteIP == '127.0.0.1') and RemoteIP != "" and ActionType =~ "LogonSuccess") on DeviceId, LogonId
```

---

## Version History
| Version | Date | Impact | Notes |
|---------|------|--------|------|
| 1.2  | 2024-06-06| minor | Added a filter for "ProcessCreated" actiontype, as MDE is rolling out other actiontypes as well. |
| 1.1  | 2022-02-22| minor | Use ingestion_time for event selection and include de-duplication logic. |
| 1.0  | 2021-02-25| major | Initial version. |