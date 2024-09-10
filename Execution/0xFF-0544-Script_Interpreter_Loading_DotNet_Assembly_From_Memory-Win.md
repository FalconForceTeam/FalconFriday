Note: You are viewing an old, archived version of this content. The latest version is available in the ['main' branch](https://github.com/FalconForceTeam/FalconFriday/blob/main/0xFF-0544-Script_Interpreter_Loading_DotNet_Assembly_From_Memory-Win.md).

# Script Interpreter Loading DotNet Assembly From Memory

## Metadata
**ID:** 0xFF-0544-Script_Interpreter_Loading_DotNet_Assembly_From_Memory-Win

**OS:** WindowsEndpoint, WindowsServer

**FP Rate:** Low

---

## ATT&CK Tags

| Tactic | Technique | Subtechnique | Technique Name |
|---|---|---| --- |
| TA0002 - Execution | T1059 |  | Command and Scripting Interpreter|
| TA0002 - Execution | T1059 | 007 | Command and Scripting Interpreter - JavaScript|
| TA0002 - Execution | T1059 | 005 | Command and Scripting Interpreter - Visual Basic|
| TA0005 - Defense Evasion | T1218 | 005 | System Binary Proxy Execution - Mshta|
| TA0005 - Defense Evasion | T1218 | 014 | System Binary Proxy Execution - MMC|

## Utilized Data Sources

| Log Provider | Event ID | Event Name | ATT&CK Data Source | ATT&CK Data Component|
|---------|---------|----------|---------|---------|
|MicrosoftThreatProtection|ClrUnbackedModuleLoaded||Module|Module Load|
---

## Technical description of the attack
The query searches for script interpreters (mmc.exe, mshta.exe, wscript.exe, and cscript.exe) loading .NET assemblies from memory. In the case of the MMC executable, the query also checks for the MSC file that was loaded, as some legitimate MSC files are known to load .NET assemblies via MMC.


## Permission required to execute the technique
User

## Detection description
Multiple offensive tools exist that allow an attacker to convert a .NET assembly to a script that can be executed by script interpreters. This allows attackers to bypass security controls by executing malicious code without writing it to disk. This technique can be used for initial access by embedding the malicious script in a `.msc` or `.hta` file. These files can contain embedded scripts and are executed when the user opens the file.


## Considerations
None.


## False Positives
Some custom MMC snap-ins may load .NET assemblies, which can trigger this alert.


## Suggested Response Actions
Investigate the .NET assembly that was loaded. The name of this assembly is available in the `DotNetAssemblyName` field of the query output.
* Check if this is a known malicious assembly, such as Rubeus or SharpHound.
* Check if this assembly is loaded from memory on multiple machines.
Investigate the source file that loaded the assembly. This can be observed from the `InitiatingProcessCommandLine` field.
* If the file was recently downloaded, this could indicate a successful initial access attempt.
* Check if the file is known within the environment.
Investigate the machine and user that initiated the alert:
* Check if there are any signs of compromise on the affected machine or user account.


## Detection Blind Spots
Attackers could directly load shellcode or other malicious code using script interpreters without using .NET assemblies.
The detection can by bypassed if an attacker is able to trick a user into launching MMC.exe manually and then opening a malicious .msc file.


## References
* https://www.elastic.co/security-labs/grimresource
* https://github.com/tyranid/DotNetToJScript
* https://github.com/med0x2e/GadgetToJScript

---
## Detection

**Language:** Kusto

**Platform:** M365 Security

**Query:**
```C#
let timeframe = 2*1h;
DeviceEvents
| where ingestion_time() >= ago(timeframe)
| where ActionType == "ClrUnbackedModuleLoaded"
| where InitiatingProcessFileName in~ ("mmc.exe","mshta.exe","wscript.exe","cscript.exe")
| extend DotNetAssemblyName = tostring(parse_json(AdditionalFields).ModuleILPathOrName)
| extend ParsedCommandLine=parse_command_line(InitiatingProcessCommandLine, "windows")
// When a .msc file is opened in MMC, the file path is passed as an argument to MMC.
// Based on testing this is the first argument in the command line. In some cases a command-line switch /32 is passed as the first argument
// and the file path is the second argument. This is handled by the iif statement below.
| extend MscFile=ParsedCommandLine[1]
| extend MscFile=iif(MscFile startswith "/", ParsedCommandLine[2], MscFile)
// Some Microsoft MSC files are known to load .NET assemblies via MMC.
| where not(InitiatingProcessFileName =~ "mmc.exe" and (MscFile startswith @"c:\windows\system32\" or MscFile startswith @"C:\Program Files\Update Services\" or MscFile startswith @"C:\ProgramData\Microsoft\Windows\Start Menu\"))
// Do not alert when MMC is started without any arguments, since in that case it is unknown which MSC file was loaded.
| where not(InitiatingProcessFileName =~ "mmc.exe" and (array_length(ParsedCommandLine) == 1))
// Begin environment-specific filter.
// End environment-specific filter.
```

---

## Version History
| Version | Date | Impact | Notes |
|---------|------|--------|------|
| 1.0  | 2024-06-27| major | Initial version. |