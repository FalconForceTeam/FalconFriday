# Suspicious office child process created

## Metadata
**ID:** 0xFF-0069-Suspicious_office_child_process_created-Win

**OS:** WindowsEndpoint, WindowsServer

**FP Rate:** Low

---

## ATT&CK Tags

| Tactic | Technique | Subtechnique | Technique Name |
|---|---|---| --- |
| TA0002 - Execution | T1204 |  | User Execution|

## Utilized Data Sources

| Log Provider | Event ID | Event Name | ATT&CK Data Source | ATT&CK Data Component|
|---------|---------|----------|---------|---------|
|MicrosoftThreatProtection|FileCreated||File|File Creation|
|MicrosoftThreatProtection|ConnectionSuccess||Network Traffic|Network Connection Creation|
|MicrosoftThreatProtection|ProcessCreated||Process|Process Creation|
---

## Technical description of the attack
This query obtains a list of downloaded Office documents (doc, xls, etc.) by looking at files written by commonly used web browsers. It then searches for invocations of an Office program by double-clicking on these files. If these processes spawn an uncommon child process this is reported as suspicious.


## Permission required to execute the technique
User

## Detection description
An Office file which was downloaded, has spawned a child process. This could be behavior often seen from attackers.


## Considerations
None.


## False Positives
Some Office plugins might cause false positives if they change the Office program behavior.


## Suggested Response Actions
Evaluate if the child processes created isn't performing suspicious actions.


## Detection Blind Spots
If the user opens the file in another way than double clicking it, for example, by using 'file, open' in an Office application it will not be detected as a downloaded file.


## References

---
## Detection

**Language:** Kusto

**Platform:** M365 Security

**Query:**
```C#
let timeframe = 2*1d;
let browsers = dynamic(["iexplore.exe", "chrome.exe", "firefox.exe", "msedge.exe"]);
let ext = dynamic([".docm", ".xlsm", ".xls", ".doc", ".pptm", ".ppt"]);
let officeApps = dynamic(["winword.exe", "excel.exe", "powerpnt.exe"]);
let whitelist = dynamic(["MSOSYNC.exe", "splwow64.exe", "csc.exe", "outlook.exe", "AcroRd32.exe", "Acrobat.exe", "explorer.exe", "DW20.exe",
"Microsoft.Mashup.Container.Loader.exe", "Microsoft.Mashup.Container.NetFX40.exe", "WerFault.exe", "CLVIEW.exe", "wermgr.exe"]);
let whitelistedDomains = dynamic([""]);
let binPeriodForSearch = 1h;
let timeDiffFileCreateNetworkEvent = 15; // In seconds. Don't make this more than 15s because of comparison later on.
// List all filecreate events where the filename has a known Office extension which can contain macros.
let fileDownloads = materialize(
  DeviceFileEvents
  | where ingestion_time() >= ago(timeframe)
  // We need to have FileCreated and FileRenamed here because some browsers first download the file under a different name and rename it when it's done.
  // For example, the Chrome .crdownload files are all renamed to the intended name after the download has finished.
  | where ActionType in~ ("FileCreated", "FileRenamed") and InitiatingProcessFileName in~ (browsers) and FileName has_any (ext)
  // We need to do this to limit the search of deviceNetworkEvents. Otherwise, the dataset becomes too big to join in MDE.
  | extend period=bin(Timestamp, binPeriodForSearch)
  // Optimizations to keep MDE happy. Otherwise the database gets too big.
  | project DeviceId, InitiatingProcessFileName, InitiatingProcessId, period, FileName, Timestamp
  // The renames are meant to avoid confusions as there will be a lot of FileNames from different tables.
  | project-rename DeviceFileEvents_InitiatingProcessFileName = InitiatingProcessFileName,
                   DeviceFileEvents_FileName = FileName,
                   DeviceFileEvents_Timestamp = Timestamp
);
// Now we need to find the network event that triggered the the filewrite.
// This is an approximation based on timestamp, deviceid, pid and process name.
let downloadSource = materialize(
  DeviceNetworkEvents
  | where ingestion_time() >= ago(timeframe)
  | where DeviceId in~ ((fileDownloads | project DeviceId)) and RemotePort in (80, 443)
  | extend period=bin(Timestamp, binPeriodForSearch)
  // Exclude allow-listed domains. Here you want to allow-list your internal Sharepoint environment.
  // This can be useful if you want to use this rule for external attacks.
  // There is a trade-off, as an internal attacker might abuse your Sharepoint for malware.
  | where parse_url(RemoteUrl).Host !in~ (whitelistedDomains)
  | lookup kind=inner fileDownloads on DeviceId, InitiatingProcessId, $left.InitiatingProcessFileName == $right.DeviceFileEvents_InitiatingProcessFileName, period
  | extend TimeDiff = datetime_diff('second', Timestamp, DeviceFileEvents_Timestamp)
  // The filecreate and network event should happen within max 15 second of each other.
  | where  -timeDiffFileCreateNetworkEvent < TimeDiff and TimeDiff < timeDiffFileCreateNetworkEvent
  // We're now only interested in the unique filenames of the downloads and the location they're possibly downloaded from.
  | summarize possibelURLs=make_set(RemoteUrl) by DeviceFileEvents_FileName
);
// Final step in tying everything together.
// Find Office applications that create a child process which is in our previously generated list.
// We don't filter on devicename because we want to see all instances of this file being run.
DeviceProcessEvents
| where ingestion_time() >= ago(timeframe)
| where ActionType =~ "ProcessCreated"
| where InitiatingProcessFileName in~ (officeApps) and FileName !in~ (officeApps) and FileName !in~ (whitelist) and FileName !in~ (browsers)
| project-rename DeviceProcessEvents_InitiatingProcessCommandLine = InitiatingProcessCommandLine
| where DeviceProcessEvents_InitiatingProcessCommandLine has_any (( downloadSource | project DeviceFileEvents_FileName))
| where not(FolderPath matches regex @"C:\\Program Files \(x86\)\\TechSmith\\Camtasia Studio \d+\\TscHelp\.exe")
| where not(ProcessCommandLine matches regex @"^""?rundll32""? C:\\WINDOWS\\system32\\spool\\DRIVERS\\((x64)|(x86))\\\d\\hpmsn\d+.((dll)|(DLL)),")
// Verclsid cannot be filtered as it's a LOLBIN which allows creating arbitrary COM objects.
// We can only filter the execution of very specific COM objects.
// Embedded Outlook item in an Office file.
//00020D0B-0000-0000-C000-000000000046 == Outlook 97-2003 Object. 00000112-0000-0000-C000-000000000046 == IOLEInterface 0x5 == CLSCTX_INPROC_SERVER	| CLSCTX_LOCAL_SERVER
| where not(ProcessCommandLine matches regex @"^""?verclsid\.exe""? \/S \/C \{00020D0B-0000-0000-C000-000000000046\} \/I \{00000112-0000-0000-C000-000000000046\} \/X 0x5$")
// Embedded Adobe document in Office file.
| where not(ProcessCommandLine matches regex @"^""?verclsid\.exe""? \/S \/C \{B801CA65-A1FC-11D0-85AD-444553540000\} \/I \{00000112-0000-0000-C000-000000000046\} \/X 0x5$")
// Embedded XML file in Office file.
| where not(ProcessCommandLine matches regex @"^""?verclsid\.exe""? \/S \/C \{48123BC4-99D9-11D1-A6B3-00C04FD91555\} \/I \{00000112-0000-0000-C000-000000000046\} \/X 0x5$")
// Bitmap image.
| where not(ProcessCommandLine matches regex @"^""?verclsid\.exe""? \/S \/C \{D3E34B21-9D75-101A-8C3D-00AA001A1652\} \/I \{00000112-0000-0000-C000-000000000046\} \/X 0x5$")
// ZIP folder.
| where not(ProcessCommandLine matches regex @"^""?verclsid\.exe""? \/S \/C \{E88DCCE0-B7B3-11D1-A9F0-00AA0060FA31\} \/I \{00000112-0000-0000-C000-000000000046\} \/X 0x5$")
// HTML document.
| where not(ProcessCommandLine matches regex @"^""?verclsid\.exe""? \/S \/C \{25336920-03F9-11CF-8FD0-00AA00686F13\} \/I \{00000112-0000-0000-C000-000000000046\} \/X 0x5$")
// FileProfile is case-sensitive and works on lower-case hashes.
| extend SHA1=tolower(SHA1)
| invoke FileProfile(SHA1, 1000)
| where not(FolderPath startswith @"C:\Windows\System32\spool\drivers\" and IsCertificateValid and IsRootSignerMicrosoft) // All drivers signed by Microsoft are trusted.
// Begin environment-specific filter.
// End environment-specific filter.
```

---

## Version History
| Version | Date | Impact | Notes |
|---------|------|--------|------|
| 1.3  | 2024-06-06| minor | Added a filter for "ProcessCreated" actiontype, as MDE is rolling out other actiontypes as well. |
| 1.2  | 2023-01-03| minor | Lowered the case of hashes that are fed to the FileProfile function due to case sensitivity. |
| 1.1  | 2022-02-22| minor | Use ingestion_time for event selection and include de-duplication logic. |
| 1.0  | 2021-02-16| major | Initial version. |