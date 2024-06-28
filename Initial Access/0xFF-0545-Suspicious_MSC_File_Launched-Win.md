# Suspicious MSC File Launched

## Metadata
**ID:** 0xFF-0545-Suspicious_MSC_File_Launched-Win

**OS:** WindowsEndpoint, WindowsServer

**FP Rate:** Low

---

## ATT&CK Tags

| Tactic | Technique | Subtechnique | Technique Name |
|---|---|---| --- |
| TA0005 - Defense Evasion | T1218 | 014 | System Binary Proxy Execution - MMC|
| TA0001 - Initial Access | T1566 |  | Phishing|

## Utilized Data Sources

| Log Provider | Event ID | Event Name | ATT&CK Data Source | ATT&CK Data Component|
|---------|---------|----------|---------|---------|
|MicrosoftThreatProtection|ProcessCreated||Process|Process Creation|
|MicrosoftThreatProtection|FileCreated||File|File Creation|
|MicrosoftThreatProtection|FileRenamed||File|File Creation|
---

## Technical description of the attack
The query searches for suspicious MSC files that are launched on the system. The following types of suspicious files are detected: MSC files downloaded by web browsers, MSC files in the Downloads folder, MSC files extracted from ZIP files, and MSC files with Mark Of The Web (MOTW).


## Permission required to execute the technique
User

## Detection description
Attackers are known to use malicious MSC files to deliver payloads to victims. MSC files are Microsoft Management Console (MMC) files that can be used to run administrative tools. Attackers can use MSC files to deliver malicious payloads to victims by tricking them into opening the file. This use-case aims to detect suspicious MSC files that are launched on the system.


## Considerations
None.


## False Positives
Administrators might share MSC files using SharePoint or other file sharing services. These might have to by filtered out.


## Suggested Response Actions
Investigate the MSC file identified:
* Check the hash of the MSC file, available in the `MscSHA1` field of the query output, against threat intelligence feeds. Check if this is a known file.
* If a Mark of the Web is available via the `FileOriginUrl` field, investigate the source of the file.
Investigate the device and user that initiated the alert:
* Check if there are any signs of compromise on the affected machine or user account.


## Detection Blind Spots
If the time between the MSC file being downloaded and the time it is executed is longer than the query timeframe, the alert might not be triggered.
The detection can by bypassed if an attacker is able to trick a user into launching MMC.exe manually and then opening a malicious .msc file.


## References
* https://www.elastic.co/security-labs/grimresource

---
## Detection

**Language:** Kusto

**Platform:** M365 Security

**Query:**
```C#
let timeframe = 2*1h;
let RegexValidateTempZipPath = @"((?i)[^=|\/]*?AppData\\Local\\Temp\\(7z.........\\|wz....\\|Temp\d{1,3}_\w+)\b[^( ;)|]*)";
let MscRenamedFromCrDownload=(
    DeviceFileEvents
    | where ingestion_time() >= ago(timeframe)
    | where ActionType == "FileRenamed"
    | where FileName endswith ".msc"
    | where PreviousFileName endswith ".crdownload"
    | extend SuspiciousReason="MSC file downloaded by web browser."
);
let MscWrittenByBrowser=(
    DeviceFileEvents
    | where ingestion_time() >= ago(timeframe)
    | where ActionType == "FileRenamed" or ActionType == "FileCreated"
    | where FileName endswith ".msc"
    | where InitiatingProcessFileName in~ ("chrome.exe", "msedge.exe", "brave.exe", "opera.exe", "vivaldi.exe", "iexplore.exe", "msedgewebview2.exe", "firefox.exe")
    | extend SuspiciousReason="MSC file downloaded by web browser."
);
let MscInDownloadsFolder=(
    DeviceFileEvents
    | where ingestion_time() >= ago(timeframe)
    | where ActionType == "FileRenamed" or ActionType == "FileCreated"
    | where FileName endswith ".msc"
    | where FolderPath contains @"\downloads\"
    | extend SuspiciousReason="MSC file downloaded by web browser."
);
let MscDecompressed=(
    DeviceFileEvents
    | where ingestion_time() >= ago(timeframe)
    | where ActionType == "FileRenamed" or ActionType == "FileCreated"
    | where FileName endswith ".msc"
    | where InitiatingProcessFileName in~ ("7zfm.exe", "7zg.exe", "7z.exe", "winzip64.exe", "winrar.exe", "winzip.exe")
    or FolderPath matches regex RegexValidateTempZipPath
    or FolderPath contains @".zip\"
    | extend SuspiciousReason="MSC file extracted from zip file."
);
let MscMOTW=(
    DeviceFileEvents
    | where ingestion_time() >= ago(timeframe)
    | where ActionType == "FileRenamed" or ActionType == "FileCreated"
    | where FileName endswith ".msc"
    | where isnotempty(FileOriginUrl)
    | extend SuspiciousReason="MSC file with Mark Of The Web (MOTW)."
);
let SuspiciousMscFiles=(
    union MscRenamedFromCrDownload, MscWrittenByBrowser, MscInDownloadsFolder, MscDecompressed, MscMOTW
    | distinct FolderPath=tolower(FolderPath), DeviceId, FileOriginUrl, MscSHA1=SHA1, SuspiciousReason, MscCreatedBy=InitiatingProcessFolderPath, MscCreatedByCommandLine=InitiatingProcessCommandLine
);
DeviceProcessEvents
| where ingestion_time() >= ago(timeframe)
| where ActionType == "ProcessCreated"
| where FileName =~ "mmc.exe"
| extend ParsedCommandLine=parse_command_line(ProcessCommandLine, "windows")
// Look for process creations of mmc.exe where the .msc file is on the command-line, indicating that the user clicked on the .msc file.
| where tostring(ParsedCommandLine) contains ".msc"
// When a .msc file is opened in MMC, the file path is passed as an argument to MMC.
// Based on testing this is the first argument in the command line. In some cases a command-line switch /32 is passed as the first argument
// and the file path is the second argument. This is handled by the iif statement below.
| extend MscFile=ParsedCommandLine[1]
| extend MscFile=iif(MscFile startswith "/", ParsedCommandLine[2], MscFile)
| extend MscFile=tolower(MscFile)
| lookup kind=inner SuspiciousMscFiles on DeviceId, $left.MscFile == $right.FolderPath
| project-reorder Timestamp, DeviceId, DeviceName, SuspiciousReason, MscFile,  MscCreatedBy, MscCreatedByCommandLine, MscSHA1
// Begin environment-specific filter.
// End environment-specific filter.
```

---

## Version History
| Version | Date | Impact | Notes |
|---------|------|--------|------|
| 1.0  | 2024-06-27| major | Initial version. |