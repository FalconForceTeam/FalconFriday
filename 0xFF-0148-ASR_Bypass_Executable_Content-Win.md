# ASR Bypass Executable Content

## Metadata
**ID:** 0xFF-0148-ASR_Bypass_Executable_Content-Win

**OS:** WindowsEndpoint

---

## ATT&CK Tags

| Tactic | Technique | Subtechnique | Technique Name |
|---|---|---| --- |
| TA0002 - Execution | T1204 | 002 | User Execution - Malicious File|
| TA0005 - Defense Evasion | T1036 |  | Masquerading|

## Utilized Data Sources

| Log Provider | Table Name | Event ID | Event Name | ATT&CK Data Source | ATT&CK Data Component|
|---------|---------|---------|----------|---------|---------|
|MicrosoftThreatProtection|DeviceFileEvents|FileCreated||File|File Creation|
---

## Detection description
There is an ASR rule that detects whenever an Office application writes an executable file to disk. There is a documented bypass for this rule, which allows an attacker to write the file to disk with a benign extension (e.g., .txt or .tmp) and rename the file afterwards. This query tries to detect such behavior.



## Permission required to execute the technique
User


## Description of the attack
The ASR rule `Block Office applications from creating executable content` with GUID `3B576869-A4EC-4529-8536-B80A7769E899` is meant to prevent Office applications from dropping potentially malicious files on disk. Dropping a file on disk might in certain conditions be enough to get it executed.


## Considerations
This ASR bypass only works for non-binary files.


## False Positives
We have observed very little false positives for this behavior.


## Suggested Response Actions
Obtain a copy of the file written and verify its contents for malicious behavior. In our testing, this query provides almost no false positives. Renaming of a file from a non-executable extension to an executable extension by an Office application is almost always an ASR bypass, potentially with malicious purposes.


## Detection Blind Spots
The .lnk extension is left out of this query as "executable content" since it generates many false positives, as Office applications create .lnk files all the time.


## References
* https://blog.sevagas.com/IMG/pdf/bypass_windows_defender_attack_surface_reduction.pdf

---
## Detection

**Language:** Kusto

**Platform:** M365 Security

**Query:**
```C#
let timeframe = 2*1h;
let default_global_prevalence = 0;
let executableExtensions = dynamic([".js", ".hta", ".vb", ".vba", ".vbs", ".ps", ".ps1", ".bat", ".cmd", ".lnk", ".application"]);
DeviceFileEvents
| where ingestion_time() >= ago(timeframe)
| where InitiatingProcessFileName in~ ("winword.exe", "excel.exe", "outlook.exe", "powerpnt.exe")
| where ActionType =~ "FileRenamed"
| where FileName has_any(executableExtensions)
| extend MatchExt = executableExtensions[has_any_index(FileName ,executableExtensions)]
| where iff (isempty(PreviousFileName) ,true, PreviousFileName !endswith MatchExt)
// There is some Office feature which triggers a behavior where a .tmp file with "~ew shortcut.tmp" is created
// and then renamed to New Shortcut.lnk. However, since the filename is localized to the local Windows version, we can't use
// the English names for New Shortcut and we have to do the string magic below to replace the first char with an ~ and the .lnk with .tmp.
| where not(strcat("~", replace_string(substring(FileName, 1), ".lnk", ".tmp")) =~ PreviousFileName)
| mv-apply ext=executableExtensions to typeof(string) on
(
    where  FileName endswith ext
)
| project-reorder PreviousFileName, FileName
// FileProfile is case-sensitive and works on lower-case hashes.
| extend SHA1=tolower(SHA1)
| invoke FileProfile(SHA1, 1000)
| where not(ProfileAvailability =~ "Error")
| where coalesce(GlobalPrevalence,default_global_prevalence) < 500
// Begin environment-specific filter.
// End environment-specific filter.
```

---

## Version History
| Version | Date | Impact | Notes |
|---------|------|--------|------|
| 1.9  | 2024-06-28| minor | Modified the usage of FileProfile to exclude results if the call to the FileProfile API has failed. |
| 1.8  | 2023-03-27| minor | Performance update. |
| 1.7  | 2023-01-30| minor | Updated wording to improve clarity of documentation. |
| 1.6  | 2023-01-03| minor | Lowered the case of hashes that are fed to the FileProfile function due to case sensitivity. |
| 1.5  | 2022-11-01| minor | Use default_global_prevalence variable to allow customizing handling of empty GlobalPrevalence |
| 1.4  | 2022-07-25| minor | Added new exception rule for newly observed Office behavior |
| 1.3  | 2022-02-22| minor | Use ingestion_time for event selection and include de-duplication logic. |
| 1.2  | 2021-09-09| minor | Removed binary formats from the extension list as these are detected by ASR anyway and result in unnecessary false positives. |
| 1.1  | 2021-08-24| minor | Update MITRE tags. |
| 1.0  | 2021-04-07| major | Initial version. |