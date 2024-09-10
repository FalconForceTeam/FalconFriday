Note: You are viewing an old, archived version of this content. The latest version is available in the ['main' branch](https://github.com/FalconForceTeam/FalconFriday/blob/main/hunts/Teams_RCE.md).

# Teams RCE

## Background info
This hunt is originally intended for the RCE released on [this github page](https://github.com/oskarsve/ms-teams-rce). However, as the hunt is very generically looking for child-processes of Teams, it can be used more generically for finding any kind of RCE through Teams, also in the future. 

If you want to use this as a detection rule instead of a hunt, you'd need to fine-tune it a bit more to filter out as many false positives as possible.   


## Description of the hunt
The query looks for any child processes of Teams and excludes all the expected processes. Next, it unions the results with all the child processes of protocolhandler.exe. This is because in some cases, Teams triggers protocolhandler.exe and protocolhandler.exe actually spawns the child process. So the right-side of the union looks for the relation teams.exe->protocolhandler.exe->malicious.exe.


**Query:**
```C#
let allowedProcs = dynamic(["teams.exe", "msedge.exe", "onenote.exe", "firefox.exe", "protocolhandler.exe", "werfault.exe", 
"OneDrive.exe", "winproj.exe", "chrome.exe", "mspub.exe", "outlook.exe", "iexplore.exe", "winword.exe", "excel.exe", "7zG.exe", 
"7zFM.exe", "AcroRd32.exe", "crashpad_handler.exe", "mspaint.exe", "notepad.exe", "PBIDesktop.exe", "Powerpnt.exe", "wermgr.exe", "visio.exe"]);
DeviceProcessEvents
| where InitiatingProcessFileName =~ "teams.exe" 
| where not(FileName in~ (allowedProcs))
| where not(FolderPath matches regex @"[C-Z]:\\Users\\(\w|[\.\-\s])+\\AppData\\Local\\Microsoft\\Teams\\Update.exe") and
        not(FolderPath matches regex @"[C-Z]:\\Users\\(\w|[\.\-\s])+\\AppData\\Local\\SquirrelTemp\\Update.exe") and 
        not(FolderPath matches regex @"[C-E]:\\ProgramData\\(\w+|[\.\-\s])\\SquirrelTemp\\Update\.exe") and //assuming ProgramData is on C, D or E
        not(FolderPath matches regex @"[C-E]:\\ProgramData\\(\w+|[\.\-\s])\\Microsoft\\Teams\\Update\.exe")//assuming ProgramData is on C, D or E
| union 
    (DeviceProcessEvents
    | where InitiatingProcessFileName == "protocolhandler.exe" and InitiatingProcessParentFileName =~ "teams.exe"
    | where FileName !in~ (allowedProcs)
)
```

## Considerations
* The current whitelist of allowed child processes is based on filename only. For production purposes, we'd recommend to use the full-path of the whitelisted executables, instead of only the filename. 

## False Positives
*  Opening a file from Teams triggers a childprocess. 
*  Non-standard browsers (anything else than Chrome, Edge, Firefox, Internet Explorer) are not whitelisted. 
  
## Detection Blind Spots
* In the current query, an attacker can use one of the whitelisted names


## References
*  https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688
*  https://attack.mitre.org/techniques/T1574/002/
  