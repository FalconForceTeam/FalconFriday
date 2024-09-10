# PRT Credential Stealing

## Metadata
**ID:** 0xFF-0175-PRT_Credential_Stealing-Win

**OS:** WindowsEndpoint, WindowsServer

**FP Rate:** Low

---

## ATT&CK Tags

| Tactic | Technique | Subtechnique | Technique Name |
|---|---|---| --- |
| TA0004 - Privilege Escalation | T1134 | 001 | Access Token Manipulation - Token Impersonation/Theft|
| TA0006 - Credential Access | T1003 |  | OS Credential Dumping|
| TA0006 - Credential Access | T1555 |  | Credentials from Password Stores|

## Utilized Data Sources

| Log Provider | Event ID | Event Name | ATT&CK Data Source | ATT&CK Data Component|
|---------|---------|----------|---------|---------|
|MicrosoftThreatProtection|ProcessCreated||Command|Command Execution|
---

## Technical description of the attack
This query detects when `BrowserCore.exe` is accessed by a suspicious process. The `BrowserCore.exe` binary is responsible for allowing browser add-ons to use Single Sign On via Azure AD. This rule detects when an uncommon process interacts with the `BrowserCore.exe` process.


## Permission required to execute the technique
User

## Detection description
When a browser wants to use Single Sign On to AzureAD, it can start the `BrowserCore.exe` process and interact with it via `stdin` and `stdout`. Chrome typically does this through named pipes.


## Considerations
Standard detection triggers on direct interaction with `BrowserCore.exe`. The standard detection can be bypassed by using named pipes, similar to how Chrome interacts with the binary. This rule also triggers on non-direct interaction (e.g., through named pipes).


## False Positives
None expected.


## Suggested Response Actions
In extensive testing, we have not observed any false positives for this rule. When this rule triggers, there is a very high probability that someone is trying to steal an Azure AD Primary Refresh Token. This is typically malicious behavior.


## Detection Blind Spots
Injecting a prevalent process will result in evading this detection rule. However, this is covered by another detection rule. Obtaining the PRT through a COM object will not trigger this event.


## References
* https://dirkjanm.io/abusing-azure-ad-sso-with-the-primary-refresh-token/
* https://o365blog.com/post/prt/
* https://posts.specterops.io/requesting-azure-ad-request-tokens-on-azure-ad-joined-machines-for-browser-sso-2b0409caad30

---
## Detection

**Language:** Kusto

**Platform:** M365 Security

**Query:**
```C#
let timeframe = 2*1h;
let default_global_prevalence = 0;
let lolbins = dynamic(["at.exe", "atbroker.exe", "bash.exe", "bitsadmin.exe", "certreq.exe", "certutil.exe", "cmd.exe", "cmdkey.exe", "cmstp.exe", "control.exe", "csc.exe", "cscript.exe", "desktopimgdownldr.exe", "dfsvc.exe", "diantz.exe", "diskshadow.exe", "dnscmd.exe", "esentutl.exe", "eventvwr.exe", "expand.exe", "extexport.exe", "extrac32.exe", "findstr.exe", "forfiles.exe", "ftp.exe", "gfxdownloadwrapper.exe", "gpscript.exe", "hh.exe", "ie4uinit.exe", "ieexec.exe", "ilasm.exe", "infdefaultinstall.exe", "installutil.exe", "jsc.exe", "makecab.exe", "mavinject.exe", "microsoft.workflow.compiler.exe", "mmc.exe", "mpcmdrun.exe", "msbuild.exe", "msconfig.exe", "msdt.exe", "mshta.exe", "msiexec.exe", "netsh.exe", "odbcconf.exe", "pcalua.exe", "pcwrun.exe", "pktmon.exe", "presentationhost.exe", "print.exe", "psr.exe", "rasautou.exe", "reg.exe", "regasm.exe", "regedit.exe", "regini.exe", "register-cimprovider.exe", "regsvcs.exe", "regsvr32.exe", "replace.exe", "rpcping.exe", "rundll32.exe", "runonce.exe", "runscripthelper.exe", "sc.exe", "schtasks.exe", "scriptrunner.exe", "syncappvpublishingserver.exe", "ttdinject.exe", "tttracer.exe", "vbc.exe", "verclsid.exe", "wab.exe", "wmic.exe", "wscript.exe", "wsreset.exe", "xwizard.exe", "agentexecutor.exe", "appvlp.exe", "bginfo.exe", "cdb.exe", "csi.exe", "devtoolslauncher.exe", "dnx.exe", "dotnet.exe", "dxcap.exe", "excel.exe", "mftrace.exe", "msdeploy.exe", "msxsl.exe", "ntdsutil.exe", "powerpnt.exe", "rcsi.exe", "sqldumper.exe", "sqlps.exe", "sqltoolsps.exe", "squirrel.exe", "te.exe", "tracker.exe", "vsjitdebugger.exe", "winword.exe", "wsl.exe", "powershell.exe", "pwsh.exe"]);
// Adding services.exe and svchost.exe to the list of LOLBINs since these can be abused to start cmd.exe and talk to browsercore.
let extendedLolbins = array_concat(lolbins, dynamic(["services.exe", "svchost.exe"]));
let trustedProcess = dynamic(["chrome.exe", "teams.exe"]);
let trustedProcessHashes = materialize(DeviceProcessEvents | where ActionType =~ "ProcessCreated" |  where FileName in~ (trustedProcess) | distinct SHA1);
let suspiciousHashes = materialize(trustedProcessHashes | extend SHA1=tolower(SHA1) | invoke FileProfile(SHA1, 1000) | where not(ProfileAvailability =~ "Error") | where coalesce(GlobalPrevalence,default_global_prevalence) < 200 or isempty(GlobalPrevalence));
let allBrowserCores = DeviceProcessEvents
| where ingestion_time() >= ago(timeframe)
| where ActionType =~ "ProcessCreated"
| where ProcessVersionInfoOriginalFileName =~ "BrowserCore.exe";
allBrowserCores
// FileProfile is case-sensitive and works on lower-case hashes.
| extend SHA1=tolower(SHA1)
// We need the grandparent SHA1, since the normal execution hierarchy is chrome->cmd->browsercore.exe (or similar with Teams).
| join kind = leftouter (DeviceProcessEvents | where ActionType =~ "ProcessCreated" | where FileName in~ ((allBrowserCores | project InitiatingProcessParentFileName))) on $left.InitiatingProcessParentId == $right.ProcessId, DeviceId, $left.InitiatingProcessParentFileName == $right.FileName
// Filter grandparent.
| extend GrandParentFileSHA1 = SHA11 // Renaming SHA1 to GrandParentFileSHA1 for future readability.
| where GrandParentFileSHA1 in~ (suspiciousHashes) or InitiatingProcessParentFileName !in~ (trustedProcess)
// Filter parent.
| where InitiatingProcessSHA1 in~ (suspiciousHashes) or InitiatingProcessFileName !in~ (trustedProcess)
// Removing empty GrandParentFileSHA1 hashes since sometimes the process start event is not logged and hence GrandParentFileSHA1 is empty.
// This contaminates the results. A future improvement would be to check if the trusted process we're looking
// for is logged as parent (instead of as child).
| where not(isempty(GrandParentFileSHA1))
| invoke FileProfile(GrandParentFileSHA1, 1000)
| where not(ProfileAvailability =~ "Error")
| where coalesce(GlobalPrevalence,default_global_prevalence) < 200 or isempty(GlobalPrevalence) or InitiatingProcessParentFileName in~ (extendedLolbins)
// Begin environment-specific filter.
// End environment-specific filter.
```

---

## Version History
| Version | Date | Impact | Notes |
|---------|------|--------|------|
| 2.5  | 2024-06-28| minor | Modified the usage of FileProfile to exclude results if the call to the FileProfile API has failed. |
| 2.4  | 2024-06-06| minor | Added a filter for "ProcessCreated" actiontype, as MDE is rolling out other actiontypes as well. |
| 2.3  | 2023-01-03| minor | Lowered the case of hashes that are fed to the FileProfile function due to case sensitivity. |
| 2.2  | 2022-11-01| minor | Use default_global_prevalence variable to allow customizing handling of empty GlobalPrevalence |
| 2.1  | 2022-02-22| minor | Use ingestion_time for event selection and include de-duplication logic. |
| 2.0  | 2021-11-15| major | Optimized the query for increased performance on large datasets. |
| 1.2  | 2021-10-29| minor | Fixed typo in timestamp. |
| 1.1  | 2021-09-29| minor | Extended the LOLBINs to cover the case where a service or scheduled task is used to talk to browsercore. |
| 1.0  | 2021-09-29| major | Initial version. |