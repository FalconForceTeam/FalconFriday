# Azure AD UserAgent OS Missmatch

## Metadata
**ID:** 0xFF-0061-Azure_AD_UserAgent_OS_Missmatch

**OS:** N/A

---

## ATT&CK Tags

| Tactic | Technique | Subtechnique | Technique Name |
|---|---|---| --- |
| TA0005 - Defense Evasion | T1036 |  | Masquerading|

## Utilized Data Sources

| Log Provider | Table Name | Event ID | Event Name | ATT&CK Data Source | ATT&CK Data Component|
|---------|---------|---------|----------|---------|---------|
|AzureActiveDirectory|SigninLogs|Sign-in activity||Logon Session|Logon Session Metadata|
|AzureActiveDirectory|AADNonInteractiveUserSignInLogs|Sign-in activity||Logon Session|Logon Session Metadata|
---

## Detection description
This query extracts the operating system from the UserAgent header and compares this to the DeviceDetail information present in Azure Active Directory.



## Permission required to execute the technique
User


## Description of the attack
An attacker might be able to steal an access token for a particular device and use that to use Azure AD applications on another device, bypassing certain restrictions.


## Considerations
None.


## False Positives
Users might use a plugin to hide their true UserAgent. This might lead to false positives. Also, there are some applications that incorrectly report the OS in the UserAgent header, for example, Mobile Safari when using the 'request desktop site' feature.


## Suggested Response Actions
Verify with the user whether there is a legitimate reason for using this particular UserAgent in combination with the application.


## Detection Blind Spots
If the attacker fully mimics the UserAgent of the actual application this rule will not be able to detect it.


## References

---
## Detection

**Language:** Kusto

**Platform:** Sentinel

**Query:**
```C#
let timeframe = 2*1d;
let RuleId = "0061";
let DedupFields = dynamic(["TimeGenerated"]);
let ExtractOSFromUA=(ua:string) {
    case(
        ua contains "Windows NT 6.0", "Windows Vista/Windows Server 2008",
        ua contains "Windows NT 6.1", "Windows 7/Windows Server 2008R2",
        ua contains "Windows NT 6.1", "Windows 7/Windows Server 2008",
        ua contains "Windows NT 6.2", "Windows 8/Windows Server 2012",
        ua contains "Windows NT 6.3", "Windows 8.1/Windows Server 2012R2",
        ua contains "Windows NT 10.0", "Windows 10",
        ua contains "Windows Phone", "WindowsPhone",
        ua contains "Android", "Android",
        ua contains "iPhone;", "IOS",
        ua contains "iPad;", "IOS",
        ua contains "Polycom/", "Polycom",
        ua contains "Darwin/", "MacOS",
        ua contains "Mac OS X", "MacOS",
        ua contains "macOS", "MacOS",
        ua contains "ubuntu", "Linux",
        ua contains "Linux", "Linux",
        ua contains "curl", "CLI",
        ua contains "python", "CLI",
        "Unknown"
    )
};
// Query to obtain 'simplified' user agents in a given timespan.
union withsource=tbl_name AADNonInteractiveUserSignInLogs, SigninLogs
| where ingestion_time() >= ago(timeframe)
| extend UserAgentOS=tolower(ExtractOSFromUA(UserAgent))
| where not(isempty(UserAgent))
| where not(isempty(AppId))
| where ResultType == 0
| extend DeviceOS=tolower(DeviceDetail_dynamic.operatingSystem)
| where not(isempty(DeviceOS))
| where not(UserAgentOS =~ "unknown")
// Look for matches both ways, since sometimes the browser OS is more specific and sometimes the DeviceOS is more specific.
| where not(UserAgentOS contains DeviceOS) and not(DeviceOS contains UserAgentOS)
// In some cases UserAgentOS or DeviceOS can contain spaces and the comparison will fail. Remove spaces to avoid false positives.
| where not(replace_string(UserAgentOS," ","") contains replace_string(DeviceOS," ","")) and not(replace_string(DeviceOS," ","") contains replace_string(UserAgentOS," ",""))
| where not(DeviceOS =~ "ios" and UserAgentOS =~ "macos") // This can happen for 'request desktop site'.
| where not(DeviceOS =~ "android" and UserAgentOS =~ "linux") // Android and Linux are sometimes confused.
| summarize count(), arg_min(TimeGenerated,*) by DeviceOS, UserAgentOS, UserPrincipalName
// Begin environment-specific filter.
// End environment-specific filter.
// Begin de-duplication logic.
| extend DedupFieldValues=pack_all()
| mv-apply e=DedupFields to typeof(string) on (
    extend DedupValue=DedupFieldValues[tostring(e)]
    | order by e // Sorting is required to ensure make_list is deterministic.
    | summarize DedupValues=make_list(DedupValue)
)
| extend DedupEntity=strcat_array(DedupValues, "|")
| project-away DedupFieldValues, DedupValues
| join kind=leftanti (
    SecurityAlert
    | where AlertName has RuleId and ProviderName has "ASI"
    | where TimeGenerated >= ago(timeframe)
    | extend DedupEntity = tostring(parse_json(tostring(parse_json(ExtendedProperties)["Custom Details"])).DedupEntity[0])
    | project DedupEntity
) on DedupEntity
// End de-duplication logic.
```

---

## Version History
| Version | Date | Impact | Notes |
|---------|------|--------|------|
| 1.3  | 2024-03-04| minor | Removed spaces when comparing UserAgentOS and DeviceOS to avoid false positives. |
| 1.2  | 2022-08-26| minor | Entity mapping added. |
| 1.1  | 2022-02-22| minor | Use ingestion_time for event selection and include de-duplication logic. |
| 1.0  | 2021-03-12| major | Initial version. |