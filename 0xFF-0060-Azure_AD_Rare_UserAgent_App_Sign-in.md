# Azure AD Rare UserAgent App Sign-in

## Metadata
**ID:** 0xFF-0060-Azure_AD_Rare_UserAgent_App_Sign-in

**OS:** N/A

**FP Rate:** Medium

---

## ATT&CK Tags

| Tactic | Technique | Subtechnique | Technique Name |
|---|---|---| --- |
| TA0005 - Defense Evasion | T1036 |  | Masquerading|

## Utilized Data Sources

| Log Provider | Event ID | Event Name | ATT&CK Data Source | ATT&CK Data Component|
|---------|---------|----------|---------|---------|
|AzureActiveDirectory|Sign-in activity||Logon Session|Logon Session Metadata|
|AzureActiveDirectory|Sign-in activity||Logon Session|Logon Session Metadata|
---

## Technical description of the attack
This query establishes a baseline of the type of UserAgent (i.e., browser, Office application, etc.) that is typically used for a particular application by looking back for a number of days. It then searches the current day for any deviations from this pattern, i.e., types of UserAgents not seen before in combination with this application.


## Permission required to execute the technique
User

## Detection description
An attacker might be able to steal an access token for a particular application and use that to connect on behalf of the user.


## Considerations
None.


## False Positives
There might be users that are using a rare UserAgent, application combination for legitimate purposes, for example, a specific third party application to connect to a service.


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
let RuleId = "0060";
let DedupFields = dynamic(["TimeGenerated"]);
let lookback_timeframe= 7d;
let ExtractBrowserTypeFromUA=(ua:string) {
    // Note these are in a specific order since, for example, Edge contains based Chrome/ and Edge/ strings.
    case(
        ua contains "Edge/", dynamic({"AgentType": "Browser", "AgentName": "Edge"}),
        ua contains "Edg/", dynamic({"AgentType": "Browser", "AgentName": "Edge"}),
        ua contains "Trident/", dynamic({"AgentType": "Browser", "AgentName": "Internet Explorer"}),
        ua contains "Chrome/" and ua contains "Safari/", dynamic({"AgentType": "Browser", "AgentName": "Chrome"}),
        ua contains "Gecko/" and ua contains "Firefox/", dynamic({"AgentType": "Browser", "AgentName": "Firefox"}),
        not(ua contains "Mobile/") and ua contains "Safari/" and ua contains "Version/", dynamic({"AgentType": "Browser", "AgentName": "Safari"}),
        ua startswith "Dalvik/" and ua contains "Android", dynamic({"AgentType": "Browser", "AgentName": "Android Browser"}),
        ua startswith "MobileSafari//", dynamic({"AgentType": "Browser", "AgentName": "Mobile Safari"}),
        ua contains "Mobile/" and ua contains "Safari/" and ua contains "Version/", dynamic({"AgentType": "Browser", "AgentName": "Mobile Safari"}),
        ua contains "Mobile/" and ua contains "FxiOS/", dynamic({"AgentType": "Browser", "AgentName": "IOS Firefox"}),
        ua contains "Mobile/" and ua contains "CriOS/", dynamic({"AgentType": "Browser", "AgentName": "IOS Chrome"}),
        ua contains "Mobile/" and ua contains "WebKit/", dynamic({"AgentType": "Browser", "AgentName": "Mobile Webkit"}),
        //
        ua startswith "Excel/", dynamic({"AgentType": "OfficeApp", "AgentName": "Excel"}),
        ua startswith "Outlook/", dynamic({"AgentType": "OfficeApp", "AgentName": "Outlook"}),
        ua startswith "OneDrive/", dynamic({"AgentType": "OfficeApp", "AgentName": "OneDrive"}),
        ua startswith "OneNote/", dynamic({"AgentType": "OfficeApp", "AgentName": "OneNote"}),
        ua startswith "Office/", dynamic({"AgentType": "OfficeApp", "AgentName": "Office"}),
        ua startswith "PowerPoint/", dynamic({"AgentType": "OfficeApp", "AgentName": "PowerPoint"}),
        ua startswith "PowerApps/", dynamic({"AgentType": "OfficeApp", "AgentName": "PowerApps"}),
        ua startswith "SharePoint/", dynamic({"AgentType": "OfficeApp", "AgentName": "SharePoint"}),
        ua startswith "Word/", dynamic({"AgentType": "OfficeApp", "AgentName": "Word"}),
        ua startswith "Visio/", dynamic({"AgentType": "OfficeApp", "AgentName": "Visio"}),
        ua startswith "Whiteboard/", dynamic({"AgentType": "OfficeApp", "AgentName": "Whiteboard"}),
        ua startswith "Mozilla/5.0 (compatible; MSAL 1.0)", dynamic({"AgentType": "OfficeApp", "AgentName": "Office Telemetry"}),
        //
        ua contains ".NET CLR", dynamic({"AgentType": "Custom", "AgentName": "Dotnet"}),
        ua startswith "Java/", dynamic({"AgentType": "Custom", "AgentName": "Java"}),
        ua startswith "okhttp/", dynamic({"AgentType": "Custom", "AgentName": "okhttp"}),
        ua contains "Drupal/", dynamic({"AgentType": "Custom", "AgentName": "Drupal"}),
        ua contains "PHP/", dynamic({"AgentType": "Custom", "AgentName": "PHP"}),
        ua startswith "curl/", dynamic({"AgentType": "Custom", "AgentName": "curl"}),
        ua contains "python-requests", dynamic({"AgentType": "Custom", "AgentName": "Python"}),
        pack("AgentType","Other","AgentName", extract(@"^([^/]*)/",1,ua))
    )
};
// Query to obtain 'simplified' user agents in a given timespan.
let QueryUserAgents = (start_time:timespan, end_time:timespan) {
    union withsource=tbl_name AADNonInteractiveUserSignInLogs, SigninLogs
    | where ingestion_time() >= ago(start_time)
    | where ingestion_time() < ago(end_time)
    | where ResultType == 0  // Only look at successful logins.
    | extend ParsedUserAgent=ExtractBrowserTypeFromUA(UserAgent)
    | extend UserAgentType=tostring(ParsedUserAgent.AgentType)
    | extend UserAgentName=tostring(ParsedUserAgent.AgentName)
    | extend SimpleUserAgent=UserAgentType
    | where not(isempty(UserAgent))
    | where not(isempty(AppId))
};
// Get baseline usage per application.
let BaselineUserAgents=materialize(
    QueryUserAgents(lookback_timeframe+timeframe, timeframe)
    | summarize RequestCount=count() by AppId, AppDisplayName, SimpleUserAgent
);
let BaselineSummarizedAgents=(
    BaselineUserAgents
    | summarize BaselineUAs=make_set(SimpleUserAgent),BaselineRequestCount=sum(RequestCount) by AppId, AppDisplayName
);
QueryUserAgents(timeframe, 0d)
| summarize count() by AppId, AppDisplayName, UserAgent, SimpleUserAgent
| join kind=leftanti BaselineUserAgents on AppId, AppDisplayName, SimpleUserAgent
| join BaselineSummarizedAgents on AppId, AppDisplayName
| where BaselineRequestCount > 100 // Search only for actively used applications.
// Get back full original requests.
| join QueryUserAgents(timeframe, 0d) on AppId, UserAgent
| project-away ParsedUserAgent, UserAgentName
| project-reorder TimeGenerated, AppDisplayName, UserPrincipalName, UserAgent, BaselineUAs
// Begin environment-specific filter.
// End environment-specific filter.
| summarize count() by UserPrincipalName, AppDisplayName, AppId, UserAgentType, SimpleUserAgent, UserAgent
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
| 1.3  | 2023-06-23| minor | Updated check for MSAL User-Agent to remove false-positives. |
| 1.2  | 2022-08-26| minor | Entity mapping added. |
| 1.1  | 2022-02-22| minor | Use ingestion_time for event selection and include de-duplication logic. |
| 1.0  | 2021-03-12| major | Initial version. |