# Use of Expired Azure AD Credentials Without Successful Login

## Metadata
**ID:** 0xFF-0091-Use_of_Expired_Azure_AD_Credentials_Without_Successful_Login-Azure

**OS:** N/A

**FP Rate:** Low

---

## ATT&CK Tags

| Tactic | Technique | Subtechnique | Technique Name |
|---|---|---| --- |
| TA0006 - Credential Access | T1528 |  | Steal Application Access Token|
| TA0006 - Credential Access | T1539 |  | Steal Web Session Cookie|
| TA0005 - Defense Evasion | T1550 | 004 | Use Alternate Authentication Material - Web Session Cookie|
| TA0008 - Lateral Movement | T1550 | 004 | Use Alternate Authentication Material - Web Session Cookie|

## Utilized Data Sources

| Log Provider | Event ID | Event Name | ATT&CK Data Source | ATT&CK Data Component|
|---------|---------|----------|---------|---------|
|AzureActiveDirectory|Sign-in activity||Logon Session|Logon Session Creation|
---

## Technical description of the attack
This query searches for logins with an expired access credential, for example, an expired cookie. It then matches the IP address from which the expired credential access occurred with the IP addresses of successful logins. If there are logins with expired credentials, but no successful logins from an IP this might indicate an attacker has copied the authentication cookie and is re-using it on another machine.


## Permission required to execute the technique
User

## Detection description
Attackers can gain access to Azure AD protected resources by stealing an authentication token or cookie from a web-browser and then injecting that stolen cookie into a different system.


## Considerations
None.


## False Positives
Users could be on a connection with a regularly changing IP address that shows the expired login from a different IP compared to successful logins.


## Suggested Response Actions
Investigate if the user account could be compromised. Especially when the country for the expired logins differs from the country the user normally logs in from.


## Detection Blind Spots
If an attacker only uses the authentication cookie while it is still valid this technique will not detect it.


## References
* https://github.com/splunk/security_content/blob/626a4fe1a8b5dcf5b526bf5e458d243e0c12f55d/detections/cloud/o365_excessive_sso_logon_errors.yml
* https://stealthbits.com/blog/bypassing-mfa-with-pass-the-cookie/

---
## Detection

**Language:** Kusto

**Platform:** Sentinel

**Query:**
```C#
// Timeframe to search for failed logins.
let timeframe = 2*1d;
let RuleId = "0091";
let DedupFields = dynamic(["TimeGenerated"]);
// Timeframe to look back for successful logins from the same user by IP.
let lookback=3d;
let SuspiciousSignings=(
    SigninLogs
    | where ingestion_time() >= ago(timeframe)
    | where ResourceDisplayName contains "Windows Azure Active Directory"
    // 50132 = SsoArtifactInvalidOrExpired - The session is not valid due to password expiration or recent password change.
    // 50173 = FreshTokenNeeded - The provided grant has expired due to it being revoked, and a fresh auth token is needed.
    | where ResultType in (50173, 50132)
    | summarize FailedCountPerDay=count(),FailedUserAgents=make_set(UserAgent), FailedCountries=make_set(LocationDetails.countryOrRegion),FailedIps=make_set(IPAddress) by UserPrincipalName, Day=bin(TimeGenerated, 1d)
    | where FailedCountPerDay >= 1
);
let SuccessLogins=(
    SigninLogs
    | where TimeGenerated >= ago(lookback)
    | where UserPrincipalName in~ ((SuspiciousSignings | project UserPrincipalName))
    | where ResultType == 0
    | summarize count() by UserPrincipalName, IPAddress
);
SuspiciousSignings
| mv-expand FailedIp=FailedIps
| extend FailedIp=tostring(FailedIp)
| join kind=leftanti SuccessLogins on $left.FailedIp==$right.IPAddress, UserPrincipalName
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
| 1.3  | 2023-01-03| minor | Entity mapping added. |
| 1.2  | 2022-08-26| minor | Entity mapping added. |
| 1.1  | 2022-02-22| minor | Use ingestion_time for event selection and include de-duplication logic. |
| 1.0  | 2021-04-21| major | Initial version. |