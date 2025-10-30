# Suspicious LDAP Queries from Information Gathering Tools

## Metadata
**ID:** 0xFF-0223-BloodHound_Usage-Win

**OS:** WindowsEndpoint, WindowsServer

---

## ATT&CK Tags

| Tactic | Technique | Subtechnique | Technique Name |
|---|---|---| --- |
| TA0007 - Discovery | T1087 | 002 | Account Discovery - Domain Account|
| TA0007 - Discovery | T1482 |  | Domain Trust Discovery|

## Utilized Data Sources

| Log Provider | Table Name | Event ID | Event Name | ATT&CK Data Source | ATT&CK Data Component|
|---------|---------|---------|----------|---------|---------|
|MicrosoftThreatProtection|IdentityQueryEvents|LDAP query||Active Directory|Active Directory Object Access|
---

## Detection description
This rule detects usage of LDAP information gathering tools such as BloodHound, SharpHound or potential custom tools mimicking the behavior of the legitimate tool ADExplorer from Sysinternals. The rule detects tool-specific LDAP queries and also contains a custom "Signature" field, providing information about the exact tool that most probably created the detected LDAP query.



## Permission required to execute the technique
User


## Description of the attack
Adversaries use LDAP information gathering tools such as BloodHound / SharpHound to massively collect information about the target Active Directory environment and easily identify highly complex attack paths that would otherwise be impossible to quickly identify. Legitimate tools such as ADExplorer can also be used to extract similar information. Adversaries could potentially develop custom tools that mimics the behavior of ADExplorer in order to remain undetected by defensive controls.


## Considerations
This rule focuses on identifying LDAP queries that are distinct per tool, using telemetry from Microsoft Defender for Identity. Custom tools not mimicking ADExplorer could have an unexpected behavior and therefore could be excluded from this detection rule.


## False Positives
None expected.


## Suggested Response Actions
Investigate if the user running these LDAP queries has a legitimate business use for performing this action.


## Detection Blind Spots
Telemetry from Microsoft Defender for Identity (MDI) is used. If MDI is not in place, this rule will not provide any detection capabilities.


## References
* https://github.com/BloodHoundAD/SharpHound3
* https://github.com/fox-it/BloodHound.py
* https://bloodhound.readthedocs.io/en/latest/index.html
* https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer

---
## Detection

**Language:** Kusto

**Platform:** M365 Security

**Query:**
```C#
let timeframe = 2*1h;
let SharphoundCheck = IdentityQueryEvents
| where ActionType == "LDAP query"
| where QueryType contains "AllSecurityPrincipals" and QueryType contains "AllDomains" // Sharphound-specific behavior.
| where ingestion_time() >= ago(timeframe)
| extend Signature = "Sharphound";
let BloodhoundCheck = IdentityQueryEvents
| where ActionType == "LDAP query"
| where Query contains "sAMAccountType=805306369" and Query contains "userAccountControl&2" // Bloodhound.py-specific behavior.
| where ingestion_time() >= ago(timeframe)
| extend Signature = "Bloodhound.py";
let ADExplorerMimickCheck = IdentityQueryEvents
| where ActionType == "LDAP query"
| where Query contains "GUID=*" // ADExplorer-specific behavior.
| where ingestion_time() >= ago(timeframe)
| extend Signature = "ADExplorer mimicker";
SharphoundCheck | union ADExplorerMimickCheck, BloodhoundCheck
| summarize arg_min(Timestamp,*),Signature=make_set(Signature) by DeviceName, Query, ReportId
| sort by Timestamp desc
// Begin environment-specific filter.
// End environment-specific filter.
```

---

## Version History
| Version | Date | Impact | Notes |
|---------|------|--------|------|
| 1.2  | 2025-05-23| minor | Added alternate dedup_fields for Sentinel deployment. |
| 1.1  | 2022-02-22| minor | Use ingestion_time for event selection and include de-duplication logic. |
| 1.0  | 2022-01-04| major | Initial version. |