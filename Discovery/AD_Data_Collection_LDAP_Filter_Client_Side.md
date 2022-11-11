# Active Directory Data Collection

## Metadata
**ID:** AD_Data_Collection_LDAP_Filter_Client_Side

**OS:** WindowsEndpoint

**FP Rate:** Medium

---

## ATT&CK Tags

| Tactic | Technique | Subtechnique | Technique Name |
|---|---|---| --- |
| TA0007 - Discovery | T1482 |  | Domain Trust Discovery|
| TA0007 - Discovery | T1087 | 002 | Account Discovery - Domain Account|
| TA0007 - Discovery | T1069 | 002 | Permission Groups Discovery - Domain Groups|
| TA0007 - Discovery | T1018 |  | Remote System Discovery|
| TA0007 - Discovery | T1201 |  | Password Policy Discovery|
| TA0007 - Discovery | T1033 |  | System Owner/User Discovery|

## Utilized Data Sources

| Log Provider | Event ID | Event Name | ATT&CK Data Source | ATT&CK Data Component|
|---------|---------|----------|---------|---------|
|MicrosoftThreatProtection|LdapSearch||Active Directory|Active Directory Object Access|
---

## Technical description of the attack
​This query collects LDAP queries executed on systems monitored by Defender for Endpoint. The filter attributes of these queries are extracted and matched against a list of IOCs obtained from popular reconnaissance tools.


## Permission required to execute the technique
User

## Detection description
During the reconnaissance phase attackers attempt to enumerate information on the Active Directory structure by using various LDAP-based discovery queries to identify targets for attack. Popular tools that perform this type of LDAP-based discovery are Sharphound (part of Bloodhound) and AD Explorer.


## Considerations
The list of IOCs should be periodically updated when new reconnaissance tools are released.


## False Positives
Some legitimate administration tools will also perform LDAP queries that are identified as reconnaissance.


## Suggested Response Actions
Investigate if the user running these queries has a legitimate business use for making these queries.


## Detection Blind Spots
This query will only find LDAP queries executed directly from workstations enrolled in Defender for Endpoint. When the queries are executed from a device that is not enrolled or by using the device only as a network entry point, the queries will not be logged. To find these edge cases, LDAP query logging has to be performed and analyzed on Domain Controller level.


## References
* https://techcommunity.microsoft.com/t5/microsoft-defender-for-endpoint/hunting-for-reconnaissance-activities-using-ldap-search-filters/ba-p/824726

---

## Detection

**Language:** Kusto

**Platform:** M365 Security

**Query:**
```C#
let timeframe = 1h;
let suspect_search_filter=dynamic([
    "objectGUID=*", // AD Explorer IOC
    "(schemaIDGUID=*)", // Sharphound IOC
    "(&(objectclass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))" // Sharphound IOC
    "(|(samAccountType=805306368)(samAccountType=805306369)(objectclass=organizationalUnit))", // Sharphound IOC
    "(|(samaccounttype=268435456)(samaccounttype=268435457)(samaccounttype=536870912)(samaccounttype=536870913))", // Sharphound IOC
    "(samAccountType=805306368)(samAccountType=805306369)" // Sharphound IOC
]);
DeviceEvents
| where ingestion_time() >= ago(timeframe)
| where ActionType =~ "LdapSearch"
| where not(InitiatingProcessFolderPath startswith @"c:\program files\azure advanced threat protection sensor\" and InitiatingProcessVersionInfoOriginalFileName == @"Microsoft.Tri.Sensor.exe")
| extend AdditionalFields=parse_json(AdditionalFields)
| extend SearchFilter=tostring(AdditionalFields.SearchFilter)
| where SearchFilter has_any(suspect_search_filter)
| project-reorder DeviceName, InitiatingProcessFolderPath, SearchFilter, InitiatingProcessCommandLine
```


---

## Version History
| Version | Date | Impact | Notes |
|---------|------|--------|------|
| 1.0  | 2022-11-11| major | FalconFriday version. |