# Overly permissive security group

## Metadata
**ID:** 0xFF-0161-Overly_permissive_security_group-AWS

**OS:** N/A

---

## ATT&CK Tags

| Tactic | Technique | Subtechnique | Technique Name |
|---|---|---| --- |
| TA0005 - Defense Evasion | T1562 | 007 | Impair Defenses - Disable or Modify Cloud Firewall|

## Utilized Data Sources

| Log Provider | Table Name | Event ID | Event Name | ATT&CK Data Source | ATT&CK Data Component|
|---------|---------|---------|----------|---------|---------|
|AWS|AWSCloudTrail|AuthorizeSecurityGroupIngress||Cloud Service|Cloud Service Modification|
---

## Detection description
This query detects someone setting a security group with inbound rules allowing 0.0.0.0 or a subnet less than or equal to /16. It does it similarly with ipv6.



## Permission required to execute the technique
User


## Description of the attack
An attacker on AWS might want to obtain access to a machine via SSH, RDP or another management protocol. Since properly configured servers are not internet-reachable, attackers have been observed to allow-list a very large range to provide themselves access to the resource.


## Considerations
This rule only works for organizations which adhere to a strict policy with regards to "least privilege" access.


## False Positives
This rule can trigger a significant number of false positives. It's necessary to tune this rule per organization to ensure that it matches the organization-specific modus operandi with regards to security groups.


## Suggested Response Actions
Confirm if the user has indeed created an overly broad security group rule.


## Detection Blind Spots
None expected.


## References

---
## Detection

**Language:** Kusto

**Platform:** Sentinel

**Query:**
```C#
let timeframe = 2*1h;
let RuleId = "0161";
let DedupFields = dynamic(["TimeGenerated"]);
AWSCloudTrail
| where ingestion_time() >= ago(timeframe)
| where EventName =~ "AuthorizeSecurityGroupIngress"
| distinct *
| extend RequestParameters=parse_json(RequestParameters)
| extend ipPermissionsItems = RequestParameters.ipPermissions.items
| mv-expand ipPermissionsItems
| mv-expand ipPermissionsItems.ipRanges.items, ipPermissionsItems.ipv6Ranges.items
| parse ipPermissionsItems_ipRanges_items.cidrIp with ipprefix:string "/" iprange:int
| parse ipPermissionsItems_ipv6Ranges_items.cidrIpv6 with ipv6prefix:string "/" ipv6range:int
| parse RequestParameters.cidrIp with cidripprefix:string "/" cidriprange:int
| where ipprefix =~ "0.0.0.0" or iprange <= 16
  or ipv6prefix =~ "::" or ipv6range <= 64
  or cidripprefix =~ "0.0.0.0" or cidriprange <= 16
| extend SecurityGroupId = RequestParameters.groupId
// Begin environment-specific filter.
// End environment-specific filter.
| extend UserAccount=tostring(split(UserIdentityArn, "/")[-1])
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
| 1.3  | 2022-08-25| minor | Entity mapping added. |
| 1.2  | 2022-02-22| minor | Use ingestion_time for event selection and include de-duplication logic. |
| 1.1  | 2022-02-01| minor | Add alerting based on cidrIp as well. |
| 1.0  | 2021-08-12| major | Initial version. |