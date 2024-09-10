Note: You are viewing an old, archived version of this content. The latest version is available in the ['main' branch](https://github.com/FalconForceTeam/FalconFriday/blob/main/0xFF-0161-Overly_permissive_security_group-AWS.md).

# Overly permissive security group

## Metadata
**ID:** 0xFF-0161-Overly_permissive_security_group-AWS

**OS:** N/A

**FP Rate:** High

---

## ATT&CK Tags

| Tactic | Technique | Subtechnique | Technique Name |
|---|---|---| --- |
| TA0005 - Defense Evasion | T1562 | 007 | Impair Defenses - Disable or Modify Cloud Firewall|

## Utilized Data Sources

| Log Provider | Event ID | Event Name | ATT&CK Data Source |
|---------|---------|----------|---------|
|AWSCloudTrail||||
---

## Technical description of the attack
​This query detects someone setting a security group with inbound rules allowing 0.0.0.0 or a subnet less than or equal to /16. It does it similarly with ipv6.


## Permission required to execute the technique
User

## Detection description
An attacker on AWS might want to obtain access to a machine via SSH, RDP or another management protocol. Since properly configured servers are not internet-reachable, attackers have been observed to allow-list a very large range to provide themselves access to the resource.


## Considerations
This rule only works for organizations which adhere to a strict policy with regards to "least privilege" access.


## False Positives
This rule can trigger a significant number of false positives. It's necessary to tune this rule per organization to ensure that it matches the organization-specific modus operandi with regards to security groups.


## Suggested Response Actions
Confirm if the user has indeed created an overly broad security group rule.


## Detection Blind Spots
None known.


## References

---

## Detection

**Language:** Kusto

**Platform:** Sentinel

**Query:**
```C#
let timeframe = 1h;
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
// Begin client-specific filter.
// End client-specific filter.
```


---

## Version History
| Version | Date | Impact | Notes |
|---------|------|--------|------|
| 1.1  | 2022-02-01| minor | Add alerting based on cidrIp as well. |
| 1.0  | 2021-08-12| major | Initial version. |