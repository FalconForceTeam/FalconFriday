# AWS Discovery Commands Executed from Instance Profile

## Metadata
**ID:** 0xFF-0239-Discovery_Commands_Executed_from_Instance_Profile-AWS

**OS:** N/A

---

## ATT&CK Tags

| Tactic | Technique | Subtechnique | Technique Name |
|---|---|---| --- |
| TA0007 - Discovery | T1087 | 004 | Account Discovery - Cloud Account|
| TA0007 - Discovery | T1526 |  | Cloud Service Discovery|
| TA0003 - Persistence | T1078 | 004 | Valid Accounts - Cloud Accounts|

## Utilized Data Sources

| Log Provider | Table Name | Event ID | Event Name | ATT&CK Data Source | ATT&CK Data Component|
|---------|---------|---------|----------|---------|---------|
|AWS|AWSCloudTrail|ListRoles||Application Log|Application Log Content|
|AWS|AWSCloudTrail|GetAccountAuthorizationDetails||Application Log|Application Log Content|
|AWS|AWSCloudTrail|ListUsers||Application Log|Application Log Content|
---

## Detection description
This query searches for certain discovery commands such as `ListRoles` and `ListUsers` being executed using credentials originating from an instance profile.



## Permission required to execute the technique
User


## Description of the attack
When an attacker gains access to an EC2 instance in AWS, the metadata of that instance can be extracted via the metadata endpoint. This metadata can include access credentials linked to the instance via instance profiles. The attacker can extract these credentials and use them to access other services in AWS.


## Considerations
None.


## False Positives
There might be EC2 machines that issue these discovery commands for valid business purposes. These will have to be filtered.


## Suggested Response Actions
The EC2 instance ID is available in the `UserIdentityPrincipalid` field. Confirm if the EC2 instance legitimately issued these discovery commands.


## Detection Blind Spots
The detection relies on the `UserIdentityPrincipalid` containing `:i-` to detect access by credentials originating from an instance profile. An attacker might be able to bypass this by manually obtaining credentials.


## References
* https://github.com/DataDog/stratus-red-team
* https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html
* https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_switch-role-ec2_instance-profiles.html

---
## Detection

**Language:** Kusto

**Platform:** Sentinel

**Query:**
```C#
let timeframe = 2*1h;
let RuleId = "0239";
let DedupFields = dynamic(["TimeGenerated"]);
AWSCloudTrail
| where ingestion_time() >= ago(timeframe)
| where UserIdentityPrincipalid contains_cs ":i-"
| where EventName in~ ("ListRoles","GetAccountAuthorizationDetails","ListUsers","ListAssociations","ListBuckets","GetSecretValue","DescribeInstances","ListGroups")
| extend Target_instance_id = tostring(parse_json(tostring(parse_json(tostring(parse_json(RequestParameters).instancesSet)).items))[0].instanceId)
| extend Source_instance_id = tostring(split(UserIdentityArn, "/")[-1])
| where not(Source_instance_id == Target_instance_id and EventName =~ "DescribeInstances")
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
| 1.4  | 2025-05-19| minor | Updated entity mapping to remove deprecated FullName field. |
| 1.3  | 2023-07-26| minor | Updated the EventName list and enhanced the detection logic. |
| 1.2  | 2022-08-25| minor | Entity mapping added. |
| 1.1  | 2022-02-22| minor | Use ingestion_time for event selection and include de-duplication logic. |
| 1.0  | 2022-02-02| major | Initial version. |