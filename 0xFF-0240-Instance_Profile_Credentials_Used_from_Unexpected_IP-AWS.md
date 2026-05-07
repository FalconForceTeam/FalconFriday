# AWS Instance Profile Credentials Used from Unexpected IP

## Metadata
**ID:** 0xFF-0240-Instance_Profile_Credentials_Used_from_Unexpected_IP-AWS

**OS:** N/A

---

## ATT&CK Tags

| Tactic | Technique | Subtechnique | Technique Name |
|---|---|---| --- |
| TA0003 - Persistence | T1078 | 004 | Valid Accounts - Cloud Accounts|

## Utilized Data Sources

| Log Provider | Table Name | Event ID | Event Name | ATT&CK Data Source | ATT&CK Data Component|
|---------|---------|---------|----------|---------|---------|
|AWS|AWSCloudTrail|||Cloud Service|Cloud Service Modification|

---

## Detection description
This query searches for API calls made by credentials originating from an instance profile. It creates a summary of the external IP addresses used for these calls. When the same instance is observed making calls from multiple IP addresses, this is considered suspicious and the rule triggers.



## Permission required to execute the technique
User


## Description of the attack
When an attacker gains access to an EC2 instance in AWS, the metadata of that instance can be extracted via the metadata endpoint. This metadata can include access credentials linked to the instance via instance profiles. The attacker can load these credentials in their own system and use them to access AWS APIs.


## Considerations
The query should run over an extended time period, for example, 24 hours, to ensure that both legitimate and illegitimate requests are covered.


## False Positives
There might be EC2 machines that have multiple external IP addresses. These will have to be filtered.


## Suggested Response Actions
Verify whether legitimate business or operational reasons exist for the instance to communicate with the suspicious IPs.

In case of a suspected breach or insider threat:
* Review the latest activities performed by the instance role in the `EventsByIp` field and validate the permissions of role.
* If malicious activity is verified, remove the instance role and review activities in the EC2 instance to establish the levels of access the threat actors could achieve.


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
let timeframe = 2*1d;
let RuleId = "0240";
let DedupFields = dynamic(["TimeGenerated"]);
let AgentAPIs = dynamic(["AcknowledgeMessage","DeleteMessage","FailMessage","GetEndpoint","GetMessages","SendReply","CreateControlChannel","CreateDataChannel","OpenControlChannel","OpenDataChannel","DescribeDocumentParameters","DescribeInstanceProperties","GetCalendar","GetManifest","ListInstanceAssociations","PutCalendar","PutConfigurePackageResult","RegisterManagedInstance","RequestManagedInstanceRoleToken","UpdateInstanceAssociationStatus","UpdateInstanceInformation","UpdateManagedInstancePublicKey"]);
let InstanceAPICalls=(
    AWSCloudTrail
    | where ingestion_time() >= ago(timeframe)
    | where EventName !in~ (AgentAPIs) // Exclude SSM Agent API calls
    | where UserIdentityPrincipalid contains_cs ":i-"
    | parse UserIdentityPrincipalid with * ":i-" InstanceId
    | where not(ipv4_is_match(SourceIpAddress, "198.18.0.0/15")) // AWS interconnect.
    | where not(ipv4_is_in_range(SourceIpAddress, "18.202.0.0/15") or ipv4_is_in_range(SourceIpAddress, "34.240.0.0/12") or ipv4_is_in_range(SourceIpAddress, "52.16.0.0/15")) // AWS IP ranges.
    | where not(SourceIpAddress =~ "AWS Internal")
    | where not(ipv4_is_private(SourceIpAddress))
    // Begin environment-specific filter.
    // End environment-specific filter.
);
let InstancesFromMultipleIPs=(
    InstanceAPICalls
    | summarize IPCount=dcount(SourceIpAddress) by InstanceId
    | where IPCount > 1
);
InstanceAPICalls
// Find calls that originate from an instance which has multiple known IPs.
| lookup kind=inner InstancesFromMultipleIPs on InstanceId
// Find the first event issued by the Source IP that made the least number of calls since that is likely to be
// a request issued by the attacker.
| summarize arg_min(TimeGenerated, *), EventCount=count(), EventNames=make_set(EventName) by InstanceId, SourceIpAddress
| summarize arg_min(EventCount,*), ObservedIps=make_set(SourceIpAddress),RequestCountByIp=make_bag(bag_pack(SourceIpAddress, EventCount)),EventsByIp=make_bag(bag_pack(SourceIpAddress, EventNames)) by InstanceId
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
| 2.1  | 2025-09-16| minor | Updated the query to exclude AWS-related API calls and IP ranges. Enhanced the response plan |
| 2.0  | 2025-08-12| major | Updated the query to use the bag_pack() function instead of the deprecated pack(). |
| 1.3  | 2025-05-19| minor | Updated entity mapping to remove deprecated FullName field. |
| 1.2  | 2022-08-25| minor | Entity mapping added. |
| 1.1  | 2022-02-22| minor | Use ingestion_time for event selection and include de-duplication logic. |
| 1.0  | 2022-02-02| major | Initial version. |