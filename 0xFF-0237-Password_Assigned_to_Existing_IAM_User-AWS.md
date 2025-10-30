# Password Assigned to Existing AWS IAM User

## Metadata
**ID:** 0xFF-0237-Password_Assigned_to_Existing_IAM_User-AWS

**OS:** N/A

---

## ATT&CK Tags

| Tactic | Technique | Subtechnique | Technique Name |
|---|---|---| --- |
| TA0001 - Initial Access | T1078 | 004 | Valid Accounts - Cloud Accounts|
| TA0003 - Persistence | T1098 | 001 | Account Manipulation - Additional Cloud Credentials|

## Utilized Data Sources

| Log Provider | Table Name | Event ID | Event Name | ATT&CK Data Source | ATT&CK Data Component|
|---------|---------|---------|----------|---------|---------|
|AWS|AWSCloudTrail|CreateLoginProfile||User Account|User Account Modification|
---

## Detection description
This use case monitors for modifications in the AWS console access of an IAM user. Threat actors that gain access to an IAM user can enable the access to the AWS Management Console by abusing the 'CreateLoginProfile' API call without resetting the user's password thus remaining stealthy and gaining the ability to manipulate and control critical AWS resources.



## Permission required to execute the technique
User


## Description of the attack
The AWS Management Console is a web-based interface for users to interact with and manage their AWS resources. It offers a centralized platform for configuring and monitoring various AWS services, making it convenient for accessing and controlling the cloud infrastructure.  When attackers enable the AWS Management Console for a user who initially lacked access, they can achieve unhindered control over AWS resources, allowing them to manipulate configurations, launch instances, modify security settings, and manage storage resources without detection. This unauthorized resource control can lead to disruptions in services, compromise data integrity, exfiltration of sensitive data and privilege escalation enabling more sophisticated and damaging actions, further compromising the organization's security posture.


## Considerations
None.


## False Positives
There might be a business reason for assigning a console password to an existing user.


## Suggested Response Actions
* Confirm if the user responsible for the account that triggered this alert is aware of the change. Verify whether legitimate business or operational reasons exist for enabling console access.
* In case of a suspected breach or insider threat, investigate the latest activities of the associated account that occurred around the time of the alert.
* If the console access is deemed suspicious, ensure to disable the access to prior levels.


## Detection Blind Spots
None expected.


## References
* https://github.com/DataDog/stratus-red-team
* https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateLoginProfile.html

---
## Detection

**Language:** Kusto

**Platform:** Sentinel

**Query:**
```C#
let timeframe = 2*1h;
let RuleId = "0237";
let DedupFields = dynamic(["TimeGenerated"]);
AWSCloudTrail
| where ingestion_time() >= ago(timeframe)
| where EventSource =~ "iam.amazonaws.com" and EventTypeName =~ "AwsApiCall" and EventName =~ "CreateLoginProfile"
| extend PasswordResetRequired = tostring(parse_json(RequestParameters).passwordResetRequired)
| where PasswordResetRequired =~ "false"
| extend TargetUserName = tostring(parse_json(RequestParameters).userName)
| project-reorder TimeGenerated, TargetUserName, UserIdentityUserName, UserIdentityType, UserIdentityArn, AWSRegion, SourceIpAddress, UserAgent
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
| 1.3  | 2023-11-11| minor | Enriched descriptions and query. |
| 1.2  | 2022-08-31| minor | Entity mapping added. |
| 1.1  | 2022-02-22| minor | Use ingestion_time for event selection and include de-duplication logic. |
| 1.0  | 2022-02-01| major | Initial version. |