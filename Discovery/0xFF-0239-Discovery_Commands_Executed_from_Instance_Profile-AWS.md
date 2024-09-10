Note: You are viewing an old, archived version of this content. The latest version is available in the ['main' branch](https://github.com/FalconForceTeam/FalconFriday/blob/main/0xFF-0239-Discovery_Commands_Executed_from_Instance_Profile-AWS.md).

# AWS Discovery Commands Executed from Instance Profile

## Metadata
**ID:** 0xFF-0239-Discovery_Commands_Executed_from_Instance_Profile-AWS

**OS:** N/A

**FP Rate:** Low

---

## ATT&CK Tags

| Tactic | Technique | Subtechnique | Technique Name |
|---|---|---| --- |
| TA0007 - Discovery | T1087 | 004 | Account Discovery - Cloud Account|
| TA0007 - Discovery | T1526 |  | Cloud Service Discovery|
| TA0003 - Persistence | T1078 | 004 | Valid Accounts - Cloud Accounts|

## Utilized Data Sources

| Log Provider | Event ID | Event Name | ATT&CK Data Source |
|---------|---------|----------|---------|
|AWSCloudTrail||||
---

## Technical description of the attack
​This query searches for certain discovery commands such as `ListRoles` and `ListUsers` being executed using credentials originating from an instance profile.


## Permission required to execute the technique
User

## Detection description
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
let timeframe = 1h;
AWSCloudTrail
| where ingestion_time() >= ago(timeframe)
| where UserIdentityPrincipalid contains_cs ":i-"
| where EventName in ("ListRoles","GetAccountAuthorizationDetails","ListUsers")
// Begin client-specific filter.
// End client-specific filter.
```


---

## Version History
| Version | Date | Impact | Notes |
|---------|------|--------|------|
| 1.0  | 2022-02-02| major | Initial version. |