Note: You are viewing an old, archived version of this content. The latest version is available in the ['main' branch](https://github.com/FalconForceTeam/FalconFriday/blob/main/0xFF-0237-Password_Assigned_to_Existing_IAM_User-AWS.md).

# Password Assigned to Existing AWS IAM User

## Metadata
**ID:** 0xFF-0237-Password_Assigned_to_Existing_IAM_User-AWS

**OS:** N/A

**FP Rate:** Low

---

## ATT&CK Tags

| Tactic | Technique | Subtechnique | Technique Name |
|---|---|---| --- |
| TA0003 - Persistence | T1098 | 001 | Account Manipulation - Additional Cloud Credentials|

## Utilized Data Sources

| Log Provider | Event ID | Event Name | ATT&CK Data Source |
|---------|---------|----------|---------|
|AWSCloudTrail||||
---

## Technical description of the attack
​This query searches for the `CreateLoginProfile` event which assigns a console password to an existing AWS IAM user.


## Permission required to execute the technique
User

## Detection description
When an attacker gains access to an account with high privileges in AWS, they might abuse that to set a password for an existing IAM user so that user account can be used to gain access to the AWS web console.


## Considerations
None.


## False Positives
There might be a business reason for assigning a console password to an existing user.


## Suggested Response Actions
Confirm if the user responsible for the setting the console password has done so for a valid business reason.


## Detection Blind Spots
None known.


## References
* https://github.com/DataDog/stratus-red-team
* https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateLoginProfile.html

---

## Detection

**Language:** Kusto

**Platform:** Sentinel

**Query:**
```C#
let timeframe = 1h;
AWSCloudTrail
| where ingestion_time() >= ago(timeframe)
| where EventName == "CreateLoginProfile"
// Begin client-specific filter.
// End client-specific filter.
```


---

## Version History
| Version | Date | Impact | Notes |
|---------|------|--------|------|
| 1.0  | 2022-02-01| major | Initial version. |