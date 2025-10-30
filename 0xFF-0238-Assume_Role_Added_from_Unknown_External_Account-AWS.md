# AWS Assume Role Added from Unknown External Account

## Metadata
**ID:** 0xFF-0238-Assume_Role_Added_from_Unknown_External_Account-AWS

**OS:** N/A

---

## ATT&CK Tags

| Tactic | Technique | Subtechnique | Technique Name |
|---|---|---| --- |
| TA0003 - Persistence | T1098 | 001 | Account Manipulation - Additional Cloud Credentials|

## Utilized Data Sources

| Log Provider | Table Name | Event ID | Event Name | ATT&CK Data Source | ATT&CK Data Component|
|---------|---------|---------|----------|---------|---------|
|AWS|AWSCloudTrail|CreateRole||User Account|User Account Modification|
|AWS|AWSCloudTrail|UpdateAssumeRolePolicy||User Account|User Account Modification|
---

## Detection description
This query searches for roles being created or updated where `sts:AssumeRole` is granted with an external AWS account. If the external AWS account id is not in a list of known accounts an alert is raised.



## Permission required to execute the technique
User


## Description of the attack
When an attacker gains access to an account with access to AWS, they might abuse that account to grant the 'AssumeRole' privilege to an external AWS account. Once this privilege is assigned, the external account can be used to access the role and perform actions in the compromised AWS account.


## Considerations
The rule requires setting up a list of known trusted AWS accounts.


## False Positives
There might be sharing of resources with external accounts for business reasons. Such sharing will have to be filtered.


## Suggested Response Actions
Confirm if the user responsible for the providing external access to the role has done so for a valid business reason.


## Detection Blind Spots
None expected.


## References
* https://github.com/DataDog/stratus-red-team

---
## Detection

**Language:** Kusto

**Platform:** Sentinel

**Query:**
```C#
let timeframe = 2*1h;
let RuleId = "0238";
let DedupFields = dynamic(["TimeGenerated"]);
let TrustedAccounts= dynamic([]);
AWSCloudTrail
| where ingestion_time() >= ago(timeframe)
| where EventName in ("CreateRole","UpdateAssumeRolePolicy")
| extend AssumeRoleDocument=iif(EventName == "CreateRole", parse_json(RequestParameters).assumeRolePolicyDocument, parse_json(RequestParameters).policyDocument)
| extend Statement=parse_json(tostring(AssumeRoleDocument)).Statement
| mv-expand Statement
| where Statement.Action =~ "sts:AssumeRole"
| where Statement.Effect =~ "Allow"
| mv-expand AddedAccount=Statement.Principal.AWS
| where not(isempty(AddedAccount))
| extend AddedAccount=iif(AddedAccount contains "*", "*", AddedAccount)
| extend AddedAccount=iif(AddedAccount startswith "arn:", split(AddedAccount, ":")[4], AddedAccount)
| where not(AddedAccount == UserIdentityAccountId)
| where not(AddedAccount in (TrustedAccounts))
| project-reorder AddedAccount
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
| 1.2  | 2022-08-31| minor | Entity mapping added. |
| 1.1  | 2022-02-22| minor | Use ingestion_time for event selection and include de-duplication logic. |
| 1.0  | 2022-02-02| major | Initial version. |