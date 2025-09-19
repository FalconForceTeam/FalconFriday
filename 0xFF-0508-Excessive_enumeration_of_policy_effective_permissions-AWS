# Excessive enumeration of policy effective permissions

## Metadata
**ID:** 0xFF-0508-Excessive_enumeration_of_policy_effective_permissions-AWS

**OS:** N/A

---

## ATT&CK Tags

| Tactic | Technique | Subtechnique | Technique Name |
|---|---|---| --- |
| TA0007 - Discovery | T1069 | 003 | Permission Groups Discovery - Cloud Groups|
| TA0007 - Discovery | T1580 |  | Cloud Infrastructure Discovery|

## Utilized Data Sources

| Log Provider | Table Name | Event ID | Event Name | ATT&CK Data Source | ATT&CK Data Component|
|---------|---------|---------|----------|---------|---------|
|AWS|AWSCloudTrail|AwsApiCall||Application Log|Application Log Content|
---

## Detection description
This query identifies for the enumeration and the evaluation of the Actions described of the AWS Policy document. It is based on the footprint of the IAM Policy Simulator and the APIs performing the evaluation of the allowed actions of the policies. To avoid unnecessary pagination, the Policy Simulator calls `ListUsers` with a maxItems value of 50, and the rest of the `List*` operations with a limit of 1000 values. The call of `SimulatePrincipalPolicy` and `SimulateCustomPolicy` APIs evaluate the effective permissions described on the policy.



## Permission required to execute the technique
User


## Description of the attack
In AWS, IAM policies are the primary mechanism for specifying the permissions that control access to AWS resources. These policies describe a set of actions that are allowed or denied within the resources of the AWS infrastructure. The enumeration of actions described, through simulation of a policy attached to an AWS principal or resource, may
indicate the early stages of the reconnaissance phase of an attack. An attacker tries to gather information about the permissions and access levels of various entities within the AWS environment. Such attacker behavior is detrimental because it provides adversaries with valuable insights into the security posture of an AWS environment.
Permissions enumeration allows attackers to map out the landscape of available resources, identify potential targets, and understand the extent of control they may gain upon successful compromise. This way, threat actors actors can make informed decisions on their next steps, choosing the most effective path to obtain their goals.


## Considerations
None.


## False Positives
Legitimate administrative operations for policy simulation or evaluation will trigger an alert.


## Suggested Response Actions
* Confirm if the user responsible for the account that triggered this alert is aware of the policies discovery activities. Verify whether operational reasons exist for assessing the policies.
* In case of a suspected breach or insider threat, investigate the latest activities of the associated account that occurred around the time of the alert.


## Detection Blind Spots
None expected.


## References
* https://docs.aws.amazon.com/cli/latest/reference/iam/simulate-principal-policy.html
* https://docs.aws.amazon.com/cli/latest/reference/iam/simulate-custom-policy.html
* https://falconforce.nl/dawshund-framework-to-put-a-leash-on-naughty-aws-permissions/
* https://www.invictus-ir.com/news/the-curious-case-of-dangerdev-protonmail-me

---
## Detection

**Language:** Kusto

**Platform:** Sentinel

**Query:**
```C#
let timeframe = 2*1h;
let RuleId = "0508";
let DedupFields = dynamic(["UserIdentityUserName"]);
let SuspiciousThreshold = 40;
let PolicySimulatorBehaviour = (
  AWSCloudTrail
  | where EventSource == "iam.amazonaws.com" and EventTypeName =~ "AwsApiCall" and EventName startswith "List"
  | where UserAgent == "AWS Internal"
  | extend MaxItemsRequest = toint(parse_json(RequestParameters).maxItems)
  | extend IsPolicySim = case(
          EventName =~ "ListUsers" and MaxItemsRequest == 50, 1,
          EventName startswith "List" and EventName != "ListUsers" and MaxItemsRequest == 1000, 1,
          0
      )
  | where IsPolicySim == 1
  | extend EventMinute = bin(TimeGenerated, 2m)
  | summarize RequestMade=count(), Events = make_set(EventName) by TimestampBin=bin(TimeGenerated,2m), UserIdentityArn, SourceIpAddress
  // Begin environment-specific filter.
  // End environment-specific filter.
);
let PermissionsEvaluation = (
  AWSCloudTrail
  | where ingestion_time() >= ago(timeframe)
  | where EventSource =~ "iam.amazonaws.com" and EventTypeName =~ "AwsApiCall" and EventName in~ ("SimulatePrincipalPolicy","SimulateCustomPolicy")
  | extend RequestParameters = parse_json(RequestParameters)
  | mv-expand Actions = RequestParameters.actionNames
  | summarize RequestMade=count(), EnumeratedActionsNames = make_set(Actions) by UserIdentityUserName, TimestampBin=bin(TimeGenerated,1h)
  | where array_length(EnumeratedActionsNames) > SuspiciousThreshold
  // Begin environment-specific filter.
  // End environment-specific filter.
);
union PolicySimulatorBehaviour, PermissionsEvaluation
```

---

## Version History
| Version | Date | Impact | Notes |
|---------|------|--------|------|
| 2.0  | 2025-09-10| major | OrangeCon 25 Edition. Updated query with a new TTP |
| 1.1  | 2025-05-23| minor | Updated dedup_fields to match the query output columns. |
| 1.0  | 2024-02-12| major | Initial version. |
