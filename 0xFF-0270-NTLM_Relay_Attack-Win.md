# NTLM Relay Attack

## Metadata
**ID:** 0xFF-0270-NTLM_Relay_Attack-Win

**OS:** WindowsEndpoint, WindowsServer

**FP Rate:** Low

---

## ATT&CK Tags

| Tactic | Technique | Subtechnique | Technique Name |
|---|---|---| --- |
| TA0006 - Credential Access | T1557 | 001 | Adversary-in-the-Middle - LLMNR/NBT-NS Poisoning and SMB Relay|
| TA0006 - Credential Access | T1187 |  | Forced Authentication|

## Utilized Data Sources

| Log Provider | Event ID | Event Name | ATT&CK Data Source | ATT&CK Data Component|
|---------|---------|----------|---------|---------|
|MicrosoftThreatProtection|ConnectionSuccess||Network Traffic|Network Connection Creation|
|MicrosoftThreatProtection|LogonSuccess||Logon Session|Logon Session Creation|
|MicrosoftThreatProtection|||||
---

## Technical description of the attack
This query searches for successful NTLM network logins where the device name contained in the NTLM authentication message contains a device that is known to MDE, but the source IP address is different from the known source IP address for that specific device. This could indicate an attacker is relaying the NTLM authentication information. To remove false positives, this query also searches for an outgoing network connection from the initiator to the attacker.


## Permission required to execute the technique
User

## Detection description
NTLM relay attacks can be used by an attacker to authenticate to a system by relaying NTLM credentials that are taken from a different system. In an NTLM relay attack three machines are involved: the initiator, the attacker and the target. The initiator initiates an NTLM session to the attacker, the attacker then relays the NTLM authentication information to the target.


## Considerations
None.


## False Positives
None expected.


## Suggested Response Actions
The query results can be used as a starting point for further investigations. The RemoteIP in the results contains the attacker's IP address.


## Detection Blind Spots
The rule will only work if both the initiator and the target machines are enrolled in MDE.


## References
* https://github.com/Cyb3r-Monk/Threat-Hunting-and-Detection/blob/main/Credential%20Access/Potentially%20Relayed%20NTLM%20Authentication%20-%20MDE.md

---
## Detection

**Language:** Kusto

**Platform:** M365 Security

**Query:**
```C#
let timeframe = 2*1d;
// Extract a list of known local IPs per device. Note that the DeviceNetworkEvents table is used for this, since this is faster than the
// DeviceNetworkInfo table where IP addresses are stored inside a JSON structure that requires additional parsing.
let DeviceIPs=(
    DeviceNetworkEvents
    | where ingestion_time() >= ago(timeframe)
    | where ActionType == "ConnectionAttempt" or ActionType == "ConnectionSuccess"
    | distinct DeviceName, LocalIP
    | extend DeviceName=tolower(split(DeviceName,".")[0])
);
// Find potential NTLM relay attack by looking for NTLM logins from devices that are known in MDE, but are from a source IP that does not match any known IP addresses for the device.
let PotentialNTLMRelayLogins=materialize (
    DeviceLogonEvents
    | where ingestion_time() >= ago(timeframe)
    | where ActionType == "LogonSuccess"
    | where LogonType == "Network"
    | where Protocol=="NTLM"
    | where isnotempty(RemoteDeviceName) and isnotempty(RemoteIP)
    | where RemoteIPType <> "Loopback"
    | extend RemoteDeviceName=tolower(RemoteDeviceName)
    | where RemoteDeviceName in ((DeviceIPs | project DeviceName)) // The remote device is known in MDE.
    | join kind=leftanti DeviceIPs on $left.RemoteIP == $right.LocalIP, $left.RemoteDeviceName == $right.DeviceName // The Remote IP does not match any known IP for the device.
    | project-reorder Timestamp, RemoteIP, RemoteDeviceName, AccountDomain, AccountName
);
// Filter the potential NTLM relay events by checking there was an outgoing SMB connection from the source device to the relay IP address.
DeviceNetworkEvents
| where ingestion_time() >= ago(timeframe)
| where RemotePort in (445, 80, 9389)
| where RemoteIP in ((PotentialNTLMRelayLogins | project RemoteIP))
| extend ShortDeviceName=tolower(split(DeviceName,".")[0])
| where ShortDeviceName in ((PotentialNTLMRelayLogins | project RemoteDeviceName))
| lookup kind=inner PotentialNTLMRelayLogins on $left.ShortDeviceName == $right.RemoteDeviceName, $left.RemoteIP == $right.RemoteIP
// Begin environment-specific filter.
// End environment-specific filter.
```

---

## Version History
| Version | Date | Impact | Notes |
|---------|------|--------|------|
| 1.1  | 2023-12-04| minor | Extend Sentinel entity mapping. |
| 1.0  | 2022-03-07| major | Initial version. |