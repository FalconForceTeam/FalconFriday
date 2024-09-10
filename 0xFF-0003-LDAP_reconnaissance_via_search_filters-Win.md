# LDAP reconnaissance via search filters

## Metadata
**ID:** 0xFF-0003-LDAP_reconnaissance_via_search_filters-Win

**OS:** WindowsEndpoint

**FP Rate:** Medium

---

## ATT&CK Tags

| Tactic | Technique | Subtechnique | Technique Name |
|---|---|---| --- |
| TA0007 - Discovery | T1482 |  | Domain Trust Discovery|
| TA0007 - Discovery | T1087 | 002 | Account Discovery - Domain Account|
| TA0007 - Discovery | T1069 | 002 | Permission Groups Discovery - Domain Groups|
| TA0007 - Discovery | T1018 |  | Remote System Discovery|
| TA0007 - Discovery | T1201 |  | Password Policy Discovery|
| TA0007 - Discovery | T1033 |  | System Owner/User Discovery|

## Utilized Data Sources

| Log Provider | Event ID | Event Name | ATT&CK Data Source | ATT&CK Data Component|
|---------|---------|----------|---------|---------|
|MicrosoftThreatProtection|LdapSearch||Active Directory|Active Directory Object Access|
---

## Technical description of the attack
This query collects LDAP queries executed on systems monitored by Defender for Endpoint. The filter and distinguished name attributes of these queries are extracted and matched against a list of IOCs obtained from popular reconnaissance tools.


## Permission required to execute the technique
User

## Detection description
During the reconnaissance phase attackers attempt to enumerate information on the Active Directory structure by using various LDAP-based discovery queries to identify targets for attack. Popular tools that perform this type of LDAP-based discovery are Sharphound (part of Bloodhound) and Powerview.


## Considerations
The list of IOCs should be periodically updated when new reconnaissance tools are released.


## False Positives
Some legitimate administration tools will also perform LDAP queries that are identified as reconnaissance.


## Suggested Response Actions
Investigate if the user running these queries has a legitimate business use for making these queries.


## Detection Blind Spots
This query will only find LDAP queries executed directly from workstations enrolled in Defender for Endpoint. When the queries are executed from a device that is not enrolled or by using the device only as a network entry point, the queries will not be logged. To find these edge cases, LDAP query logging has to be performed and analyzed on Domain Controller level.


## References
* https://techcommunity.microsoft.com/t5/microsoft-defender-for-endpoint/hunting-for-reconnaissance-activities-using-ldap-search-filters/ba-p/824726
* https://www.ptsecurity.com/upload/corporate/ww-en/analytics/positive-research-2020-eng.pdf

---
## Detection

**Language:** Kusto

**Platform:** M365 Security

**Query:**
```C#
let timeframe = 2*1h;
let suspect_search_filter=dynamic([
    "(&(&(objectCategory=person)(objectClass=user))(|(description=*pass*)(comment=*pass*)))", // Metasploit IOC [1].
    "(&(objectCategory=computer)(operatingSystem=*server*))", // Metasploit IOC [1].
    "(&(objectClass=group))", // Metasploit IOC [1].
    "(&(objectClass=group)(managedBy=*)),(&(objectClass=group)(managedBy=*)(groupType:1.2.840.113556.1.4.803:=2147483648))", // Metasploit IOC [1].
    "(&(sAMAccountType=805306369)(dnshostname=*))", // Powerview IOC [1].
    "(&(samAccountType=805306368)(samAccountName=*)", // Powerview IOC [1].
    "(&(samAccountType=805306368)(servicePrincipalName=*)", // Powerview IOC [1].
    "(&(objectClass=msDFS-Linkv2))", // Powerview IOC [1].
    "(&(objectCategory =organizationalUnit)(name=*))" // Powerview IOC [1].
//  "(samAccountType=805306368)" // Empire IOC [1] - disabled by default, since it is too generic.
    "objectClass=trustedDomain", // Recon IOC [2].
//  "objectClass=crossRef", // Recon IOC [2].
    "userAccountControl:1.2.840.113556.1.4.803:=524288", // Recon IOC [2].
    "userAccountControl:1.2.840.113556.1.4.803:=4194304", // AD Recon IOC [2].
    "anr=Remote Desktop Users", // AD Recon IOC [2].
    "defender-tokenData=*", // AD Recon IOC [2].
    "Domain Admins",  // AD Recon IOC, based on own research.
    "Enterprise Admins", // AD Recon IOC, based on own research.
    "CN=Administrators", //  AD Recon IOC, based on own research.
    "(schemaIDGUID=*)", // Sharphound IOC, based on own research.
//  "(objectclass=domain)", // Sharphound IOC, based on own research.
    "(&(objectclass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))" // Sharphound IOC, based on own research.
    "(|(samAccountType=805306368)(samAccountType=805306369)(objectclass=organizationalUnit))", // Sharphound IOC, based on own research.
    "(samAccountType=805306368)(samAccountType=805306369)" // Sharphound IOC, based on own research.
]);
let suspect_dn=dynamic([
    "CN=Domain Admins", // AD Recon IOC, based on own research.
    "CN=Enterprise Admins", // AD Recon IOC, based on own research.
    "CN=DnsAdmins", // AD Recon IOC, based on own research.
    "CN=Domain Controllers", // Sharphound IOC, based on own research.
    "CN=DnsAdmins", // Sharphound IOC, based on own research.
    "CN=Read-only Domain Controllers", // Sharphound IOC, based on own research.
    "CN=Cloneable Domain Controllers" // Sharphound IOC, based on own research.
]);
DeviceEvents
| where ingestion_time() >= ago(timeframe)
| where ActionType =~ "LdapSearch"
// Begin environment-specific filter.
// End environment-specific filter.
| where not(InitiatingProcessFolderPath startswith @"c:\program files\azure advanced threat protection sensor\" and InitiatingProcessVersionInfoOriginalFileName == @"Microsoft.Tri.Sensor.exe")
| extend AdditionalFields=parse_json(AdditionalFields)
| extend SearchFilter=tostring(AdditionalFields.SearchFilter)
| extend DistinguishedName=tostring(AdditionalFields.DistinguishedName)
| where SearchFilter has_any(suspect_search_filter) or DistinguishedName has_any(suspect_dn)
| project-reorder DeviceName, InitiatingProcessFolderPath, SearchFilter, DistinguishedName, InitiatingProcessCommandLine
// FileProfile is case-sensitive and works on lower-case hashes.
| extend InitiatingProcessSHA1=tolower(InitiatingProcessSHA1)
| invoke FileProfile(InitiatingProcessSHA1, 1000)
| where not(Signer =~ "Microsoft Corporation" and IsCertificateValid == 1 and InitiatingProcessFileName =~ "microsoft.tri.sensor.exe")
| where not(Signer =~ "Microsoft Corporation" and IsCertificateValid == 1 and SoftwareName =~ "Endpoint Configuration Manager")
| where not(Signer =~ "Microsoft Corporation" and IsCertificateValid == 1 and SoftwareName contains "AD Connect")
| where not(Signer =~ "Microsoft Windows" and IsCertificateValid == 1 and InitiatingProcessFileName =~ "Microsoft.IdentityServer.ServiceHost.exe")
| where not(InitiatingProcessFolderPath =~ @"c:\windows\system32\lsass.exe")

```

---

## Version History
| Version | Date | Impact | Notes |
|---------|------|--------|------|
| 1.5  | 2023-12-04| minor | Commented out two general LDAP filters that make the query produce false positives in large environments. |
| 1.4  | 2023-06-23| minor | Added allow-listing for a number of Microsoft processes that caused false-positives. |
| 1.3  | 2023-01-03| minor | Lowered the case of hashes that are fed to the FileProfile function due to case sensitivity. |
| 1.2  | 2022-06-08| minor | Add MDI sensor to allow-list. |
| 1.1  | 2022-02-22| minor | Use ingestion_time for event selection and include de-duplication logic. |
| 1.0  | 2021-02-01| major | Initial version. |