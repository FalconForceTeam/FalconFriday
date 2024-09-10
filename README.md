Note: You are viewing an old, archived version of this content. The latest version is available in the ['main' branch](https://github.com/FalconForceTeam/FalconFriday/blob/main/README.md).

# FalconFriday
<b>TL;DR: We believe there isn't enough content available to detect advanced adversary techniques. That's why reguarly on "Falcon Friday", we will release (Microsoft Defender for Endpoint - MDE) hunting queries to detect offensive techniques.</b>

To give you an idea, we're going to release hunts for attacks such as:

- DLL Injection
- Process Injection
- COM Hijacking
- .NET-to-JScript
- Aborted MFA requests
- Abuse of LOLBins
- Misbehaving Office Applications
- Process Hollowing
- Unmanaged binaries running managed code
- Anomalies in LDAP traffic 
- Command execution using WMI
- SMB NULL session attempts
- etc

Stay tuned and let us know if there is any specific attack technique you want to detect.

# Background

Our current plan is to release hunting MDE queries on a regular basis. The queries will be released on GitHub, accompanied by a short blog post on Medium detailing background, working of the query, the accuracy we expect, any possible variations or improvements, any catches and really anything else we deem relevant.
Initially, we'll be working based on the excellent library of @spotheplanet's https://www.ired.team/ and release the queries specifically for MDE. Since [@olafhartong](https://github.com/olafhartong) is involved, we might release Sysmon hunts as well...we'll see how it goes.

We will publish the KQL queries on GitHub. Each query will be aimed at detecting some specific technique as precisely as possible and linked to MITRE ATT&CK. We anticipate that some queries will have more than 1 variant, aimed at detecting the same attack in different ways with varying trade-offs. Similarly, we will document trade-offs for various options in a single query to give you the flexibility to gear towards more false positives or more false negatives.

Having said that, don't expect to copy-paste the queries in your environment and be done with it. We will provide a foundation query which can detect a certain technique. However, you will still need to fine-tune/extend  the query to your organization's specifics to make it work in your environment and integrate into your monitoring solution.

The queries will be free to use in any way you like, although we appreciate a reference back to [@falconforceteam](https://twitter.com/falconforceteam) Twitter / [FalconForce](https://github.com/falconforceteam) GitHub.
