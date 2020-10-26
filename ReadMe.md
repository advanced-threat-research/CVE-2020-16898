# CVE-2020-16898: “Bad Neighbor”

#### CVSS Score: 8.8 
#### CVSS Vector: CVSS3.0/AV:A/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H/E:P/RL:O/RC:C

### Overview
On October 13, [Microsoft announced](https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-16898) an exceptionally critical vulnerability in the Windows IPv6 stack, which allows an attacker to send maliciously crafted packets to potentially execute arbitrary code on a remote system. The proof-of-concept shared with MAPP members is both extremely simple and perfectly reliable. It results in an immediate BSOD (Blue Screen of Death), but moreso, indicates the likelihood of exploitation for those who can manage to bypass Windows 10 and Windows Server 2019 mitigations. The effects of an exploit that would grant remote code execution would be widespread and highly impactful, as this is the type of bug that could be made wormable. For ease of reference, we named the vulnerability “Bad Neighbor” because it is located within an ICMPv6 Neighbor Discovery “Protocol”, using the Router Advertisement type.

This document has been prepared by McAfee Advanced Threat Research. It is intended to provide valuable insights for network administrators and security personnel, looking to further understand this vulnerability and to defend against exploitation. The signature produced here should be thoroughly considered and vetted in staging environments prior to being used in production and may benefit from specific tuning to the target deployment. 

*The information provided herein is subject to change without notice, and is provided "AS IS", with all faults, without guarantee or warranty as to the accuracy or applicability of the information to any specific situation or circumstance and for use at your own risk. Additionally, we cannot guarantee any performance or efficacy benchmarks for any signatures.*

### Signature
The Suricata signature for this vulnerability is located in [cve-2020-16898.rules](/cve-2020-16898.rules) and contains the following logic:

*alert icmp any any -> any any (msg:"Potential CVE-2020-16898 Exploit"; lua:**cve-2020-16898.lua**; sid:202016898; rev:1;)*

The corresponding Lua script may be found in [cve-2020-16898.lua](/cve-2020-16898.lua). It contains the logic necessary to properly parse the ICMPv6 layer and identify potential exploitation of Bad Neighbor, as follows:

Once we've located the start of the ICMPv6 layer, we test the first byte of the layer to ensure that it's a Router Advertisement ICMPv6 packet (Type = 134) - if it isn't, we exit.

Since Suricata primitives have not been updated to parse the ICMPv6 options, we simply jump to the 17th byte of the ICMPv6 layer, since that's where the Options should start, if present (the first 16 bytes are static-length fields, per [RFC 4443](https://tools.ietf.org/html/rfc4443#section-2.1)). From there, we loop over every Option until we run out of bytes in the packet. For each Option, we're only interested in the first two bytes: the Option Type and Length fields, respectively. While we ignore all Options that aren't RDNSS, for Option Type = 25 (RDNSS), we check to see if the Length (second byte in the Option) is an even number. If it is, we flag it. If not, we continue. Since the Length is counted in increments of 8 bytes, we multiply the Length by 8 and jump ahead that many bytes to get to the start of the next Option (subtracting 1 to account for the length byte we've already consumed). 

With this rule, we also check to make sure that the Length is at least 3, since [RFC 8106](https://tools.ietf.org/html/rfc8106#section-5.1) requires it, but ultimately this check may be superfluous, since we're only concerned with whether the Length is even or not. 
