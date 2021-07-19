Threat modelling is the process by which threats, whether vulnerabilities or the absence of appropriate controls, can be described and mitigations or remediations planned. The purpose of the process is to provide those responsible for designing, developing, implementing, operating or using the system with a systematic understanding of what controls have been included and any gaps that may exist, given the nature of the system. In practice, this should consider the likely attacker's profile, the tools, tactics and procedures they use to compromise such system and the assets which are most at risk. For this document, threat modelling was used to answer questions such as "Where would an SD-WAN solution be most vulnerable to attack?" and "What security controls do we need to design into the standard to protect against these attacks?".

For the purposes of this document, the [W88 working group](https://wiki.mef.net/pages/viewpage.action?pageId=89000303) took the following approach:
 
1. Created an application diagram using [Microsoft's Threat Modelling Tool](https://aka.ms/threatmodelingtool)
2. Annotated the diagram with the properties as understood for each asset and functional flow 
3. Reviewed the working drafts to identify coverage of the threats identified by the previous two steps
4. Annotated the threat with related references from this document
5. Discussed and made changes to the overall document based on any gaps identified

The threat model identifies threats and groups them into six categories, based on the [STRIDE](https://en.wikipedia.org/wiki/STRIDE_(security)) model:

* Spoofing is defined as pretending to be someone or something other than yourself. Spoofing violates the property of authentication.
* Tampering is defined as modifying something on disk, network, memory or somewhere else. Tampering violates the property of integrity.
* Repudiation is defined as claiming you didn't do something or were not responsible. Repudiation violates the property of non-repudiation.
* Information disclosure is defined as providing information to someone not authorized to access it. Information disclosure violates the property of confidentiality.
* Denial of Service is defined as exhausting resources needed to provide service. Denial of Service violates the property of availability.
* Elevation of privilege is defined as allowing someone to do something they are not authorized to do. Elevation of privilege violates the property of authorization.

For threats that the document proposes to mitigate or remediate, the threat model provided attempts to reference the appropriate sections of this document in justifying their state as "Mitigation Implemented". While a number of items within the threat model were also deemed to be "Out of scope", their inclusion in the references in the supplied threat model should be instructive as to some of the responsibilities of individual implementations which will need consideration by software engineering, implementation and/or operational teams.

In a network that leverages an MBF to enable security policy enforcement, the likelihood of the above categories of threat above can be critically affected by how the MBF intercepts and mediates access. The impact of design decisions in this regard can impact the security and privacy of both end-users as well as operators of the service, MBF and indeed remote application endpoints. Since much of today's network traffic is encrypted (typically with TLS), it is critical that any interception and mediation performed by the MBF does not impact the efficacy of the integrity and confidentiality protections that encryption provides. Ensure that all properties of encrypted traffic (whether they relate to TLS versions, cipher suite selections, PKI certificate management or other) are maintained and that they are implemented and configured in-line with good security practices. Mitigation: R35, R36, R37, R38, R39, R40, R41, R42, R43, R44, R45, D2, D3, R46, R47 and R48 deals with transport security as it relates to the MBF.

An indicative selection of threats from the threat model are listed here, where mitigations are covered by requirements in this document. These are for illustrative purposes:

Threat ID 20 
* Category: Elevation of Privilege. 
* Description: Common SSO implementations such as OAUTH2 and OAUTH Wrap can be vulnerable to on-path attacks if cryptographic controls are weakened. Privilege manipulation attacks apply to supporting functions by which identity is asserted as much as to the original application flow itself, particularly if the application places additional trust on the flow because of the presence of the MBF. 
* Mitigation: R39 deals with the need to secure network flows when communicating with supporting functions.

Threat ID 22 
* Category: Information disclosure. 
* Description: Improper data protection of Policy Enforcement can allow an attacker to read information not intended for disclosure, for example authentication and authorization flows. Information disclosure threats apply to supporting functions as much as the original application flow itself, particularly if the application places additional trust on the flow because of the presence of the MBF. Review authorization settings. 
* Mitigation: R39 deals with the need to secure network flows when communicating with supporting functions.

Threat ID 23 
* Category: Spoofing. 
* Description: Policy Enforcement may be spoofed by an attacker, and this may lead to incorrect data delivered to the Authorization Provider. Spoofing attacks apply to supporting functions as much as the original Application Flow itself. Consider using a standard authentication mechanism to identify the source data store. 
* Mitigation: R39 deals with the need to secure network flows when communicating with supporting functions.

Threat ID 47 
* Category: Repudiation. 
* Description: Does the log capture enough data to understand what happened in the past? Do your logs capture enough data to understand an incident after the fact? Is such capture lightweight enough to be left on all the time? Do you have enough data to deal with repudiation claims? Make sure the log has sufficient and appropriate data to handle a repudiation claim. You might want to talk to an audit expert as well as a privacy expert about your choice of data. 
* Mitigation: Requirements around logging and auditing are covered by R16, R17 and R18.

Threat ID 51 
* Category: Tampering. 
* Description: Log readers can come under attack via log files. Remember that any user supplied data could be malicious and consider ways to canonicalize data in all logs. Implement a single reader for the logs, if possible, to reduce attack surface area. Be sure to understand and document log file elements which come from untrusted sources. 
* Mitigation: Requirements around the trustworthiness of user originated data extracted from Application Flows are covered by D1.

The raw/tool file version is available on this link: 

* https://github.com/MEF-GIT/MEF-SDWAN-Application-Flow-Security-Threat-Model

To view this tool's output in the original source form, please use the freely available tool from Microsoft: https://aka.ms/threatmodelingtool. An overview of the tool and usage can also be found here: https://docs.microsoft.com/en-us/azure/security/develop/threat-modeling-tool.
