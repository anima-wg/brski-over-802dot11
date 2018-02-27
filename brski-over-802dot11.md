---

title: "BRSKI over 802.11"
abbrev: BRSKI-WIFI
docname: draft-friel-brski-over-802dot11-00
category: std

stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
 -
    ins: O. Friel
    name: Owen Friel
    org: Cisco
    email: ofriel@cisco.com
 -
    ins: E. Lear
    name: Eliot Lear
    org: Cisco
    email: lear@cisco.com
 -
    ins: M. Pritikin
    name: Max Pritikin
    org: Cisco
    email: pritikin@cisco.com
 -
    ins: M. Richardson
    name: Michael Richardson
    org: Sandelman Software Works
    email: mcr+ietf@sandelman.ca

informative:

informative:
  IANA:
    author:
      org: Internet Assigned Numbers Authority
    title: Service Name and Transport Protocol Port Number Registry
    target: https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml
    
  calculator:
    author:
      org: Revolution Wi-Fi
    title: SSID Overhead Calculator
    target: http://www.revolutionwifi.net/revolutionwifi/p/ssid-overhead-calculator.html

  DPP:
    author:
      org: Wi-Fi Alliance
    title: Wi-Fi Device Provisioning Protocol
    target: https://www.wi-fi.org/file/wi-fi-device-provisioning-protocol-dpp-draft-technical-specification-v0023

  IEEE802.11:
    title: Wireless LAN Medium Access Control (MAC) and Physical Layer (PHY) Specifications
    author:
        ins: IEEE
        name: IEEE
        org: IEEE
    date: 2016

  IEEE802.11u:
    title: 802.11 Amendment 9 Interworking with External Networks
    author:
        ins: IEEE
        name: IEEE
        org: IEEE
    date: 2011

  IEEE802.11i:
    title: 802.11 Amendment 6 Medium Access Control (MAC) Security Enhancements
    author:
        ins: IEEE
        name: IEEE
        org: IEEE
    date: 2004

  IEEE802.11aq:
    title: 802.11 Amendment 5 Pre-Association Discovery
    author:
        ins: IEEE
        name: IEEE
        org: IEEE
    date: 2017

  IEEE802.1X:
    title: Port-Based Network Access Control
    author:
        ins: IEEE
        name: IEEE
        org: IEEE
    date: 2010

  IEEE802.1AR:
    title: Secure Device Identity
    author:
        ins: IEEE
        name: IEEE
        org: IEEE
    date: 2017
    
--- abstract

This document outlines the challenges associated with implementing Bootstrapping Remote Secure Key Infrastructures over 802.11 and 802.1x networks. Multiple options are presented for discovering and authenticating to the correct 802.11 SSID. This initial draft is a  discussion document and no final recommendations are made on the recommended approaches to take.

--- middle

# Introduction

Bootstrapping Remote Secure Key Infrastructures (BRSKI) {{?I-D.ietf-anima-bootstrapping-keyinfra}} describes how a device can bootstrap against a local network using an Initial Device Identity X.509 [IEEE802.1AR] IDevID certificate that is pre-installed by the vendor on the device in order to obtain an [IEEE802.1AR] LDevID. The BRSKI flow assumes the device can obtain an IP address, and thus assumes the device has already connected to the local network. Further, the draft states that BRSKI use of IDevIDs:

> allows for alignment with 802.1X network access control methods, its use here is for Pledge authentication rather than network access control. Integrating this protocol with network access control, perhaps as an Extensible Authentication Protocol (EAP) method (see {{?RFC3748}}, is out-of-scope.

The draft does not describe any mechanisms for how a wi-fi enabled device would discover and select a suitable [IEEE802.11] SSID when multiple SSIDs are available. A typical deployment scenario could involve a device begin deployed in a location were twenty or more SSIDs are being broadcast, for example, in a multi-tenanted building or campus where multiple independent organizations operate wi-fi networks.

In order to reduce the administrative overhead of installing new devices, it is desirable that the device will automatically discover and connect to the correct SSID without the installer having to manually provision any network information or credentials on the device. It is also desirable that the device does not discover, connect to, and automatically enroll with the wrong network as this could result in a device that is owned by one organization connecting to the network of a different organization in a multi-tenanted building or campus.

Additionally, as noted above, the BRSKI draft does not describe how BRSKI could potentially align with [IEEE802.1X] authentication mechanisms.

This document outlines multiple different potential mechanisms that would enable a bootstrapping device to choose between different available 802.11 SSIDs in order to execute the BRSKI flow. This document also outlines several options for how 802.11 networks enforcing 802.1X authentication could enable the BRSKI flow, and describes the required device behaviour.

## Terminology

802.11u: an amendment to the IEEE 802.11-2007 standard to add features that improve interworking with external networks.

ANQP: Access Network Query Protocol

AP: Wi-Fi Access Point

CA: Certificate Authority

EAP: Extensible Authentication Protocol

EST: Enrollment over Secure Transport

HotSpot 2.0 / HS2.0: Wi-Fi Alliance standard that enables cell phones to roam seamlessly between cellular and wi-fi networks.

IDevID: Initial Device Identifier

LDevID: Locally Significant Device Identifier

SSID: 802.11 Service Set Identifier

STA: Wi-Fi station

WLC: Wireless LAN Controller

# Potential SSID Discovery Mechanisms

This section outlines multiple different mechanisms that could potentially be leveraged that would enable a bootstrapping device to choose between multiple different available 802.11 SSIDs. As noted previously, this draft does not make any final recommendations.

## Well-known BRSKI SSID

A standardized naming convention for SSIDs offering BRSKI services is defined such as:

- BRSKI%ssidname

Where:

- BRSKI: is a well-known prefix string of characters. This prefix string would be baked into device firmware.
- %: is a well known delimiter character. This delimiter character would be baked into device firmware.
- ssidname: is the freeform SSID name that the network operator defines.

Device manufacturers would bake the well-known prefix string and character delimiter into device firmware. Network operators configuring SSIDs which offer BRSKI services would have to ensure that the SSID of those networks begins with this prefix. On bootstrap, the device would scan all available SSIDs and look for ones with this given prefix.

If multiple SSIDs are available with this prefix, then the device could simply round robin through these SSIDs and attempt to start the BRSKI flow on each one in turn until it succeeds.

This has the obvious issue that when the device chooses the wrong SSID (for example, the device is being deployed by one organization in a multi-tenant campus, and chooses to connect to the SSID of a different organization), the device is dependent upon the incorrect network rejecting its BRSKI enrollment attempt. It is quite possible that the device will end up enrolled with the wrong network.

Another issue with defining a specific naming convention for the SSID is that this may require network operators to have to deploy a new SSID. In general, network operators attempt to keep the number of unique SSIDs deployed to a minimum as each deployed SSID eats up a percentage of available air time and network capacity. A good discussion of SSID overhead and an SSID overhead [calculator] is available.

## 802.11aq

[IEEE802.11aq] is currently being worked by the IEEE, but is not yet finalized, and is not yet supported by any vendors in shipping product. 802.11aq defines new elements that can be included in 802.11 Beacon, Probe Request and Probe Response frames, and defines new elements for ANQP frames.

The extensions allow an AP to broadcast support for backend services, where allowed services are those registered in the [IANA] Service Name and Transport Protocol Port Number Registry. The services can be advertised in 802.11 elements that include either:

- SHA256 hashes of the registered service names
- a bloom filter of the SHA256 hashes of the registered service names

Bloom filters simply serve to reduce the size of Beacon and Probe Response frames when a large number of services are advertised. If a bloom filter is used by the AP, and a device discovers a potential service match in the bloom filter, then the device can query the AP for the full list of service name hashes using newly defined ANQP elements.

If BRSKI were to leverage 802.11aq, then the 802.11aq specification would need to be pushed and supported, and a BRSKI service would need to be defined in [IANA].

802.11aq based SSID discovery suffers from the same potential issue as Well-known BRSKI SSID: it does nothing to prevent a device from enrolling against the wrong network.

## 802.11u NAI Realm

[IEEE802.11u] defines mechanisms for interworking. An introduction to 802.11u is given in the appendices. The 802.11u NAI Realm IE could be a possible mechanism for advertising BRSKI capability. BRSKI could possibly piggy back on top of NAI Realm and simply advertise an NAI Realm of "_bootstrapks". Wireless LAN Controllers (WLC) appear to allow this kind of configuration today.

Note that today some WLCs tie 802.11u configuration to HS2.0 configuration i.e. you cannot enable advertising 802.11u bits without also advertising HS2.0 in Beacons - but thats a WLC implementation gap not a standards gap.

The key conceptual difference with this NAI Realm proposal is that BRSKI uses this special realm name more as a logical service advertisement rather than as a backhaul internet provider advertisement. Leveraging the NAI Realm to advertise a service is conceptually very similar to what 802.11aq is attempting to achieve.

Leveraging NAI Realm would not require any 802.11 specification changes, and could be defined by this IETF draft. Device manufacturers would bake the well-known NAI Realm string into device firmware. Network operators configuring SSIDs which offer BRSKI services would have to ensure that the SSID offered an NAI Realm with this specific name. On bootstrap, the device would scan all available SSIDs and use ANQP to query for NAI Realms matching the BRSKI service name.

Additionally (or alternatively...) as NAI Realm includes advertising the EAP mechanism required, if a new EAP-BRSKI were to be defined, then this could be advertised. Devices could then scan for an NAI Realm that enforced EAP-BRSKI, and ignore the realm name.

Again, 802.11u NAI Realm suffers from the same limitations as 802.11aq and Well-known BRSKI SSID: it does nothing to prevent a device from enrolling against the wrong network.

Additionally, as the IEEE is attempting to standardize logical service advertisement via 802.11aq, 802.11aq would seem to be the more appropriate option than overloading NAI Realm. However, it is worth noting that configuring of NAI Realms is supported today by WLCs.

## 802.11u Interworking Information - Internet

It is possible that an SSID may be configured to provide unrestricted and unauthenticated internet access. This could be advertised in the Interworking Information IE by including:

- internet bit = 1
- ASRA bit = 0

If such a network were discovered, a device could attempt to use the BRSKI well-known vendor cloud Registrar. Possibly this could be a default fall back mechanism that a device could use when determining which SSID to use.

## Define new 802.11u Extensions

Of the various elements currently defined by 802.11u for potentially advertising BRSKI, NAI Realm is the only element that is a possible option, as outlined above. The Roaming Consortium and 3GPP Cellular Network elements are not suitable at all. Another option that has been suggested in the IETF mailers is defining an extension to 802.11u specifically for advertising BRSKI service capability.

802.11aq appears to be the proposed mechanism for generically advertising any service capability, provided that service is registered with [IANA]. It is probably a better approach to encourage adoption of 802.11aq and register a service name for BRSKI with [IANA] rather than attempt to define a completely new BRSKI-specific 802.11u extension.

## Wi-Fi Protected Setup

This is probably a bad idea for reasons to be documented...

## Wi-Fi Device Provisioning Profile

The [DPP] specification defines how an entity that is already trusted by a network can assist an untrusted entity in enrolling with the network. The description below assumes the 802.11 network is in infrastructure mode. DPP introduces multiple key roles including:

- Configurator: A logical entity that is already trusted by the network that has capabilities to enroll and provision devices called Enrollees. A Configurator may be a STA or an AP.

- Enrollee: A logical entity that is being provisioned by a Configurator. An Enrollee may be a STA or an AP.

- Initiator: A logical entity that initiates the DPP Authentication Protocol. The Initiator may be the Configurator or the Enrollee.

h- Responder: A logical entity that responds to the Initiator of the DPP Authentication Protocol. The Responder may be the Configurator or the Enrollee.

In order to support a plug and play model for installation of devices, where the device is simply powered up for the first time and automatically discovers the network without the need for a helper or supervising application, for example an application running on a smart cell phone or tablet that performs the role of Configurator, then this implies that the AP must perform the role of the Configurator and the device or STA performs the role of Enrollee. Note that the AP may simply proxy DPP messages through to a backend WLC, but from the perspective of the device, the AP is the Configurator.

The DPP specification also mandates that the Initiator must know in advance and validate the bootstrapping public key of the Responder. For BRSKI purposes, the DPP bootstrapping public key will be the [IEEE802.1AR] IDevID of the device. As the boostrapping device cannot know in advance the bootstrapping public key of a specific operators network, this implies that the Configurator must take on the role of the Initiator. Therefore, the AP must take on the roles of both the Configurator and the Initiator.

More details to be added...

# Potential Authentication Options

When the bootstrapping device determines which SSID to connect to, there are multiple potential options available for how the device authenticates with the network while bootstrapping. Several options are outlined in this section. This list is not exhaustive.

At a high level, authentication can generally be split into two phases using two different credentials:

- Pre-BRSKI: The device can use its [IEEE802.1AR] IDevID to connect to the network while executing the BRSKI flow
- Post-BRSKI: The device can use its [IEEE802.1AR] LDevID to connect to the network after completing BRSKI enrollment

The authentication options outlined in this document include:

- Unauthenticated Pre-BRSKI and EAP-TLS Post-BRSKI

- PSK Pre-BRSKI and 802.1X EAP-TLS Post-BRSKI

- 802.1X EAP-TLS Pre-BRSKI and 802.1X EAP-TLS Post-BRSKI

- New 802.1X EAP-BRSKI mechanism

These mechanisms are described in more detail in the following sections.

## SSID Considerations

[IEEE802.11i] allows an SSID to advertise multiple authentication mechanisms. A very brief introduction to 802.11i is given in the appendices. For example, a single SSID could advertise both PSK and 802.1X authentication mechanisms. When a network operator needs to enforce two different authentication mechanisms, one for pre-BRSKI devices and one for post-BRSKI devices, the operator has two options:

- configure one SSID advertising both authentication  mechanisms
- configure two SSIDs with each one advertising a different authentication mechanism

Devices should be flexible enough to handle both potential scenarios. When discovering a pre-BRSKI SSID, the device should also discover the authentication mechanism enforced by the SSID that is advertising BRSKI support. If the device supports the authentication mechanism being advertised, then the device can connect to the SSID in order to initiate the BRSKI flow. For example, the device may support 802.1X as a pre-BRSKI authentication mechanism, but may not support PSK as a pre-BRSKI authentication mechanism.

Once the device has completed the BRKSI flow and has obtained an LDevID, a mechanism is needed to tell the device which SSID to use for post-BRSKI network access. This may be a different SSID to the pre-BRSKI SSID. The mechanism by which the post-BRSKI SSID is advertised to the device is out-of-scope of this version of this document.

## IP Address Assignment Considerations

If a device has to perform two different authentications, one for pre-BRSKI and one for post-BRSKI, network policy will typically assign the device to different VLANs for these different stages, and assign the device different IP addresses depending on which network segment the device is assigned to. This will generally be true even if a single SSID is used for both pre-BRSKI and post-BRSKI connections. Therefore, the bootstrapping device must be able to completely reset its network connection and network software stack, and obtain a new IP address between pre-BRSKI and post-BRSKI connections.

## Unauthenticated Pre-BRSKI and EAP-TLS Post-BRSKI

The device connects to an unauthenticated network pre-BRSKI. The device connects to a network enforcing 802.1X EAP-TLS post-BRSKI. The device uses its LDevID as the post-BRSKI 802.1X credential.

To be completed..

## PSK Pre-BRSKI and 802.1X EAP-TLS Post-BRSKI

The device connects to a network enforcing PSK pre-BRSKI. The mechanism by which the PSK is provisioned on the device for pre-BRSKI authentication is out-of-scope of this version of this document. The device connects to a network enforcing 802.1X EAP-TLS post-BRSKI. The device uses the LDevID obtained via BRSKI as the post-BRSKI 802.1X credential. 

When the device connects to the post-BRSKI network that is enforcing 802.1X EAP-TLS, the device uses its LDevID as its credential. The device should verify the certificate presented by the server during that EAP-TLS exchange against the trusted CA list it obtained during BRSKI.

If the 802.1X network enforces a tunneled EAP method, for example {{?RFC7170}}, where the device must present an additional credential such as a password, the mechanism by which that additional credential is provisioned on the device for post-BRSKI authentication is out-of-scope of this version of this document. NAI Realm may be used to advertise the EAP methods being enforced by an SSID. It is to be determined if guidelines should be provided on use of NAI Realm for advertising EAP method in order to streamline BRSKI.

## 802.1X EAP-TLS Pre-BRSKI and 802.1X EAP-TLS Post-BRSKI

The device connects to a network enforcing 802.1X EAP-TLS pre-BRSKI. The device uses its IDevID as the pre-BRSKI 802.1X credential. The device connects to a network enforcing 802.1X EAP-TLS post-BRSKI. The device uses its LDevID as the post-BRSKI 802.1X credential.

When the device connects to a pre-BRSKI network that is enforcing 802.1X EAP-TLS, the device uses its IDevID as its credential. The deivce should not attempt to verify the certificate presented by the server during that EAP-TLS exchange, as it has not yet discovered the local domain trusted CA list.

When the device connects to the post-BRSKI network that is enforcing 802.1X EAP-TLS, the device uses its LDevID as its credential. The deivce should verify the certificate presented by the server during that EAP-TLS exchange against the trusted CA list it obtained during BRSKI.

Again, if the post-BRSKI network enforces a tunneled EAP method, the mechanism by which that second credential is provisioned on the device is out-of-scope of this version of this document.

## New 802.1X EAP-BRSKI mechanism

A new EAP method, let's call it EAP-BRSKI, is defined that encapsulates the full BRSKI flow. At a high level, this enables the device to obtain an LDevID during the Layer 2 authentication stage. This has multiple advantages including:

- avoids the need for the device to potentially connect to two different SSIDs during bootstrap
- the device only needs to handle one authentication mechanism during bootstrap
- the device only needs to obtain one IP address, which it obtains after BRSKI is complete
- avoids the need for the device to have to disconnect from the network, reset its network stack, and reconnect to the network
- potentially simplifies network policy configuration

The device discovers and connects to a network enforcing 802.1X EAP-BRSKI. A high level EAP-BRSKI flow would look something like:

- Device starts the EAP flow by sending the EAP TLS ClientHello message
- EAP server replies and includes CertificateRequest message, and may specify certificate_authorities in the message
- if the device has an LDevID and the LDevID issuing CA is allowed by the certificate_authorities list (i.e. the issuing CA is explicitly included in the list, or else the list is empty) then the device uses its LDevID to establish the TLS tunnel
- if the device does not have an LDevID, or certificate_authorities prevents it using its LDevID, then the device uses its IDevID to establish the TLS tunnel 
- if certificate_authorities prevents the device from using its IDevID (and its LDevID if it has one) then the device fails to connect

The EAP server continues with TLS tunnel establishment:

- if the device certificate is invalid or expired, then the EAP server fails the connection request. 
- if the device certificate is valid but is not allowed due to a configured policy on the EAP server, then the EAP server fails the connection request
- if the device certificate is accepted, then the EAP server establishes the TLS tunnel and starts the tunneled EAP-BRSKI procedures

At this stage, the EAP server has some policy decisions to make:

- if network policy indicates that the device certificate is sufficient to grant network access, whether it is an LDevID or an IDevID, then the EAP server simply initiates the Crypto-Binding TLV and 'Success' Result TLV exchange. The device can now obtain an IP address and connect to the network.
- if the device certificate is an LDevID, the EAP server may instruct the device via a new EAP TLV to do an {{?RFC7030}} EST 'simplereenroll' using its LDevID. Assuming the 'simplereenroll' completes successfully, the EAP server completes the exchange by initiating the Crypto-Binding TLV and 'Success' Result TLV exchange.
- the EAP server may instruct the device to initialise a full BRSKI flow. Typically, the EAP server will instruct the device to initialize a BRSKI flow when it presents an IDevID, however, the EAP server may instruct the device to initialize a BRSKI flow even if it presented a valid LDevID. The device sends all BRSKI messages, for example 'requestvoucher', inside the TLS tunnel using new EAP TLVs. Assuming the BRSKI flow completes successfully and the device is issued an LDevID, the EAP server completes the exchange by initiating the Crypto-Binding TLV and 'Success' Result TLV exchange.

Once the EAP flow has successfully compelted, then:

- network policy will automatically assign the device to the correct network segment
- the device obtains an IP address
- the device can access production service


# IANA Considerations

[[ TODO ]]

# Security Considerations

[[ TODO ]]

--- back

# 802.11 Primer

## 802.11i

802.11i-2004 is an IEEE standard from 2004 that improves connection security. 802.11i defines the Robust Security Network IE which includes information on:

- Pairwise Cipher Suites (WEP-40, WEP-104, CCMP-128, etc.)
- Authentication and Key Management Suites (PSK, 802.1X, etc.)

The RSN IEs are included in Beacon and Probe Response frames. STAs can use this frame to determine the authentication mechanisms offered by a particular AP e.g. PSK or 802.1X.

## 802.11u

802.11u-2011 is an IEEE standard from 2011 that adds features that improve interworking with external networks. 802.11u-2011 is incorporated into 802.11-2016.

STAs and APs advertise support for 802.11u by setting the Interworking bit in the Extended Capabilities IE, and by including the Interworking IE in Beacon, Probe Request and Probe Response frames.

The Interworking IE includes information on:

- Access Network Type (Private, Free public, Chargeable public, etc.)
- Internet bit (yes/no)
- ASRA (Additional Step required for Access - e.g. Acceptance of terms and conditions, On-line enrollment, etc.)

802.11u introduced Access Network Query Protocol (ANQP) which enables STAs to query APs for information not present in Beacons/Probe Responses.

ANQP defines these key IEs for enabling the STA to determine which network to connect to:

- Roaming consortium IE: includes the Organization Identifier(s) of the roaming consortium(s). The OI is typically  provisioned on cell phones by the SP, so the cell phone can automatically detect wi-fi networks that provide access to its SP's consortium.

- 3GPP Cellular Network IE: includes the Mobile Country Code (MCC) and Mobile Network Code (MNC) of the SP the AP provides access to.

- Network Access Identifier Realm IE: includes {{?RFC4282}} realm names that the AP provides access to (e.g. wifi.service-provider.com). The NAI Realm IE also includes info on the EAP type required to access that realm e.g. EAP-TLS.

- Domain name IE: the domain name(s) of the local AP operator. Its purpose is to enable a STA to connect to a domain operator that may have a more favourable pricing model for backhaul connections to the internet / SP.

STAs can use some or all of the above IEs to make a suitable decision on which SSID to pick.

HotSpot 2.0 is an example of a specification built on top of 802.11u and defines 10 additional ANQP elements using the standard vendor extensions mechanisms defined in 802.11. It also defines a HS2.0 Indication element that is included in Beacons and Probe Responses so that STAs can immediately tell if an SSID supports HS2.0.
