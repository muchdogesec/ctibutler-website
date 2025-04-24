---
date: 2025-01-20
last_modified: 2025-01-20
title: "CTI Developers: We Built an API for MITRE ATT&CK, CWE, CAPEC, ATLAS... and more!"
description: "Here is a quick-start guide to CTI Butler showing you how much easier it makes working with these frameworks."
categories:
  - "PRODUCTS"
tags: [
  "MITRE",
  "ATT&CK",
  "CWE",
  "CAPEC",
  "ATLAS",
  "FIRST",
  "DISARM"
]
products:
    - stix2arango
    - arango_cti_processor
    - cwe2stix
    - disarm2stix
    - location2stix
    - CTIButler
author_staff_member: david-greenwood
image: /assets/images/blog/2025-01-20/ctibutler.png
featured_image: /assets/images/blog/2025-01-20/ctibutler.png
layout: post
published: true
redirect_from:
  - 
---

## tl;dr

I've previously posted articles about various frameworks and how to query them using a database;

* [PSA: MITRE ATT&CK is More Than Tactics and Techniques](/blog/mitre_attack_data_structure/)
* [Fighting Disinformation: Classifying Your Research Using Standardised Disinformation Tactics and Techniques](/blog/introducing_disarm/)
* [Fortifying AI: How MITRE ATLAS Shields Artificial Intelligence from Adversarial Threats](/blog/introducing_mitre_atlas/)

The feedback is in; you don't want to work with DB queries.

So we built an API to work with these frameworks based on the use-cases you told us about.

The result; [CTI Butler](https://www.ctibutler.com), a web API that exposes a variety of CTI frameworks.

<iframe width="560" height="315" src="https://www.youtube.com/embed/84SgT-ess4E?si=K-1rFKEl05AvHoNz" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>

Then we integrated CTI Butler into all our tooling because it immediately made building integrations to these frameworks hundreds-of-times easier.

We've now opened up CTI Butler to other security engineers because we know it will make their lives hundreds-of-times easier too!

In this post I'll explain how you can get started building your CTI tooling using CTI Butler.

I'll use ATT&CK to demonstrate the APIs (because it is the most popular framework in CTI Butler), but the same features are available across all the supported frameworks (CWE, CAPEC, etc.).

## Exploring the MITRE ATT&CK REST API

### Managing multiple versions of ATT&CK

One of the hardest things to manage as a security engineer is ensuring compatibility between versions when updating.

CTI Butler supports all versions released for each framework, allowing you to choose specific versions to use in each request.

You can see all the versions of the ATT&CK available as follows;

```shell
curl -X 'GET' \
  'https://api.ctibutler.com/v1/attack-enterprise/versions/' \
  -H 'accept: application/json' \
  -H 'API-KEY: REDACTED'
```

```json
{
  "latest": "16.0",
  "versions": [
    "16.0",
    "15.1",
    "15.0",
    "14.1",
    "14.0",
    "13.1",
    "13.0",
    "12.1",
    "12.0",
    "11.3",
    "11.2",
    "11.1",
    "11.0",
    "10.1",
    "10.0",
    "9.0",
    "8.2",
    "8.1",
    "8.0",
    "7.2",
    "7.1",
    "7.0",
    "6.3",
    "6.2",
    "6.1",
    "6.0",
    "5.2",
    "5.1",
    "5.0",
    "4.0",
    "3.0",
    "2.0",
    "1.0"
  ]
}
```

The `latest` version shown (here `16.0`) will be the version of objects returned by all other endpoints unless a specific version in the list is specified (I'll demonstrate this in the next section).

### Searching and filtering objects

The objects endpoints allow for rich filtering of the ATT&CK data.

#### Specify an ATT&CK version

Often it takes time to upgrade tooling to support breaking changes.

To get objects for a specific version of ATT&CK that are not the latest (below I use `14.0`) to ensure compatibility you can use CTI Butler as follows;

```shell
curl -X 'GET' \
  'https://api.ctibutler.com/v1/attack-enterprise/objects/?attack_version=14.0' \
  -H 'accept: application/json' \
  -H 'API-KEY: REDACTED'
```

```json
{
  "page_size": 50,
  "page_number": 1,
  "page_results_count": 50,
  "total_results_count": 1642,
  "objects": [
    {
      "created": "2020-01-14T17:18:32.126Z",
      "created_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
      "description": "Adversaries may inject malicious code into process via Extra Window Memory (EWM) in order to evade process-based defenses as well as possibly elevate privileges. EWM injection is a method of executing arbitrary code in the address space of a separate live process. \n\nBefore creating a window, graphical Windows-based processes must prescribe to or register a windows class, which stipulate appearance and behavior (via windows procedures, which are functions that handle input/output of data).(Citation: Microsoft Window Classes) Registration of new windows classes can include a request for up to 40 bytes of EWM to be appended to the allocated memory of each instance of that class. This EWM is intended to store data specific to that window and has specific application programming interface (API) functions to set and get its value. (Citation: Microsoft GetWindowLong function) (Citation: Microsoft SetWindowLong function)\n\nAlthough small, the EWM is large enough to store a 32-bit pointer and is often used to point to a windows procedure. Malware may possibly utilize this memory location in part of an attack chain that includes writing code to shared sections of the process’s memory, placing a pointer to the code in EWM, then invoking execution by returning execution control to the address in the process’s EWM.\n\nExecution granted through EWM injection may allow access to both the target process's memory and possibly elevated privileges. Writing payloads to shared sections also avoids the use of highly monitored API calls such as <code>WriteProcessMemory</code> and <code>CreateRemoteThread</code>.(Citation: Elastic Process Injection July 2017) More sophisticated malware samples may also potentially bypass protection mechanisms such as data execution prevention (DEP) by triggering a combination of windows procedures and other system functions that will rewrite the malicious payload inside an executable portion of the target process.  (Citation: MalwareTech Power Loader Aug 2013) (Citation: WeLiveSecurity Gapz and Redyms Mar 2013)\n\nRunning code in the context of another process may allow access to the process's memory, system/network resources, and possibly elevated privileges. Execution via EWM injection may also evade detection from security products since the execution is masked under a legitimate process. ",
      "external_references": [
```

#### Searching for an object by name and type

Often I find myself looking for an ATT&CK object to classify what I've found.

Here I filter the ATT&CK Enterprise objects to only include those with `exploit` in the `name`, and are a Technique;

```shell
curl -X 'GET' \
  'https://api.ctibutler.com/v1/attack-enterprise/objects/?attack_type=Technique&attack_version=14.0&name=exploit' \
  -H 'accept: application/json' \
  -H 'API-KEY: REDACTED'
```

```json
{
  "page_size": 50,
  "page_number": 1,
  "page_results_count": 6,
  "total_results_count": 6,
  "objects": [
    {
      "created": "2018-04-18T17:59:24.739Z",
      "created_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
      "description": "Adversaries may attempt to exploit a weakness in an Internet-facing host or system to initially access a network. The weakness in the system can be a software bug, a temporary glitch, or a misconfiguration.\n\nExploited applications are often websites/web servers, but can also include databases (like SQL), standard services (like SMB or SSH), network device administration and management protocols (like SNMP and Smart Install), and any other system with Internet accessible open sockets.(Citation: NVD CVE-2016-6662)(Citation: CIS Multiple SMB Vulnerabilities)(Citation: US-CERT TA18-106A Network Infrastructure Devices 2018)(Citation: Cisco Blog Legacy Device Attacks)(Citation: NVD CVE-2014-7169) Depending on the flaw being exploited this may also involve [Exploitation for Defense Evasion](https://attack.mitre.org/techniques/T1211). \n\nIf an application is hosted on cloud-based infrastructure and/or is containerized, then exploiting it may lead to compromise of the underlying instance or container. This can allow an adversary a path to access the cloud or container APIs, exploit container host access via [Escape to Host](https://attack.mitre.org/techniques/T1611), or take advantage of weak identity and access management policies.\n\nAdversaries may also exploit edge network infrastructure and related appliances, specifically targeting devices that do not support robust host-based defenses.(Citation: Mandiant Fortinet Zero Day)(Citation: Wired Russia Cyberwar)\n\nFor websites and databases, the OWASP top 10 and CWE top 25 highlight the most common web-based vulnerabilities.(Citation: OWASP Top 10)(Citation: CWE top 25)",
      "external_references": [
        {
          "source_name": "mitre-attack",
          "url": "https://attack.mitre.org/techniques/T1190",
          "external_id": "T1190"
        },
```

It's also possible to search on the `description` / `alias` values of ATT&CK objects in this way.

## Tracking changes to objects

One of the areas where CTI Butler really shines is being to compare versions.

If I take the sub-techniques `T1499.004` (`Application or System Exploitation`) shown above, I can see all versions of it that exist in the database;

```shell
curl -X 'GET' \
  'https://api.ctibutler.com/v1/attack-enterprise/objects/T1499.004/versions/' \
  -H 'accept: application/json' \
  -H 'API-KEY: REDACTED'
```

```json
[
  {
    "modified": "2024-10-15T15:42:23.001Z",
    "versions": [
      "16.0"
    ]
  },
  {
    "modified": "2022-05-11T14:00:00.188Z",
    "versions": [
      "15.1",
      "15.0",
      "14.1",
      "14.0",
      "13.1",
      "13.0",
      "12.1",
      "12.0",
      "11.3",
      "11.2",
      "11.1"
    ]
  },
  {
    "modified": "2022-03-25T18:11:13.604Z",
    "versions": [
      "11.0"
    ]
  },
  {
    "modified": "2021-03-29T16:09:41.559Z",
    "versions": [
      "10.1",
      "10.0",
      "9.0"
    ]
  },
  {
    "modified": "2020-03-29T02:07:27.508Z",
    "versions": [
      "8.2",
      "8.1",
      "8.0",
      "7.2",
      "7.1",
      "7.0"
    ]
  }
]
```

The response tells me `T1499.004` was introduced in ATT&CK 7.0, and has changed 5 times since being introduced (most recently on the update for v16.0).

You can compare the changes using the version filter shown earlier. For example, here I get the 16.0 version of T1499.004;

```shell
curl -X 'GET' \
  'https://api.ctibutler.com/v1/attack-enterprise/objects/T1499.004/?attack_version=16.0' \
  -H 'accept: application/json' \
  -H 'API-KEY: REDACTED'
```

```json
{
  "page_size": 50,
  "page_number": 1,
  "page_results_count": 1,
  "total_results_count": 1,
  "objects": [
    {
      "created": "2020-02-20T15:37:27.052Z",
      "created_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
      "description": "Adversaries may exploit software vulnerabilities that can cause an application or system to crash and deny availability to users. (Citation: Sucuri BIND9 August 2015) Some systems may automatically restart critical applications and services when crashes occur, but they can likely be re-exploited to cause a persistent denial of service (DoS) condition.\n\nAdversaries may exploit known or zero-day vulnerabilities to crash applications and/or systems, which may also lead to dependent applications and/or systems to be in a DoS condition. Crashed or restarted applications or systems may also have other effects such as [Data Destruction](https://attack.mitre.org/techniques/T1485), [Firmware Corruption](https://attack.mitre.org/techniques/T1495), [Service Stop](https://attack.mitre.org/techniques/T1489) etc. which may further cause a DoS condition and deny availability to critical information, applications and/or systems. ",
      "external_references": [
        {
          "source_name": "mitre-attack",
          "url": "https://attack.mitre.org/techniques/T1499/004",
          "external_id": "T1499.004"
        },
        {
          "source_name": "Sucuri BIND9 August 2015",
          "description": "Cid, D.. (2015, August 2). BIND9 – Denial of Service Exploit in the Wild. Retrieved April 26, 2019.",
          "url": "https://blog.sucuri.net/2015/08/bind9-denial-of-service-exploit-in-the-wild.html"
        }
      ],
      "id": "attack-pattern--2bee5ffb-7a7a-4119-b1f2-158151b19ac0",
      "kill_chain_phases": [
        {
          "kill_chain_name": "mitre-attack",
          "phase_name": "impact"
        }
      ],
      "modified": "2024-10-15T15:42:23.001Z",
      "name": "Application or System Exploitation",
      "object_marking_refs": [
        "marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168"
      ],
      "revoked": false,
      "spec_version": "2.1",
      "type": "attack-pattern",
      "x_mitre_attack_spec_version": "3.2.0",
      "x_mitre_data_sources": [
        "Application Log: Application Log Content",
        "Sensor Health: Host Status",
        "Network Traffic: Network Traffic Content",
        "Network Traffic: Network Traffic Flow"
      ],
      "x_mitre_deprecated": false,
      "x_mitre_detection": "Attacks targeting web applications may generate logs in the web server, application server, and/or database server that can be used to identify the type of attack. Externally monitor the availability of services that may be targeted by an Endpoint DoS.",
      "x_mitre_domains": [
        "enterprise-attack"
      ],
      "x_mitre_impact_type": [
        "Availability"
      ],
      "x_mitre_is_subtechnique": true,
      "x_mitre_modified_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
      "x_mitre_platforms": [
        "Windows",
        "IaaS",
        "Linux",
        "macOS"
      ],
      "x_mitre_version": "1.3"
    }
  ]
}
```

And the 7.0 version of T1499.004;

```shell
curl -X 'GET' \
  'https://api.ctibutler.com/v1/attack-enterprise/objects/T1499.004/?attack_version=7.0' \
  -H 'accept: application/json' \
  -H 'API-KEY: REDACTED'
```

```json
{
  "page_size": 50,
  "page_number": 1,
  "page_results_count": 1,
  "total_results_count": 1,
  "objects": [
    {
      "created": "2020-02-20T15:37:27.052Z",
      "created_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
      "description": "Adversaries may exploit software vulnerabilities that can cause an application or system to crash and deny availability to users. (Citation: Sucuri BIND9 August 2015) Some systems may automatically restart critical applications and services when crashes occur, but they can likely be re-exploited to cause a persistent DoS condition.",
      "external_references": [
        {
          "source_name": "mitre-attack",
          "external_id": "T1499.004",
          "url": "https://attack.mitre.org/techniques/T1499/004"
        },
        {
          "source_name": "Sucuri BIND9 August 2015",
          "url": "https://blog.sucuri.net/2015/08/bind9-denial-of-service-exploit-in-the-wild.html",
          "description": "Cid, D.. (2015, August 2). BIND9 – Denial of Service Exploit in the Wild. Retrieved April 26, 2019."
        }
      ],
      "id": "attack-pattern--2bee5ffb-7a7a-4119-b1f2-158151b19ac0",
      "kill_chain_phases": [
        {
          "kill_chain_name": "mitre-attack",
          "phase_name": "impact"
        }
      ],
      "modified": "2020-03-29T02:07:27.508Z",
      "name": "Application or System Exploitation",
      "object_marking_refs": [
        "marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168"
      ],
      "spec_version": "2.1",
      "type": "attack-pattern",
      "x_mitre_attack_spec_version": "2.1.0",
      "x_mitre_data_sources": [
        "Network device logs",
        "Network intrusion detection system",
        "Web application firewall logs",
        "Web logs",
        "SSL/TLS inspection"
      ],
      "x_mitre_detection": "Attacks targeting web applications may generate logs in the web server, application server, and/or database server that can be used to identify the type of attack. Externally monitor the availability of services that may be targeted by an Endpoint DoS.",
      "x_mitre_domains": [
        "enterprise-attack"
      ],
      "x_mitre_impact_type": [
        "Availability"
      ],
      "x_mitre_is_subtechnique": true,
      "x_mitre_modified_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
      "x_mitre_platforms": [
        "Linux",
        "macOS",
        "Windows",
        "AWS",
        "GCP",
        "Azure",
        "Office 365",
        "Azure AD",
        "SaaS"
      ],
      "x_mitre_version": "1.0"
    }
  ]
}
```

### Examining relationships between objects

CTI Butler is built on a graph database making it possible to easily traverse connections between objects.

This request returns all relationships `T1499.004` is found in;

```shell
curl -X 'GET' \
  'https://api.ctibutler.com/v1/attack-enterprise/objects/T1499.004/relationships/' \
  -H 'accept: application/json' \
  -H 'API-KEY: REDACTED'
```

```json
{
  "page_size": 50,
  "page_number": 1,
  "page_results_count": 9,
  "total_results_count": 9,
  "relationships": [
    {
      "created": "2014-06-23T00:00:00.000Z",
      "created_by_ref": "identity--2e51a631-99d8-52a5-95a6-8314d3f4fbf3",
      "description": "CAPEC-25 (Forced Deadlock) uses technique T1499.004 (Application or System Exploitation)",
      "external_references": [
        {
          "source_name": "capec",
          "external_id": "CAPEC-25",
          "url": "https://capec.mitre.org/data/definitions/25.html"
        },
        {
          "source_name": "mitre-attack",
          "external_id": "T1499.004"
        }
      ],
      "id": "relationship--5c3a67e5-c0c4-5676-a6db-2ebc324d1905",
      "modified": "2022-09-29T00:00:00.000Z",
      "object_marking_refs": [
        "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
        "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
      ],
      "relationship_type": "technique",
      "source_ref": "attack-pattern--36a2f844-0c20-41d7-9a10-66f1e4c43db8",
      "target_ref": "attack-pattern--2bee5ffb-7a7a-4119-b1f2-158151b19ac0",
      "type": "relationship"
    },
    {
      "created": "2022-03-30T14:26:51.834Z",
      "created_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
      "description": "Monitor for third-party application logging, messaging, and/or other artifacts that may exploit software vulnerabilities that can cause an application or system to crash and deny availability to users. (Citation: Sucuri BIND9 August 2015) Attacks targeting web applications may generate logs in the web server, application server, and/or database server that can be used to identify the type of attack. Externally monitor the availability of services that may be targeted by an Endpoint DoS.",
      "external_references": [
        {
          "source_name": "Sucuri BIND9 August 2015",
          "description": "Cid, D.. (2015, August 2). BIND9 – Denial of Service Exploit in the Wild. Retrieved April 26, 2019.",
          "url": "https://blog.sucuri.net/2015/08/bind9-denial-of-service-exploit-in-the-wild.html"
        }
      ],
      "id": "relationship--499da978-fa64-469e-901a-0d5db2b8b2f3",
      "modified": "2022-03-30T14:26:51.834Z",
      "object_marking_refs": [
        "marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168"
      ],
      "relationship_type": "detects",
      "source_ref": "x-mitre-data-component--9c2fa0ae-7abc-485a-97f6-699e3b6cf9fa",
      "spec_version": "2.1",
      "target_ref": "attack-pattern--2bee5ffb-7a7a-4119-b1f2-158151b19ac0",
      "type": "relationship",
      "x_mitre_attack_spec_version": "2.1.0",
      "x_mitre_domains": [
        "enterprise-attack"
      ],
      "x_mitre_modified_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
      "x_mitre_version": "1.0"
    },
```

It's also possible to get this data in an entire bundle, including the vertex objects included as follows;

```shell
curl -X 'GET' \
  'https://api.ctibutler.com/v1/attack-enterprise/objects/T1499.004/bundle/' \
  -H 'accept: application/json' \
  -H 'API-KEY: REDACTED'
```

The response of this endpoint can be loaded into a STIX bundle and directly onto a graph viewer. Here is what that looks like;

<div class="stixview" data-stix-url="/assets/images/blog/2025-01-20/T1499_004_bundle.json" data-stix-allow-dragdrop="false" data-show-idrefs="false" data-show-markings="true" data-show-sidebar="true" data-graph-layout="cise" data-caption="T1499.004 bundle" data-disable-mouse-zoom="false" data-graph-width="100%" data-graph-height="85vh" data-show-footer="true"></div>

### Examining relationships between frameworks

One of the biggest challenges with all these frameworks is that they are often treated in silo's.

For example, ATT&CK techniques can be linked to CAPEC techniques, CWEs to ATT&CK objects, etc.

CTI Butler provides the ability to join frameworks so they can be traversed like this. It does this using another of our tools [Arango CTI Processor](https://github.com/muchdogesec/arango_cti_processor/).

You'll see the first relationship object I printed in the last response was;

```json
    {
      "created": "2014-06-23T00:00:00.000Z",
      "created_by_ref": "identity--2e51a631-99d8-52a5-95a6-8314d3f4fbf3",
      "description": "CAPEC-25 (Forced Deadlock) uses technique T1499.004 (Application or System Exploitation)",
      "external_references": [
        {
          "source_name": "capec",
          "external_id": "CAPEC-25",
          "url": "https://capec.mitre.org/data/definitions/25.html"
        },
        {
          "source_name": "mitre-attack",
          "external_id": "T1499.004"
        }
      ],
      "id": "relationship--5c3a67e5-c0c4-5676-a6db-2ebc324d1905",
      "modified": "2022-09-29T00:00:00.000Z",
      "object_marking_refs": [
        "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
        "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
      ],
      "relationship_type": "technique",
      "source_ref": "attack-pattern--36a2f844-0c20-41d7-9a10-66f1e4c43db8",
      "target_ref": "attack-pattern--2bee5ffb-7a7a-4119-b1f2-158151b19ac0",
      "type": "relationship"
    }
```

Here we can see CAPEC-25 uses the ATT&CK sub-technique T1499.004.

For reference, here's CAPEC-25;

```shell
curl -X 'GET' \
  'https://api.ctibutler.com/v1/capec/objects/CAPEC-25/' \
  -H 'accept: application/json' \
  -H 'API-KEY: REDACTED'
```

```json
{
  "page_size": 50,
  "page_number": 1,
  "page_results_count": 1,
  "total_results_count": 1,
  "objects": [
    {
      "created": "2014-06-23T00:00:00.000Z",
      "created_by_ref": "identity--e50ab59c-5c4f-4d40-bf6a-d58418d89bcd",
      "description": "The adversary triggers and exploits a deadlock condition in the target software to cause a denial of service. A deadlock can occur when two or more competing actions are waiting for each other to finish, and thus neither ever does. Deadlock conditions can be difficult to detect.",
      "external_references": [
        {
          "external_id": "CAPEC-25",
          "source_name": "capec",
          "url": "https://capec.mitre.org/data/definitions/25.html"
        },
        {
          "external_id": "CWE-412",
          "source_name": "cwe",
          "url": "http://cwe.mitre.org/data/definitions/412.html"
        },
        {
          "external_id": "CWE-567",
          "source_name": "cwe",
          "url": "http://cwe.mitre.org/data/definitions/567.html"
        },
        {
          "external_id": "CWE-662",
          "source_name": "cwe",
          "url": "http://cwe.mitre.org/data/definitions/662.html"
        },
        {
          "external_id": "CWE-667",
          "source_name": "cwe",
          "url": "http://cwe.mitre.org/data/definitions/667.html"
        },
        {
          "external_id": "CWE-833",
          "source_name": "cwe",
          "url": "http://cwe.mitre.org/data/definitions/833.html"
        },
        {
          "external_id": "CWE-1322",
          "source_name": "cwe",
          "url": "http://cwe.mitre.org/data/definitions/1322.html"
        },
        {
          "description": "Endpoint Denial of Service: Application or System Exploitation",
          "external_id": "T1499.004",
          "source_name": "ATTACK",
          "url": "https://attack.mitre.org/wiki/Technique/T1499/004"
        },
        {
          "description": "G. Hoglund, G. McGraw, Exploiting Software: How to Break Code, 2004--02, Addison-Wesley",
          "external_id": "REF-1",
          "source_name": "reference_from_CAPEC"
        },
        {
          "description": "Wikipedia, The Wikimedia Foundation, Inc",
          "external_id": "REF-101",
          "source_name": "reference_from_CAPEC",
          "url": "http://en.wikipedia.org/wiki/Deadlock"
        },
        {
          "description": "OWASP Web Security Testing Guide, The Open Web Application Security Project (OWASP)",
          "external_id": "REF-609",
          "source_name": "reference_from_CAPEC",
          "url": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/07-Testing_for_XML_Injection.html"
        }
      ],
      "id": "attack-pattern--36a2f844-0c20-41d7-9a10-66f1e4c43db8",
      "modified": "2022-09-29T00:00:00.000Z",
      "name": "Forced Deadlock",
      "object_marking_refs": [
        "marking-definition--17d82bb2-eeeb-4898-bda5-3ddbcd2b799d"
      ],
      "spec_version": "2.1",
      "type": "attack-pattern",
      "x_capec_abstraction": "Meta",
      "x_capec_consequences": {
        "Availability": [
          "Resource Consumption (A successful forced deadlock attack compromises the availability of the system by exhausting its available resources.)"
        ]
      },
      "x_capec_domains": [
        "Software"
      ],
      "x_capec_example_instances": [
        "An example of a deadlock which may occur in database products is the following. Client applications using the database may require exclusive access to a table, and in order to gain exclusive access they ask for a lock. If one client application holds a lock on a table and attempts to obtain the lock on a second table that is already held by a second client application, this may lead to deadlock if the second application then attempts to obtain the lock that is held by the first application (Source: Wikipedia, http://en.wikipedia.org/wiki/Deadlock)"
      ],
      "x_capec_execution_flow": "<h2> Execution Flow </h2><div><h3>Explore</h3><ol><li> <p>The adversary initiates an exploratory phase to get familiar with the system.</p></li><li> <p>The adversary triggers a first action (such as holding a resource) and initiates a second action which will wait for the first one to finish.</p></li><li> <p>If the target program has a deadlock condition, the program waits indefinitely resulting in a denial of service.</p></li></ol></div>",
      "x_capec_likelihood_of_attack": "Low",
      "x_capec_prerequisites": [
        "The target host has a deadlock condition. There are four conditions for a deadlock to occur, known as the Coffman conditions. [REF-101]",
        "The target host exposes an API to the user."
      ],
      "x_capec_skills_required": {
        "Medium": "This type of attack may be sophisticated and require knowledge about the system's resources and APIs."
      },
      "x_capec_status": "Stable",
      "x_capec_typical_severity": "High",
      "x_capec_version": "3.9"
    }
  ]
}
```

## Exploring the MITRE ATT&CK TAXII API

The MITRE ATT&CK team [recently bumped their TAXII Server from TAXII 2.0 to TAXII 2.1](https://medium.com/mitre-attack/introducing-taxii-2-1-and-a-fond-farewell-to-taxii-2-0-d9fca6ce4c58).

TAXII is great for downloading the entire knowledgebase, but not suited to search and filtering, and was one of the big drivers for us to build the REST API described above.

However, we do know TAXII is a well loved integration transport mechanism as it is natively supported by lots of other security tooling, namely MISP.

Given we had all the STIX data in the CTI Butler database, it was easy for us to integrate a TAXII Server using [Arango TAXII Server](https://github.com/muchdogesec/arango_taxii_server) and expose all frameworks, not just ATT&CK.

### Finding collections

Generally if you were using a TAXII Client this would be configured in the tool itself.

```shell
curl -X 'GET' \
  'https://taxii.ctibutler.com/v1/' \
  -H 'accept: application/taxii+json;version=2.1' \
  -H 'API-KEY: REDACTED'
```

```json
{
  "title": "CTI Butler TAXII API",
  "description": "The most important cyber threat intelligence knowledgebases accessible via a single API.",
  "contact": "https://support.dogesec.com/",
  "api_roots": [
    "https://taxii.ctibutler.com/taxii_server/taxii2/ctibutler_database/"
  ]
}
```

Using the API Root returned (`ctibutler_database`), we can then see the TAXII Collections held within it;

```shell
curl -X 'GET' \
  'https://taxii.ctibutler.com/v1/ctibutler_database/collections/' \
  -H 'accept: application/taxii+json;version=2.1' \
  -H 'API-KEY: REDACTED'
```

```json
{
  "collections": [
    {
      "id": "mitre_cwe",
      "title": "mitre_cwe",
      "description": null,
      "can_read": true,
      "can_write": false,
      "media_types": [
        "application/stix+json;version=2.1"
      ]
    },
    {
      "id": "mitre_attack_ics",
      "title": "mitre_attack_ics",
      "description": null,
      "can_read": true,
      "can_write": false,
      "media_types": [
        "application/stix+json;version=2.1"
      ]
    },
```

### Searching the objects in a collection

One of the collections cut from the response above is `mitre_attack_enterprise`. We can interrogate the objects inside it using the `objects/` endpoint.

Here I also add the `type` filter to limit the results to only include `attack-pattern` STIX objects;

```shell
curl -X 'GET' \
  'https://taxii.ctibutler.com/v1/ctibutler_database/collections/mitre_attack_enterprise/objects/?match%5Btype%5D=attack-pattern' \
  -H 'accept: application/taxii+json;version=2.1' \
  -H 'API-KEY: 3As2pMzj.C1Zmgkb8yEVZJdC8eKBPpzpc36BsJkW9'
```

```json
{
  "more": true,
  "next": "3308368_2025-01-03T10:47:00.690987Z",
  "objects": [
    {
      "created": "2020-01-14T17:18:32.126Z",
      "created_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
      "description": "Adversaries may inject malicious code into process via Extra Window Memory (EWM) in order to evade process-based defenses as well as possibly elevate privileges. EWM injection is a method of executing arbitrary code in the address space of a separate live process. \n\nBefore creating a window, graphical Windows-based processes must prescribe to or register a windows class, which stipulate appearance and behavior (via windows procedures, which are functions that handle input/output of data).(Citation: Microsoft Window Classes) Registration of new windows classes can include a request for up to 40 bytes of EWM to be appended to the allocated memory of each instance of that class. This EWM is intended to store data specific to that window and has specific application programming interface (API) functions to set and get its value. (Citation: Microsoft GetWindowLong function) (Citation: Microsoft SetWindowLong function)\n\nAlthough small, the EWM is large enough to store a 32-bit pointer and is often used to point to a windows procedure. Malware may possibly utilize this memory location in part of an attack chain that includes writing code to shared sections of the process’s memory, placing a pointer to the code in EWM, then invoking execution by returning execution control to the address in the process’s EWM.\n\nExecution granted through EWM injection may allow access to both the target process's memory and possibly elevated privileges. Writing payloads to shared sections also avoids the use of highly monitored API calls such as <code>WriteProcessMemory</code> and <code>CreateRemoteThread</code>.(Citation: Elastic Process Injection July 2017) More sophisticated malware samples may also potentially bypass protection mechanisms such as data execution prevention (DEP) by triggering a combination of windows procedures and other system functions that will rewrite the malicious payload inside an executable portion of the target process.  (Citation: MalwareTech Power Loader Aug 2013) (Citation: WeLiveSecurity Gapz and Redyms Mar 2013)\n\nRunning code in the context of another process may allow access to the process's memory, system/network resources, and possibly elevated privileges. Execution via EWM injection may also evade detection from security products since the execution is masked under a legitimate process. ",
      "external_references": [
        {
          "source_name": "mitre-attack",
          "external_id": "T1055.011",
          "url": "https://attack.mitre.org/techniques/T1055/011"
        },
        {
          "url": "https://msdn.microsoft.com/library/windows/desktop/ms633574.aspx",
          "description": "Microsoft. (n.d.). About Window Classes. Retrieved December 16, 2017.",
          "source_name": "Microsoft Window Classes"
        },
        {
          "url": "https://msdn.microsoft.com/library/windows/desktop/ms633584.aspx",
          "description": "Microsoft. (n.d.). GetWindowLong function. Retrieved December 16, 2017.",
          "source_name": "Microsoft GetWindowLong function"
        },
        {
          "url": "https://msdn.microsoft.com/library/windows/desktop/ms633591.aspx",
          "description": "Microsoft. (n.d.). SetWindowLong function. Retrieved December 16, 2017.",
          "source_name": "Microsoft SetWindowLong function"
        },
        {
          "url": "https://www.endgame.com/blog/technical-blog/ten-process-injection-techniques-technical-survey-common-and-trending-process",
          "description": "Hosseini, A. (2017, July 18). Ten Process Injection Techniques: A Technical Survey Of Common And Trending Process Injection Techniques. Retrieved December 7, 2017.",
          "source_name": "Elastic Process Injection July 2017"
        },
        {
          "url": "https://www.malwaretech.com/2013/08/powerloader-injection-something-truly.html",
          "description": "MalwareTech. (2013, August 13). PowerLoader Injection – Something truly amazing. Retrieved December 16, 2017.",
          "source_name": "MalwareTech Power Loader Aug 2013"
        },
        {
          "url": "https://www.welivesecurity.com/2013/03/19/gapz-and-redyms-droppers-based-on-power-loader-code/",
          "description": "Matrosov, A. (2013, March 19). Gapz and Redyms droppers based on Power Loader code. Retrieved December 16, 2017.",
          "source_name": "WeLiveSecurity Gapz and Redyms Mar 2013"
        },
        {
          "url": "https://msdn.microsoft.com/library/windows/desktop/ms644953.aspx",
          "description": "Microsoft. (n.d.). SendNotifyMessage function. Retrieved December 16, 2017.",
          "source_name": "Microsoft SendNotifyMessage function"
        }
      ],
      "id": "attack-pattern--0042a9f5-f053-4769-b3ef-9ad018dfa298",
```

### Retrieving different versions of objects

Using the ATT&CK Enterprise object T1499.004 (`attack-pattern--2bee5ffb-7a7a-4119-b1f2-158151b19ac0`) I can explore the versions of it in a similar way to the REST endpoint as follows;

```shell
curl -X 'GET' \
  'https://taxii.ctibutler.com/v1/ctibutler_database/collections/mitre_attack_enterprise/objects/attack-pattern--2bee5ffb-7a7a-4119-b1f2-158151b19ac0/versions/' \
  -H 'accept: application/taxii+json;version=2.1' \
  -H 'API-KEY: REDACTED'
```

```json
{
  "more": false,
  "next": null,
  "versions": [
    "2020-03-29T02:07:27.508Z",
    "2021-03-29T16:09:41.559Z",
    "2022-03-25T18:11:13.604Z",
    "2022-05-11T14:00:00.188Z",
    "2024-10-15T15:42:23.001Z"
  ]
}
```

Although the response is slightly different, it shows the same thing; T1499.004 has been modified 5 times since creation.

To get a specific version of T1499.004 as listed above;

```shell
curl -X 'GET' \
  'https://taxii.ctibutler.com/v1/ctibutler_database/collections/mitre_attack_enterprise/objects/attack-pattern--2bee5ffb-7a7a-4119-b1f2-158151b19ac0/?match%5Bversion%5D=2020-03-29T02%3A07%3A27.508Z' \
  -H 'accept: application/taxii+json;version=2.1' \
  -H 'API-KEY: REDACTED'
```

```json
{
  "more": false,
  "next": null,
  "objects": [
    {
      "created": "2020-02-20T15:37:27.052Z",
      "created_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
      "description": "Adversaries may exploit software vulnerabilities that can cause an application or system to crash and deny availability to users. (Citation: Sucuri BIND9 August 2015) Some systems may automatically restart critical applications and services when crashes occur, but they can likely be re-exploited to cause a persistent DoS condition.",
      "external_references": [
        {
          "source_name": "mitre-attack",
          "external_id": "T1499.004",
          "url": "https://attack.mitre.org/techniques/T1499/004"
        },
        {
          "source_name": "Sucuri BIND9 August 2015",
          "url": "https://blog.sucuri.net/2015/08/bind9-denial-of-service-exploit-in-the-wild.html",
          "description": "Cid, D.. (2015, August 2). BIND9 – Denial of Service Exploit in the Wild. Retrieved April 26, 2019."
        }
      ],
      "id": "attack-pattern--2bee5ffb-7a7a-4119-b1f2-158151b19ac0",
      "kill_chain_phases": [
        {
          "kill_chain_name": "mitre-attack",
          "phase_name": "impact"
        }
      ],
      "modified": "2020-03-29T02:07:27.508Z",
      "name": "Application or System Exploitation",
      "object_marking_refs": [
        "marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168"
      ],
      "spec_version": "2.1",
      "type": "attack-pattern",
      "x_mitre_attack_spec_version": "2.1.0",
      "x_mitre_data_sources": [
        "Network device logs",
        "Network intrusion detection system",
        "Web application firewall logs",
        "Web logs",
        "SSL/TLS inspection"
      ],
      "x_mitre_detection": "Attacks targeting web applications may generate logs in the web server, application server, and/or database server that can be used to identify the type of attack. Externally monitor the availability of services that may be targeted by an Endpoint DoS.",
      "x_mitre_domains": [
        "enterprise-attack"
      ],
      "x_mitre_impact_type": [
        "Availability"
      ],
      "x_mitre_is_subtechnique": true,
      "x_mitre_modified_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
      "x_mitre_platforms": [
        "Linux",
        "macOS",
        "Windows",
        "AWS",
        "GCP",
        "Azure",
        "Office 365",
        "Azure AD",
        "SaaS"
      ],
      "x_mitre_version": "1.0"
    }
  ]
}
```

## In summary

There's much more to CTI Butler. [The easiest way to find out what else it can do is to play with it for yourself here](https://www.ctibutler.com/).