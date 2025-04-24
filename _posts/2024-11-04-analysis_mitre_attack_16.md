---
date: 2024-11-04
last_modified: 2024-11-04
title: "An Analysis of the Changes in ATT&CK Version 16.0"
description: "Your handy guide to streamlining upgrades of MITRE ATT&CK by comparing the changes made between releases."
categories:
  - RESEARCH
tags: [
    MITRE,
    ATT&CK,
    STIX
]
products:
    - stix2arango
    - arango_cti_processor
    - CTIButler
author_staff_member: david-greenwood
image: /assets/images/blog/2024-11-04/attack-enterprise-object-types-by-version-15_1-16_0-meta.png
featured_image: /assets/images/blog/2024-11-04/attack-enterprise-object-types-by-version-15_1-16_0-meta.png
layout: post
published: true
redirect_from:
  - 
---

## tl;dr

Your handy guide to streamlining upgrades of MITRE ATT&CK by comparing the changes made between releases.

## Key Findings

* ATT&CK Enterprise
  * 70 new objects
  * 378 modified objects
  * 1318 unchanged objects
  * 0 deprecated objects
  * 0 revoked objects
* ATT&CK Mobile
  * 0 new objects
  * 10 modified objects
  * 287 unchanged objects
  * 1 deprecated objects
  * 0 revoked objects
* ATT&CK ICS
  * 1 new objects
  * 18 modified objects
  * 275 unchanged objects
  * 0 deprecated objects
  * 0 revoked objects

## Overview

[The team at MITRE recently announced the launch of ATT&CK v16.0](https://medium.com/mitre-attack/attack-v16-561c76af94cf).

We are big users of ATT&CK, using it to add additional context to our intelligence. [You might have seen my fanboy post earlier this year describing the structure of the ATT&CK framework](/blog/mitre_attack_data_structure).

[Whilst the ATT&CK team keep a great change-log in their release notes](https://attack.mitre.org/resources/updates/updates-october-2024/), I wanted to dive deeper into the changes to better understand the changes.

This post walks you through my analysis.

## Follow along

In this post I am going to provide ArangoDB queries you can use to analyse and filter MITRE ATT&CK data.

If you would like to follow along, and keep a searchable copy of ATT&CK locally, you can import the data using [stix2arango](https://github.com/muchdogesec/stix2arango/).

Once you've installed stix2arango, you can run the following command to import all versions of the MITRE ATT&CK Enterprise, ICS, and Mobile datasets at the time of writing;

```shell
python3 utilities/arango_cti_processor/insert_archive_attack_enterprise.py \
    --database blog_demo \
    --ignore_embedded_relationships && \
python3 utilities/arango_cti_processor/insert_archive_attack_ics.py \
    --database blog_demo \
    --ignore_embedded_relationships && \
python3 utilities/arango_cti_processor/insert_archive_attack_mobile.py \
    --database blog_demo \
    --ignore_embedded_relationships
```

You can then use the query interface in the ArangoDB UI to run the AQL queries in this post.

_Note, in this post I show queries searching the Enterprise domain (`mitre_attack_enterprise_vertex_collection`), but show results for all matrices. To get the data for each matrix all you need to do is modify `enterprise` for `ics` or `mobile` to get the results for the specified matrix._

## ATT&CK through the ages

To begin, here is a query that shows the growth of the ATT&CK matrices over each release;

```sql
FOR doc IN mitre_attack_enterprise_vertex_collection
FILTER doc._stix2arango_note != "automatically imported on collection creation"
AND doc.x_mitre_deprecated != true
AND doc.revoked != true
COLLECT version = doc._stix2arango_note WITH COUNT INTO count
RETURN { "version": version, "count": count }
```

<img class="img-fluid" src="/assets/images/blog/2024-11-04/attack-enterprise-objects-by-version.png" alt="ATT&CK Enterprise Objects by version" title="ATT&CK Enterprise Objects by version" />

<img class="img-fluid" src="/assets/images/blog/2024-11-04/attack-mobile-objects-by-version.png" alt="ATT&CK Mobile Objects by version" title="ATT&CK Mobile Objects by version" />

<img class="img-fluid" src="/assets/images/blog/2024-11-04/attack-ics-objects-by-version.png" alt="ATT&CK ICS Objects by version" title="ATT&CK ICS Objects by version" />


## ATT&CK objects changes between version 15.1 and 16.0

This query looks at each object type and shows the count of those that have been changed, added, deprecated, revoked, or have stayed the same between 15.1 and 16.0;

```sql
FOR doc IN mitre_attack_enterprise_vertex_collection
FILTER doc._stix2arango_note IN ["v15.1", "v16.0"]
COLLECT id = doc.id, type = doc.type INTO groupedDocs

LET versions = groupedDocs[*].doc
LET createdDates = UNIQUE(versions[*].created)
LET modifiedDates = UNIQUE(versions[*].modified)
LET count_versions = LENGTH(versions)

LET deprecatedInV16 = LENGTH(FOR v IN versions FILTER v._stix2arango_note == "v16.0" AND v.x_mitre_deprecated == true RETURN v) > 0
LET deprecatedInV15 = LENGTH(FOR v IN versions FILTER v._stix2arango_note == "v15.1" AND v.x_mitre_deprecated == true RETURN v) > 0

LET revokedInV16 = LENGTH(FOR v IN versions FILTER v._stix2arango_note == "v16.0" AND v.revoked == true RETURN v) > 0
LET revokedInV15 = LENGTH(FOR v IN versions FILTER v._stix2arango_note == "v15.1" AND v.revoked == true RETURN v) > 0

// Filter out results where x_mitre_deprecated or revoked is true in both versions
FILTER NOT (deprecatedInV15 == true AND deprecatedInV16 == true)
FILTER NOT (revokedInV15 == true AND revokedInV16 == true)

LET status = (
    count_versions == 1 ? "new" :
    (revokedInV16 == true AND revokedInV15 == false ? "revoked" :
    (deprecatedInV16 == true AND deprecatedInV15 == false ? "deprecated" :
    (LENGTH(createdDates) == 1 AND LENGTH(modifiedDates) == 1 ? "unchanged" : "changed")))
)

COLLECT finalStatus = status, finalType = type WITH COUNT INTO count

// Aggregate results by status
COLLECT status = finalStatus INTO typeCounts = {
  "type": finalType,
  "count": count
}

// Construct dynamic columns for each type
RETURN MERGE(
  { "status": status },
  ZIP(
    typeCounts[*].type,
    typeCounts[*].count
  )
)
```

<img class="img-fluid" src="/assets/images/blog/2024-11-04/attack-enterprise-object-types-by-version-15_1-16_0.png" alt="ATT&CK Enterprise Object type by version" title="ATT&CK Enterprise Object type by version" />

<img class="img-fluid" src="/assets/images/blog/2024-11-04/attack-mobile-object-types-by-version-15_1-16_0.png" alt="ATT&CK Mobile Object type by version" title="ATT&CK Mobile Object type by version" />

<img class="img-fluid" src="/assets/images/blog/2024-11-04/attack-ics-object-types-by-version-15_1-16_0.png" alt="ATT&CK ICS Object type by version" title="ATT&CK ICS Object type by version" />

## New ATT&CK objects changes between version v15.1 and v16.0

This query will produce a list of objects that have been added in version 16.0;

```sql
FOR doc IN mitre_attack_enterprise_vertex_collection
FILTER doc._stix2arango_note IN ["v15.1", "v16.0"]
COLLECT id = doc.id INTO groupedDocs

LET versions = groupedDocs[*].doc
LET count_versions = LENGTH(versions)

// Only include objects that are classified as "new" (present in only one version)
FILTER count_versions == 1

// Extract external_id where source_name is "mitre-attack"
LET mitre_attack_id = FIRST(
    FOR ref IN versions[0].external_references
    FILTER ref.source_name == "mitre-attack"
    RETURN ref.external_id
)

// Return only the specified fields
RETURN {
    "type": versions[0].type,
    "external_id": mitre_attack_id,
    "name": versions[0].name
}
```

### New objects in ATT&CK Enterprise v16.0

| type             | external_id | name                                      |
| ---------------- | ----------- | ----------------------------------------- |
| attack-pattern   | T1666       | Modify Cloud Resource Hierarchy           |
| attack-pattern   | T1485.001   | Lifecycle-Triggered Deletion              |
| attack-pattern   | T1496.003   | SMS Pumping                               |
| attack-pattern   | T1071.005   | Publish/Subscribe Protocols               |
| attack-pattern   | T1558.005   | Ccache Files                              |
| attack-pattern   | T1098.007   | Additional Local or Domain Groups         |
| attack-pattern   | T1557.004   | Evil Twin                                 |
| attack-pattern   | T1480.002   | Mutual Exclusion                          |
| attack-pattern   | T1496.002   | Bandwidth Hijacking                       |
| attack-pattern   | T1496.004   | Cloud Service Hijacking                   |
| attack-pattern   | T1496.001   | Compute Hijacking                         |
| attack-pattern   | T1059.011   | Lua                                       |
| attack-pattern   | T1027.014   | Polymorphic Code                          |
| attack-pattern   | T1213.004   | Customer Relationship Management Software |
| attack-pattern   | T1127.002   | ClickOnce                                 |
| attack-pattern   | T1070.010   | Relocate Malware                          |
| attack-pattern   | T1036.010   | Masquerade Account Name                   |
| attack-pattern   | T1546.017   | Udev Rules                                |
| attack-pattern   | T1213.005   | Messaging Applications                    |
| campaign         | C0035       | KV Botnet Activity                        |
| campaign         | C0037       | Water Curupira Pikabot Distribution       |
| campaign         | C0038       | HomeLand Justice                          |
| campaign         | C0036       | Pikabot Distribution February 2024        |
| campaign         | C0040       | APT41 DUST                                |
| campaign         | C0039       | Versa Director Zero Day Exploitation      |
| course-of-action | M1060       | Out-of-Band Communications Channel        |
| intrusion-set    | G1037       | TA577                                     |
| intrusion-set    | G1031       | Saint Bear                                |
| intrusion-set    | G1035       | Winter Vivern                             |
| intrusion-set    | G1039       | RedCurl                                   |
| intrusion-set    | G1033       | Star Blizzard                             |
| intrusion-set    | G1038       | TA578                                     |
| intrusion-set    | G1030       | Agrius                                    |
| intrusion-set    | G1032       | INC Ransom                                |
| intrusion-set    | G1036       | Moonstone Sleet                           |
| intrusion-set    | G1040       | Play                                      |
| intrusion-set    | G1034       | Daggerfly                                 |
| malware          | S1145       | Pikabot                                   |
| malware          | S1154       | VersaMem                                  |
| malware          | S1162       | Playcrypt                                 |
| malware          | S1152       | IMAPLoader                                |
| malware          | S1159       | DUSTTRAP                                  |
| malware          | S1158       | DUSTPAN                                   |
| malware          | S1138       | Gootloader                                |
| malware          | S1153       | Cuckoo Stealer                            |
| malware          | S1137       | Moneybird                                 |
| malware          | S1133       | Apostle                                   |
| malware          | S1130       | Raspberry Robin                           |
| malware          | S1147       | Nightdoor                                 |
| malware          | S1149       | CHIMNEYSWEEP                              |
| malware          | S1010       | VPNFilter                                 |
| malware          | S1143       | LunarLoader                               |
| malware          | S1135       | MultiLayer Wiper                          |
| malware          | S1160       | Latrodectus                               |
| malware          | S1140       | Spica                                     |
| malware          | S1161       | BPFDoor                                   |
| malware          | S1151       | ZeroCleare                                |
| malware          | S1146       | MgBot                                     |
| malware          | S1142       | LunarMail                                 |
| malware          | S1148       | Raccoon Stealer                           |
| malware          | S1132       | IPsec Helper                              |
| malware          | S1150       | ROADSWEEP                                 |
| malware          | S1136       | BFG Agonizer                              |
| malware          | S1156       | Manjusaka                                 |
| malware          | S1141       | LunarWeb                                  |
| malware          | S1139       | INC Ransomware                            |
| malware          | S1134       | DEADWOOD                                  |
| tool             | S1155       | Covenant                                  |
| tool             | S1131       | NPPSPY                                    |

### New objects in ATT&CK Mobile v16.0

None.

### New objects in ATT&CK ICS v16.0

| type    | external_id | name   |
| ------- | ----------- | ------ |
| malware | S1157       | Fuxnet |

## ATT&CK changes

To get a similar list of changed objects between versions, you can run the query;

```sql
FOR doc IN mitre_attack_enterprise_vertex_collection
FILTER doc._stix2arango_note IN ["v15.1", "v16.0"]
COLLECT id = doc.id INTO groupedDocs

LET versions = groupedDocs[*].doc
LET createdDates = UNIQUE(versions[*].created)
LET modifiedDates = UNIQUE(versions[*].modified)
LET count_versions = LENGTH(versions)

LET deprecatedInV16 = LENGTH(FOR v IN versions FILTER v._stix2arango_note == "v16.0" AND v.x_mitre_deprecated == true RETURN v) > 0
LET deprecatedInV15 = LENGTH(FOR v IN versions FILTER v._stix2arango_note == "v15.1" AND v.x_mitre_deprecated == true RETURN v) > 0

LET revokedInV16 = LENGTH(FOR v IN versions FILTER v._stix2arango_note == "v16.0" AND v.revoked == true RETURN v) > 0
LET revokedInV15 = LENGTH(FOR v IN versions FILTER v._stix2arango_note == "v15.1" AND v.revoked == true RETURN v) > 0

// Filter out results where x_mitre_deprecated or revoked is true in both versions
FILTER NOT (deprecatedInV15 == true AND deprecatedInV16 == true)
FILTER NOT (revokedInV15 == true AND revokedInV16 == true)

// Only include objects that are classified as "changed" (present in both versions with differences in created or modified dates)
LET status = (
    count_versions == 1 ? "new" :
    (revokedInV16 == true AND revokedInV15 == false ? "revoked" :
    (deprecatedInV16 == true AND deprecatedInV15 == false ? "deprecated" :
    (LENGTH(createdDates) == 1 AND LENGTH(modifiedDates) == 1 ? "unchanged" : "changed")))
)

FILTER status == "changed"

// Safely extract external_id where source_name is "mitre-attack", handling missing external_references
LET mitre_attack_id = FIRST(
    FOR ref IN versions[0].external_references || []
    FILTER ref.source_name == "mitre-attack"
    RETURN ref.external_id
)

// Return only the specified fields
RETURN {
    "type": versions[0].type,
    "external_id": mitre_attack_id,
    "name": versions[0].name
}
```

Once you have a list of IDs returned by the above query, you can use the following query to identify the properties changed. For example, here I am comparing T1053.005 (Scheduled Task/Job: Scheduled Task) between version 15.1 and 16.0.

```sql
// Specify the ID of the object to compare
LET target_id = "T1053.005"

// Gather both versions
LET docs = (
    FOR doc IN mitre_attack_enterprise_vertex_collection
    FILTER doc._stix2arango_note IN ["v15.1", "v16.0"]
    AND "mitre-attack" IN doc.external_references[*].source_name
    AND target_id IN doc.external_references[*].external_id
    RETURN { "version": doc._stix2arango_note, "doc": doc }
)

// Extract the documents for v15.1 and v16.0
LET v15_1 = FIRST(FOR d IN docs FILTER d.version == "v15.1" RETURN d.doc) || null
LET v16_0 = FIRST(FOR d IN docs FILTER d.version == "v16.0" RETURN d.doc) || null

// Only proceed if both versions are available
RETURN (v15_1 != null AND v16_0 != null) ? {
    "id": target_id,
    "differences": (
        FOR key IN ATTRIBUTES(v15_1)
        FILTER v15_1[key] != v16_0[key]
        AND !STARTS_WITH(key, "_")  // Exclude keys starting with an underscore
        RETURN {
            "field": key,
            "v15.1": v15_1[key],
            "v16.0": v16_0[key]
        }
    )
} : {
    "id": target_id,
    "error": "One or both versions are missing for comparison."
}
```

```json
[
  {
    "id": "T1053.005",
    "differences": [
      {
        "field": "modified",
        "v15.1": "2023-11-15T14:33:53.354Z",
        "v16.0": "2024-10-13T16:13:47.770Z"
      },
      {
        "field": "external_references",
        "v15.1": [
          {
            "source_name": "mitre-attack",
            "url": "https://attack.mitre.org/techniques/T1053/005",
            "external_id": "T1053.005"
          },
          {
            "source_name": "ProofPoint Serpent",
            "description": "Campbell, B. et al. (2022, March 21). Serpent, No Swiping! New Backdoor Targets French Entities with Unique Attack Chain. Retrieved April 11, 2022.",
            "url": "https://www.proofpoint.com/us/blog/threat-insight/serpent-no-swiping-new-backdoor-targets-french-entities-unique-attack-chain"
          },
          {
            "source_name": "Defending Against Scheduled Task Attacks in Windows Environments",
            "description": "Harshal Tupsamudre. (2022, June 20). Defending Against Scheduled Tasks. Retrieved July 5, 2022.",
            "url": "https://blog.qualys.com/vulnerabilities-threat-research/2022/06/20/defending-against-scheduled-task-attacks-in-windows-environments"
          },
          {
            "source_name": "Twitter Leoloobeek Scheduled Task",
            "description": "Loobeek, L. (2017, December 8). leoloobeek Status. Retrieved December 12, 2017.",
            "url": "https://twitter.com/leoloobeek/status/939248813465853953"
          },
          {
            "source_name": "Tarrask scheduled task",
            "description": "Microsoft Threat Intelligence Team & Detection and Response Team . (2022, April 12). Tarrask malware uses scheduled tasks for defense evasion. Retrieved June 1, 2022.",
            "url": "https://www.microsoft.com/security/blog/2022/04/12/tarrask-malware-uses-scheduled-tasks-for-defense-evasion/"
          },
          {
            "source_name": "Microsoft Scheduled Task Events Win10",
            "description": "Microsoft. (2017, May 28). Audit Other Object Access Events. Retrieved June 27, 2019.",
            "url": "https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-other-object-access-events"
          },
          {
            "source_name": "TechNet Scheduled Task Events",
            "description": "Microsoft. (n.d.). General Task Registration. Retrieved December 12, 2017.",
            "url": "https://technet.microsoft.com/library/dd315590.aspx"
          },
          {
            "source_name": "TechNet Autoruns",
            "description": "Russinovich, M. (2016, January 4). Autoruns for Windows v13.51. Retrieved June 6, 2016.",
            "url": "https://technet.microsoft.com/en-us/sysinternals/bb963902"
          },
          {
            "source_name": "TechNet Forum Scheduled Task Operational Setting",
            "description": "Satyajit321. (2015, November 3). Scheduled Tasks History Retention settings. Retrieved December 12, 2017.",
            "url": "https://social.technet.microsoft.com/Forums/en-US/e5bca729-52e7-4fcb-ba12-3225c564674c/scheduled-tasks-history-retention-settings?forum=winserver8gen"
          },
          {
            "source_name": "SigmaHQ",
            "description": "Sittikorn S. (2022, April 15). Removal Of SD Value to Hide Schedule Task - Registry. Retrieved June 1, 2022.",
            "url": "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_delete/registry_delete_schtasks_hide_task_via_sd_value_removal.yml"
          }
        ],
        "v16.0": [
          {
            "source_name": "mitre-attack",
            "url": "https://attack.mitre.org/techniques/T1053/005",
            "external_id": "T1053.005"
          },
          {
            "source_name": "ProofPoint Serpent",
            "description": "Campbell, B. et al. (2022, March 21). Serpent, No Swiping! New Backdoor Targets French Entities with Unique Attack Chain. Retrieved April 11, 2022.",
            "url": "https://www.proofpoint.com/us/blog/threat-insight/serpent-no-swiping-new-backdoor-targets-french-entities-unique-attack-chain"
          },
          {
            "source_name": "Defending Against Scheduled Task Attacks in Windows Environments",
            "description": "Harshal Tupsamudre. (2022, June 20). Defending Against Scheduled Tasks. Retrieved July 5, 2022.",
            "url": "https://blog.qualys.com/vulnerabilities-threat-research/2022/06/20/defending-against-scheduled-task-attacks-in-windows-environments"
          },
          {
            "source_name": "Twitter Leoloobeek Scheduled Task",
            "description": "Loobeek, L. (2017, December 8). leoloobeek Status. Retrieved September 12, 2024.",
            "url": "https://x.com/leoloobeek/status/939248813465853953"
          },
          {
            "source_name": "Tarrask scheduled task",
            "description": "Microsoft Threat Intelligence Team & Detection and Response Team . (2022, April 12). Tarrask malware uses scheduled tasks for defense evasion. Retrieved June 1, 2022.",
            "url": "https://www.microsoft.com/security/blog/2022/04/12/tarrask-malware-uses-scheduled-tasks-for-defense-evasion/"
          },
          {
            "source_name": "Microsoft Scheduled Task Events Win10",
            "description": "Microsoft. (2017, May 28). Audit Other Object Access Events. Retrieved June 27, 2019.",
            "url": "https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-other-object-access-events"
          },
          {
            "source_name": "TechNet Scheduled Task Events",
            "description": "Microsoft. (n.d.). General Task Registration. Retrieved December 12, 2017.",
            "url": "https://technet.microsoft.com/library/dd315590.aspx"
          },
          {
            "source_name": "Red Canary - Atomic Red Team",
            "description": "Red Canary - Atomic Red Team. (n.d.). T1053.005 - Scheduled Task/Job: Scheduled Task. Retrieved June 19, 2024.",
            "url": "https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1053.005/T1053.005.md"
          },
          {
            "source_name": "TechNet Autoruns",
            "description": "Russinovich, M. (2016, January 4). Autoruns for Windows v13.51. Retrieved June 6, 2016.",
            "url": "https://technet.microsoft.com/en-us/sysinternals/bb963902"
          },
          {
            "source_name": "TechNet Forum Scheduled Task Operational Setting",
            "description": "Satyajit321. (2015, November 3). Scheduled Tasks History Retention settings. Retrieved December 12, 2017.",
            "url": "https://social.technet.microsoft.com/Forums/en-US/e5bca729-52e7-4fcb-ba12-3225c564674c/scheduled-tasks-history-retention-settings?forum=winserver8gen"
          },
          {
            "source_name": "SigmaHQ",
            "description": "Sittikorn S. (2022, April 15). Removal Of SD Value to Hide Schedule Task - Registry. Retrieved June 1, 2022.",
            "url": "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_delete/registry_delete_schtasks_hide_task_via_sd_value_removal.yml"
          },
          {
            "source_name": "Stack Overflow",
            "description": "Stack Overflow. (n.d.). How to find the location of the Scheduled Tasks folder. Retrieved June 19, 2024.",
            "url": "https://stackoverflow.com/questions/2913816/how-to-find-the-location-of-the-scheduled-tasks-folder"
          }
        ]
      },
      {
        "field": "x_mitre_version",
        "v15.1": "1.5",
        "v16.0": "1.6"
      },
      {
        "field": "description",
        "v15.1": "Adversaries may abuse the Windows Task Scheduler to perform task scheduling for initial or recurring execution of malicious code. There are multiple ways to access the Task Scheduler in Windows. The [schtasks](https://attack.mitre.org/software/S0111) utility can be run directly on the command line, or the Task Scheduler can be opened through the GUI within the Administrator Tools section of the Control Panel. In some cases, adversaries have used a .NET wrapper for the Windows Task Scheduler, and alternatively, adversaries have used the Windows netapi32 library to create a scheduled task.\n\nThe deprecated [at](https://attack.mitre.org/software/S0110) utility could also be abused by adversaries (ex: [At](https://attack.mitre.org/techniques/T1053/002)), though <code>at.exe</code> can not access tasks created with <code>schtasks</code> or the Control Panel.\n\nAn adversary may use Windows Task Scheduler to execute programs at system startup or on a scheduled basis for persistence. The Windows Task Scheduler can also be abused to conduct remote Execution as part of Lateral Movement and/or to run a process under the context of a specified account (such as SYSTEM). Similar to [System Binary Proxy Execution](https://attack.mitre.org/techniques/T1218), adversaries have also abused the Windows Task Scheduler to potentially mask one-time execution under signed/trusted system processes.(Citation: ProofPoint Serpent)\n\nAdversaries may also create \"hidden\" scheduled tasks (i.e. [Hide Artifacts](https://attack.mitre.org/techniques/T1564)) that may not be visible to defender tools and manual queries used to enumerate tasks. Specifically, an adversary may hide a task from `schtasks /query` and the Task Scheduler by deleting the associated Security Descriptor (SD) registry value (where deletion of this value must be completed using SYSTEM permissions).(Citation: SigmaHQ)(Citation: Tarrask scheduled task) Adversaries may also employ alternate methods to hide tasks, such as altering the metadata (e.g., `Index` value) within associated registry keys.(Citation: Defending Against Scheduled Task Attacks in Windows Environments) ",
        "v16.0": "Adversaries may abuse the Windows Task Scheduler to perform task scheduling for initial or recurring execution of malicious code. There are multiple ways to access the Task Scheduler in Windows. The [schtasks](https://attack.mitre.org/software/S0111) utility can be run directly on the command line, or the Task Scheduler can be opened through the GUI within the Administrator Tools section of the Control Panel.(Citation: Stack Overflow) In some cases, adversaries have used a .NET wrapper for the Windows Task Scheduler, and alternatively, adversaries have used the Windows netapi32 library and [Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047) (WMI) to create a scheduled task. Adversaries may also utilize the Powershell Cmdlet `Invoke-CimMethod`, which leverages WMI class `PS_ScheduledTask` to create a scheduled task via an XML path.(Citation: Red Canary - Atomic Red Team)\n\nAn adversary may use Windows Task Scheduler to execute programs at system startup or on a scheduled basis for persistence. The Windows Task Scheduler can also be abused to conduct remote Execution as part of Lateral Movement and/or to run a process under the context of a specified account (such as SYSTEM). Similar to [System Binary Proxy Execution](https://attack.mitre.org/techniques/T1218), adversaries have also abused the Windows Task Scheduler to potentially mask one-time execution under signed/trusted system processes.(Citation: ProofPoint Serpent)\n\nAdversaries may also create \"hidden\" scheduled tasks (i.e. [Hide Artifacts](https://attack.mitre.org/techniques/T1564)) that may not be visible to defender tools and manual queries used to enumerate tasks. Specifically, an adversary may hide a task from `schtasks /query` and the Task Scheduler by deleting the associated Security Descriptor (SD) registry value (where deletion of this value must be completed using SYSTEM permissions).(Citation: SigmaHQ)(Citation: Tarrask scheduled task) Adversaries may also employ alternate methods to hide tasks, such as altering the metadata (e.g., `Index` value) within associated registry keys.(Citation: Defending Against Scheduled Task Attacks in Windows Environments) "
      }
    ]
  }
]
```

## A shout out to ATT&CK Sync

Having the objects in a database makes them easy to query however you choose.

Though many of you reading this will just want the review changes in a more simple manner. That's where a nicely crafted web interface on top of these queries helps.

Enter ATT&CK Sync...

<iframe width="560" height="315" src="https://www.youtube.com/embed/bj6q7vaPxxY?si=2PhFTD51vj5fzXDB" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>

> The ATT&CK Sync project streamlines upgrades to new versions of MITRE ATT&CK® by providing tools and resources to migrate existing projects to current ATT&CK versions in a timely and efficient manner.

_Source: [MITRE Engenuity](https://mitre-engenuity.org/cybersecurity/center-for-threat-informed-defense/attck-sync/)_

<img class="img-fluid" src="/assets/images/blog/2024-11-04/attack-sync-t1053-005.png" alt="ATT&CK Sync T1053.005" title="ATT&CK Sync T1053.005" />

Take the T1053.005 example I showed earlier. Whilst it only shows changes to the description, [ATT&CK Sync makes it much easier to compare what was actually changed](https://center-for-threat-informed-defense.github.io/attack-sync/v15.1-v16.0/enterprise-attack/techniques/).

In fact, ATT&CK Sync was a big inspiration for the ATT&CK part of [CTI Butler](https://www.ctibutler.com/) (which contains this feature for many popular CTI frameworks, not only ATT&CK).