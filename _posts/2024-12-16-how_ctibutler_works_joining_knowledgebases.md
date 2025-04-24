---
date: 2024-12-16
last_modified: 2024-12-16
title: "How CTI Butler Creates a Threat Intelligence Graph of Common Frameworks"
description: "CTI Butler links many common knowledge bases, for example linking MITRE ATT&CK to CAPEC objects, to improve the context of our research. This post describes the logic CTI Butler employs behind the scenes to do this."
categories:
  - RESEARCH
tags: [
	MITRE,
    ATT&CK,
    CWE,
    CAPEC,
    Sigma Rules,
    YARA,
    DISARM,
    STIX,
    ArangoDB,
    ATLAS
]
products:
    - stix2arango
    - arango_cti_processor
    - cve2stix
    - CTI Butler
author_staff_member: david-greenwood
image: /assets/images/blog/2024-12-16/ctibutler-api-attack-relationship.png
featured_image: /assets/images/blog/2024-12-16/ctibutler-api-attack-relationship.png
layout: post
published: true
redirect_from:
  - 
---

## tl;dr

CTI Butler links many common knowledge bases, for example linking MITRE ATT&CK to CAPEC objects, to improve the context of our research. This post describes the logic CTI Butler employs behind the scenes to do this.

## Overview

A lot of our tooling uses data held in [CTI Butler Web](https://github.com/muchdogesec/ctibutler) to enrich our intelligence research.

One of the most used features is finding relationships for objects in each knowledgebase, like MITRE ATT&CK Enterprise.

<img class="img-fluid" src="/assets/images/blog/2024-12-16/ctibutler-api-attack-relationship.png" alt="CTI Butler ATT&CK Relationship endpoint" title="CTI Butler ATT&CK Relationship endpoint" />

This allows users to not only link their research to a single object (i.e. ATT&CK Technique), but also finds all related objects to the source object (Technique in this example) which could also be useful to include in their reporting.

Under the hood, CTI Butler uses [arango_cti_processor](https://github.com/muchdogesec/arango_cti_processor/) to manage these relationships.

<img class="img-fluid" src="/assets/images/blog/2024-12-16/cti-butler-arango-cti-processor.png" alt="CTI Butler Arango CTI Processor" title="CTI Butler Arango CTI Processor" />

In this post I want to lift the lid and show you how arango_cti_processor works so you know how CTI Butler works.

## CTI Butler knowledgebases

At the time of writing CTI Butler supports the following datasets;

1. MITRE ATT&CK Enterprise
    * [data taken directly from the MITRE repository](https://github.com/mitre-attack/attack-stix-data/tree/master/enterprise-attack)
2. MITRE ATT&CK ICS
    * [data taken directly from the MITRE repository](https://github.com/mitre-attack/attack-stix-data/tree/master/ics-attack)
3. MITRE ATT&CK Mobile
    * [data taken directly from the MITRE repository](https://github.com/mitre-attack/attack-stix-data/tree/master/mobile-attack)
4. MITRE CAPEC
    * [data taken directly from the MITRE repository](https://github.com/mitre/cti/tree/master/capec/2.1)
5. MITRE CWE
    * [data converted to STIX using cwe2stix](https://github.com/muchdogesec/cwe2stix/issues)
6. MITRE ATLAS
    * [data taken from the MITRE repository](https://github.com/mitre-atlas/atlas-navigator-data/blob/main/dist/stix-atlas-attack-enterprise.json)
7. DISARM
    * [data converted to STIX using disarm2stix](https://github.com/muchdogesec/disarm2stix/)

Any relationships that exist in these bundles will be searchable in CTI Butler without arango_cti_processor, e.g.

```shell
curl -X 'GET' \
  'http://127.0.0.1:8006/api/v1/attack-enterprise/objects/t1049/relationships/' \
  -H 'accept: application/json'
```

```json
{
  "page_size": 50,
  "page_number": 1,
  "page_results_count": 50,
  "total_results_count": 99,
  "relationships": [
    {
      "created": "2020-11-17T19:32:21.422Z",
      "created_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
      "description": "[Lucifer](https://attack.mitre.org/software/S0532) can identify the IP and port numbers for all remote connections from the compromised host.(Citation: Unit 42 Lucifer June 2020)",
      "external_references": [
        {
          "source_name": "Unit 42 Lucifer June 2020",
          "url": "https://unit42.paloaltonetworks.com/lucifer-new-cryptojacking-and-ddos-hybrid-malware/",
          "description": "Hsu, K. et al. (2020, June 24). Lucifer: New Cryptojacking and DDoS Hybrid Malware Exploiting High and Critical Vulnerabilities to Infect Windows Devices. Retrieved November 16, 2020."
        }
      ],
      "id": "relationship--0d1fe44d-a476-4553-b163-1e03890ae7b4",
      "modified": "2020-11-17T20:00:08.135Z",
      "object_marking_refs": [
        "marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168"
      ],
      "relationship_type": "uses",
      "source_ref": "malware--54a73038-1937-4d71-a253-316e76d5413c",
      "spec_version": "2.1",
      "target_ref": "attack-pattern--7e150503-88e7-4861-866b-ff1ac82c4475",
      "type": "relationship",
      "x_mitre_attack_spec_version": "2.1.0",
      "x_mitre_domains": [
        "enterprise-attack"
      ],
      "x_mitre_modified_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
      "x_mitre_version": "1.0"
    },
```

T1049 (System Network Connections Discovery) has Relationships to 99 objects in the ATT&CK Enterprise bundle. The first result above shows the Malware S0532 (Lucifer) uses this Technique.

However, in this post I will show you the external joins, to other bundles. e.g. adding the filter `?_arango_cti_processor_note=capec-attack` to search for relationships between T1049 and any CAPEC objects...

```shell
curl -X 'GET' \
  'http://127.0.0.1:8006/api/v1/attack-enterprise/objects/t1049/relationships/?_arango_cti_processor_note=capec-attack' \
  -H 'accept: application/json'
```

```json
{
  "page_size": 50,
  "page_number": 1,
  "page_results_count": 1,
  "total_results_count": 1,
  "relationships": [
    {
      "created": "2014-06-23T00:00:00.000Z",
      "created_by_ref": "identity--2e51a631-99d8-52a5-95a6-8314d3f4fbf3",
      "description": "CAPEC-309 uses technique T1049",
      "id": "relationship--d1d052a1-4296-582e-be12-1b31a3f2a42b",
      "modified": "2022-09-29T00:00:00.000Z",
      "object_marking_refs": [
        "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
        "marking-definition--2e51a631-99d8-52a5-95a6-8314d3f4fbf3"
      ],
      "relationship_type": "technique",
      "source_ref": "attack-pattern--fd114e53-fdc0-4eef-8254-40ef0d4ea482",
      "target_ref": "attack-pattern--7e150503-88e7-4861-866b-ff1ac82c4475",
      "type": "relationship"
    }
  ]
}
```

Here I can see `CAPEC-309 uses technique T1049`.

Let me show you how these are created...

## Follow along

If you'd like to follow along with the queries used in this post, you can use some utility scripts in [stix2arango](https://github.com/muchdogesec/stix2arango/).

Once stix2arango is installed, run;

```shell
python3 utilities/arango_cti_processor/insert_archive_attack_enterprise.py \
    --database blog_demo \
    --ignore_embedded_relationships && \
python3 utilities/arango_cti_processor/insert_archive_attack_ics.py \
    --database blog_demo \
    --ignore_embedded_relationships && \
python3 utilities/arango_cti_processor/insert_archive_attack_mobile.py \
    --database blog_demo \
    --ignore_embedded_relationships && \
python3 utilities/arango_cti_processor/insert_archive_capec.py \
    --database blog_demo \
    --ignore_embedded_relationships && \
python3 utilities/arango_cti_processor/insert_archive_cwe.py \
    --database blog_demo \
    --ignore_embedded_relationships && \
python3 utilities/arango_cti_processor/insert_archive_disarm.py \
    --database blog_demo \
    --ignore_embedded_relationships && \
python3 utilities/arango_cti_processor/insert_archive_atlas.py \
    --database blog_demo \
    --ignore_embedded_relationships
```

This will store all current and historic versions of the knowledgebases in an ArangoDB database called; `blog_demo_database`, with the following Collections;

1. MITRE ATT&CK Enterprise (`mitre_attack_enterprise_vertex_collection` / `mitre_attack_enterprise_edge_collection`)
2. MITRE ATT&CK ICS (`mitre_attack_ics_vertex_collection` / `mitre_attack_ics_edge_collection`)
3. MITRE ATT&CK Mobile (`mitre_attack_mobile_vertex_collection` / `mitre_attack_mobile_edge_collection`)
4. MITRE CAPEC (`mitre_capec_vertex_collection` / `mitre_capec_edge_collection`)
5. MITRE CWE (`mitre_cwe_vertex_collection` / `mitre_cwe_edge_collection`)
6. MITRE ATLAS (`mitre_atlas_vertex_collection` / `mitre_atlas_edge_collection`)
7. DISARM (`disarm_vertex_collection` / `disarm_edge_collection`)

Note, the `*_edge` collections hold STIX Relationship objects from the knowledge-base bundles (in addition to the ones created by stix2arango, as described in this post), and the `*_vertex` collections hold all the other STIX objects present in the bundles.

## Examining the joins

stix2arango will import the data to ArangoDB, but the knowledgebases are not connected in any way... yet.

If I look inside an object, I can see references between knowledgebases though.

For example, CAPECs reference MITRE ATT&CK Techniques and CWE's. Take [CAPEC-11](https://capec.mitre.org/data/definitions/11.html) which references [CWE-430](https://cwe.mitre.org/data/definitions/430.html) and [T1036.006](https://attack.mitre.org/techniques/T1036/006/);

```json
        {
            "created": "2014-06-23T00:00:00.000Z",
            "created_by_ref": "identity--e50ab59c-5c4f-4d40-bf6a-d58418d89bcd",
            "description": "An attack of this type exploits a Web server's decision to take action based on filename or file extension. Because different file types are handled by different server processes, misclassification may force the Web server to take unexpected action, or expected actions in an unexpected sequence. This may cause the server to exhaust resources, supply debug or system data to the attacker, or bind an attacker to a remote process.",
            "external_references": [
                {
                    "external_id": "CAPEC-11",
                    "source_name": "capec",
                    "url": "https://capec.mitre.org/data/definitions/11.html"
                },
                {
                    "external_id": "CWE-430",
                    "source_name": "cwe",
                    "url": "http://cwe.mitre.org/data/definitions/430.html"
                },
                {
                    "description": "Masquerading: Space after Filename",
                    "external_id": "T1036.006",
                    "source_name": "ATTACK",
                    "url": "https://attack.mitre.org/wiki/Technique/T1036/006"
                },
                {
                    "description": "G. Hoglund, G. McGraw, Exploiting Software: How to Break Code, 2004--02, Addison-Wesley",
                    "external_id": "REF-1",
                    "source_name": "reference_from_CAPEC"
                },
                {
                    "description": "Orion Application Server JSP Source Disclosure Vulnerability (Bugtraq ID: 17204), SecurityFocus",
                    "external_id": "REF-6",
                    "source_name": "reference_from_CAPEC",
                    "url": "http://www.securityfocus.com/bid/17204/info"
                }
            ],
            "id": "attack-pattern--74a4fb36-83cb-4851-b09c-370f1a408523",
            "modified": "2022-09-29T00:00:00.000Z",
            "name": "Cause Web Server Misclassification",
            "object_marking_refs": [
                "marking-definition--17d82bb2-eeeb-4898-bda5-3ddbcd2b799d"
            ],
            "spec_version": "2.1",
            "type": "attack-pattern",
            "x_capec_abstraction": "Detailed",
            "x_capec_child_of_refs": [
                "attack-pattern--95afb65f-ece7-4511-85a3-d7bfb9973022"
            ],
            "x_capec_consequences": {
                "Access_Control": [
                    "Gain Privileges"
                ],
                "Authorization": [
                    "Gain Privileges"
                ],
                "Confidentiality": [
                    "Read Data",
                    "Gain Privileges"
                ]
            },
            "x_capec_domains": [
                "Software"
            ],
            "x_capec_likelihood_of_attack": "Medium",
            "x_capec_prerequisites": [
                "Web server software must rely on file name or file extension for processing.",
                "The attacker must be able to make HTTP requests to the web server."
            ],
            "x_capec_resources_required": [
                "None: No specialized resources are required to execute this type of attack."
            ],
            "x_capec_skills_required": {
                "Low": "To modify file name or file extension",
                "Medium": "To use misclassification to force the Web server to disclose configuration information, source, or binary data"
            },
            "x_capec_status": "Draft",
            "x_capec_typical_severity": "High",
            "x_capec_version": "3.9"
        }
```

Using this data, I can programmatically generated edges in the graph database (that is what arango_cti_processor does) to link them.


Here is how arango_cti_processor identifies these references to link the knowledgebases...

### 1. CAPEC -> ATT&CK

Firstly, lets look at all CAPEC objects in v3.9 (latest version at time of writing);

```sql
LET results = (
  FOR doc IN mitre_capec_vertex_collection
    FILTER doc._stix2arango_note == "v3.9"
    AND doc.revoked != true
    COLLECT type = doc.type WITH COUNT INTO typeCount
    RETURN { type, typeCount }
)

LET totalSum = SUM(FOR result IN results RETURN result.typeCount)

RETURN APPEND(results, [{ type: "Total", typeCount: totalSum }])
```

```json
[
  [
    {
      "type": "attack-pattern",
      "typeCount": 615
    },
    {
      "type": "course-of-action",
      "typeCount": 877
    },
    {
      "type": "identity",
      "typeCount": 1
    },
    {
      "type": "marking-definition",
      "typeCount": 1
    },
    {
      "type": "Total",
      "typeCount": 1494
    }
  ]
]
```

Lets now filter the results to only Objects with ATTACK references;

```sql
RETURN (
  FOR doc IN mitre_capec_vertex_collection
    FILTER doc._stix2arango_note == "v3.9"
    AND doc.revoked != true
    
    LET capecId = (
      FOR reference IN (IS_ARRAY(doc.external_references) ? doc.external_references : [])
        FILTER reference.source_name == 'capec'
        RETURN reference.external_id
    )
    
    LET attackIds = (
      FOR reference IN (IS_ARRAY(doc.external_references) ? doc.external_references : [])
        FILTER reference.source_name == 'ATTACK'
        RETURN reference.external_id
    )
    
    FILTER LENGTH(attackIds) > 0 AND LENGTH(capecId) > 0
    
    RETURN {
      stixObjectId: doc.id,
      capecId: capecId[0],
      attackIds: CONCAT_SEPARATOR(",", attackIds)
    }
)
```

```json
[
  [
    {
      "stixObjectId": "attack-pattern--92cdcd3d-d734-4442-afc3-4599f261498b",
      "capecId": "CAPEC-1",
      "attackIds": "T1574.010"
    },
    {
      "stixObjectId": "attack-pattern--74a4fb36-83cb-4851-b09c-370f1a408523",
      "capecId": "CAPEC-11",
      "attackIds": "T1036.006"
    },
    {
      "stixObjectId": "attack-pattern--7b423196-9de6-400f-91de-a1f26b3f19f1",
      "capecId": "CAPEC-112",
      "attackIds": "T1110"
    },
```

This should return 177 results of CAPEC objects, some having multiple `attackIds` referenced.

One thing I now know is the CAPEC objects only link to ATT&CK Techniques and Sub-Techniques.

This gives us a base search for the ATT&CK knowledge base as follows;

```sql
FOR doc IN UNION(
    (FOR d IN mitre_attack_enterprise_vertex_collection RETURN d),
    (FOR d IN mitre_attack_ics_vertex_collection RETURN d),
    (FOR d IN mitre_attack_mobile_vertex_collection RETURN d)
  )
  FILTER doc._stix2arango_note == "v14.1"
  AND doc.x_mitre_deprecated != true
  AND doc.revoked != true
  AND doc.type == "attack-pattern"
  RETURN [doc]
```

Should return 820 STIX objects.

Now I can use the ATT&CK IDs in these objects, returned by the CAPEC search to find the STIX ID of the ATT&CK object and create the joins;

```sql
RETURN (
  FOR doc IN mitre_capec_vertex_collection
    FILTER doc._stix2arango_note == "v3.9"
    AND doc.revoked != true
    AND IS_ARRAY(doc.external_references)
    
    LET capecId = FIRST(
      FOR reference IN doc.external_references
        FILTER reference.source_name == 'capec'
        RETURN reference.external_id
    )
    
    LET attackIds = (
      FOR reference IN doc.external_references
        FILTER reference.source_name == 'ATTACK'
        RETURN reference.external_id
    )
    
    FILTER LENGTH(attackIds) > 0 AND capecId != null
    
    LET attackIdToDocIdMap = (
      FOR attackId IN attackIds
        LET attackDocs = (
          FOR attackDoc IN UNION(
            FOR d IN mitre_attack_enterprise_vertex_collection
              FILTER d._stix2arango_note == "v14.1"
              AND d.x_mitre_deprecated != true
              AND d.revoked != true
              AND d.type == "attack-pattern"
              AND POSITION(d.external_references[*].external_id, attackId)
              RETURN { id: d.id, collection: "mitre_attack_enterprise_vertex_collection" },
            
            FOR d IN mitre_attack_ics_vertex_collection
              FILTER d._stix2arango_note == "v14.1"
              AND d.x_mitre_deprecated != true
              AND d.revoked != true
              AND d.type == "attack-pattern"
              AND POSITION(d.external_references[*].external_id, attackId)
              RETURN { id: d.id, collection: "mitre_attack_ics_vertex_collection" },
            
            FOR d IN mitre_attack_mobile_vertex_collection
              FILTER d._stix2arango_note == "v14.1"
              AND d.x_mitre_deprecated != true
              AND d.revoked != true
              AND d.type == "attack-pattern"
              AND POSITION(d.external_references[*].external_id, attackId)
              RETURN { id: d.id, collection: "mitre_attack_mobile_vertex_collection" }
          )
          RETURN attackDoc
        )
        RETURN {
          attackId: attackId,
          attackDocs: attackDocs
        }
    )
    
    RETURN {
      stixObjectId: doc.id,
      capecId: capecId,
      attackIdToDocIdMap
    }
)
```

```json
[
  [
    {
      "stixObjectId": "attack-pattern--92cdcd3d-d734-4442-afc3-4599f261498b",
      "capecId": "CAPEC-1",
      "attackIdToDocIdMap": [
        {
          "attackId": "T1574.010",
          "attackDocs": [
            {
              "id": "attack-pattern--9e8b28c9-35fe-48ac-a14d-e6cc032dcbcd",
              "collection": "mitre_attack_enterprise_vertex_collection"
            }
          ]
        }
      ]
    },
    {
      "stixObjectId": "attack-pattern--74a4fb36-83cb-4851-b09c-370f1a408523",
      "capecId": "CAPEC-11",
      "attackIdToDocIdMap": [
        {
          "attackId": "T1036.006",
          "attackDocs": [
            {
              "id": "attack-pattern--e51137a5-1cdc-499e-911a-abaedaa5ac86",
              "collection": "mitre_attack_enterprise_vertex_collection"
            }
          ]
        }
      ]
    },
    {
      "stixObjectId": "attack-pattern--7b423196-9de6-400f-91de-a1f26b3f19f1",
      "capecId": "CAPEC-112",
      "attackIdToDocIdMap": [
        {
          "attackId": "T1110",
          "attackDocs": [
            {
              "id": "attack-pattern--a93494bb-4b80-4ea1-8695-3236a49916fd",
              "collection": "mitre_attack_enterprise_vertex_collection"
            }
          ]
        }
      ]
    },
    {
      "stixObjectId": "attack-pattern--2e2ed1f8-f736-4fc9-83bc-308595fc6e03",
      "capecId": "CAPEC-114",
      "attackIdToDocIdMap": [
        {
          "attackId": "T1548",
          "attackDocs": [
            {
              "id": "attack-pattern--67720091-eee3-4d2d-ae16-8264567f6f5b",
              "collection": "mitre_attack_enterprise_vertex_collection"
            }
          ]
        }
      ]
    },
```

Above you can see CAPEC-1 (`attack-pattern--92cdcd3d-d734-4442-afc3-4599f261498b`) is linked to T1574.010 (`attack-pattern--9e8b28c9-35fe-48ac-a14d-e6cc032dcbcd`) in the Enterprise collection.

A summary of the relationships created;

```sql
LET capecDocs = (
  FOR doc IN mitre_capec_vertex_collection
    FILTER doc._stix2arango_note == "v3.9"
    AND doc.revoked != true
    AND IS_ARRAY(doc.external_references)
    
    LET attackIds = (
      FOR reference IN doc.external_references
        FILTER reference.source_name == 'ATTACK'
        RETURN reference.external_id
    )
    
    FILTER LENGTH(attackIds) > 0
    RETURN attackIds
)

LET attackIdCountInEnterprise = LENGTH(
  FOR attackId IN FLATTEN(capecDocs)
    FOR d IN mitre_attack_enterprise_vertex_collection
      FILTER d._stix2arango_note == "v14.1"
      AND d.x_mitre_deprecated != true
      AND d.revoked != true
      AND d.type == "attack-pattern"
      AND POSITION(d.external_references[*].external_id, attackId)
      RETURN 1
)

LET attackIdCountInICS = LENGTH(
  FOR attackId IN FLATTEN(capecDocs)
    FOR d IN mitre_attack_ics_vertex_collection
      FILTER d._stix2arango_note == "v14.1"
      AND d.x_mitre_deprecated != true
      AND d.revoked != true
      AND d.type == "attack-pattern"
      AND POSITION(d.external_references[*].external_id, attackId)
      RETURN 1
)

LET attackIdCountInMobile = LENGTH(
  FOR attackId IN FLATTEN(capecDocs)
    FOR d IN mitre_attack_mobile_vertex_collection
      FILTER d._stix2arango_note == "v14.1"
      AND d.x_mitre_deprecated != true
      AND d.revoked != true
      AND d.type == "attack-pattern"
      AND POSITION(d.external_references[*].external_id, attackId)
      RETURN 1
)

RETURN {
  "mitre_attack_enterprise_vertex_collection": attackIdCountInEnterprise,
  "mitre_attack_ics_vertex_collection": attackIdCountInICS,
  "mitre_attack_mobile_vertex_collection": attackIdCountInMobile
}
```

```json
[
  {
    "mitre_attack_enterprise_vertex_collection": 271,
    "mitre_attack_ics_vertex_collection": 0,
    "mitre_attack_mobile_vertex_collection": 1
  }
]
```

In summary, 272 joins will be made between CAPEC objects and MITRE ATT&CK object.

arango_cti_processor will then create a STIX relationship object (for each link found) so that users writing database queries can easily traverse these relationships (essentially what CTI Butler does).

I showed an example of one of the SROs created by arango_cti_butler for this type of join in the CTI Butler API query I printed earlier.

#### Small side not for those following along

If you're wondering about the 1 CAPEC that links to the Mobile ATT&CK matrix, here it is;

```json
    {
      "stixObjectId": "attack-pattern--140142cc-28cb-4506-bce6-b44128b7b9a7",
      "capecId": "CAPEC-648",
      "attackIdToDocIdMap": [
        {
          "attackId": "T1113",
          "attackDocs": [
            {
              "id": "attack-pattern--0259baeb-9f63-4c69-bf10-eb038c390688",
              "collection": "mitre_attack_enterprise_vertex_collection"
            }
          ]
        },
        {
          "attackId": "T1513",
          "attackDocs": [
            {
              "id": "attack-pattern--73c26732-6422-4081-8b63-6d0ae93d449e",
              "collection": "mitre_attack_mobile_vertex_collection"
            }
          ]
        }
      ]
    },
```

### 2. CAPEC -> CWE

OK, now you know the logic to create these types of joins, I'll jump straight into the final search.

For CAPEC to CWEs;

```sql
RETURN (
  FOR doc IN mitre_capec_vertex_collection
    FILTER doc._stix2arango_note == "v3.9"
    AND IS_ARRAY(doc.external_references)
    
    LET capecId = FIRST(
      FOR reference IN doc.external_references
        FILTER reference.source_name == 'capec'
        RETURN reference.external_id
    )
    
    LET cweIds = (
      FOR reference IN doc.external_references
        FILTER reference.source_name == 'cwe'
        RETURN reference.external_id
    )
    
    FILTER LENGTH(cweIds) > 0 AND capecId != null
    
    LET cweIdToDocIdMap = (
      FOR cweId IN cweIds
        LET cweDocs = (
          FOR cweDoc IN mitre_cwe_vertex_collection
            FILTER cweDoc._stix2arango_note == "v4.14"
            AND POSITION(cweDoc.external_references[*].external_id, cweId)
            RETURN { id: cweDoc.id, collection: "mitre_cwe_vertex_collection" }
        )
        RETURN {
          cweId: cweId,
          cweDocs: cweDocs
        }
    )
    
    RETURN {
      stixObjectId: doc.id,
      capecId: capecId,
      cweIdToDocIdMap
    }
)
```

```json
[
  [
    {
      "stixObjectId": "attack-pattern--92cdcd3d-d734-4442-afc3-4599f261498b",
      "capecId": "CAPEC-1",
      "cweIdToDocIdMap": [
        {
          "cweId": "CWE-276",
          "cweDocs": [
            {
              "id": "weakness--bfa2f40d-b5f0-505e-9ac5-92adfe0b6bd8",
              "collection": "mitre_cwe_vertex_collection"
            }
          ]
        },
        {
          "cweId": "CWE-285",
          "cweDocs": [
            {
              "id": "weakness--ff910cf7-7172-51b4-9948-874740d20ea0",
              "collection": "mitre_cwe_vertex_collection"
            }
          ]
        },
        {
          "cweId": "CWE-434",
          "cweDocs": [
            {
              "id": "weakness--4898a006-e26e-582f-a3fe-fd921b8c4fc5",
              "collection": "mitre_cwe_vertex_collection"
            }
          ]
        },
        {
          "cweId": "CWE-693",
          "cweDocs": [
            {
              "id": "weakness--414d8009-5140-58ad-97f6-a575c1bb84d1",
              "collection": "mitre_cwe_vertex_collection"
            }
          ]
        },
        {
          "cweId": "CWE-732",
          "cweDocs": [
            {
              "id": "weakness--6d8788cb-39fa-5219-8e45-b1aa3eb91083",
              "collection": "mitre_cwe_vertex_collection"
            }
          ]
        },
        {
          "cweId": "CWE-1191",
          "cweDocs": [
            {
              "id": "weakness--ce0c11b1-d560-5b9b-be5b-e372bf53bf0e",
              "collection": "mitre_cwe_vertex_collection"
            }
          ]
        },
        {
          "cweId": "CWE-1193",
          "cweDocs": [
            {
              "id": "weakness--66b6bbd6-4c6f-561d-ba62-3b083a4154aa",
              "collection": "mitre_cwe_vertex_collection"
            }
          ]
        },
        {
          "cweId": "CWE-1220",
          "cweDocs": [
            {
              "id": "weakness--c64c9776-e449-5b79-bc68-ee1bb120452e",
              "collection": "mitre_cwe_vertex_collection"
            }
          ]
        },
        {
          "cweId": "CWE-1297",
          "cweDocs": [
            {
              "id": "weakness--b0e4fec3-d07d-5c19-bf36-3c0c4393e241",
              "collection": "mitre_cwe_vertex_collection"
            }
          ]
        },
        {
          "cweId": "CWE-1311",
          "cweDocs": [
            {
              "id": "weakness--4ab9926e-306b-5e13-b6ae-c823b97f1608",
              "collection": "mitre_cwe_vertex_collection"
            }
          ]
        },
        {
          "cweId": "CWE-1314",
          "cweDocs": [
            {
              "id": "weakness--b4f6d188-3eeb-59cd-addc-0983b2f39c71",
              "collection": "mitre_cwe_vertex_collection"
            }
          ]
        },
        {
          "cweId": "CWE-1315",
          "cweDocs": [
            {
              "id": "weakness--a4d26132-f22e-5a6c-a023-a8ad49a442e1",
              "collection": "mitre_cwe_vertex_collection"
            }
          ]
        },
        {
          "cweId": "CWE-1318",
          "cweDocs": [
            {
              "id": "weakness--1d2542ed-b3cb-53c1-978f-8467ec99bb42",
              "collection": "mitre_cwe_vertex_collection"
            }
          ]
        },
        {
          "cweId": "CWE-1320",
          "cweDocs": [
            {
              "id": "weakness--8e461d75-a066-5915-aa43-92eac5d38736",
              "collection": "mitre_cwe_vertex_collection"
            }
          ]
        },
        {
          "cweId": "CWE-1321",
          "cweDocs": [
            {
              "id": "weakness--2dfc4cda-189f-51e3-a942-0647acd058bb",
              "collection": "mitre_cwe_vertex_collection"
            }
          ]
        },
        {
          "cweId": "CWE-1327",
          "cweDocs": [
            {
              "id": "weakness--f167a7af-9907-5610-862d-b4e2819ad32f",
              "collection": "mitre_cwe_vertex_collection"
            }
          ]
        }
      ]
    },
    {
      "stixObjectId": "attack-pattern--4a29d66d-8617-4382-b456-578ecdb1609e",
      "capecId": "CAPEC-10",
      "cweIdToDocIdMap": [
        {
          "cweId": "CWE-120",
          "cweDocs": [
            {
              "id": "weakness--7d83b5bf-4791-5ddf-9cfc-b90977b45bc2",
              "collection": "mitre_cwe_vertex_collection"
            }
          ]
        },
```

In total 1214 relationships are identified.

### 3. CWE -> CAPEC

For CWEs to CAPECs;

```sql
RETURN (
  FOR doc IN mitre_cwe_vertex_collection
    FILTER doc._stix2arango_note == "v4.14"
    AND IS_ARRAY(doc.external_references)
    
    LET cweId = FIRST(
      FOR reference IN doc.external_references
        FILTER reference.source_name == 'cwe'
        RETURN reference.external_id
    )
    
    LET capecIds = (
      FOR reference IN doc.external_references
        FILTER reference.source_name == 'capec'
        RETURN reference.external_id
    )
    
    FILTER LENGTH(capecIds) > 0 AND cweId != null
    
    LET capecIdToDocIdMap = (
      FOR capecId IN capecIds
        LET capecDocs = (
          FOR capecDoc IN mitre_capec_vertex_collection
            FILTER capecDoc._stix2arango_note == "v3.9"
            AND POSITION(capecDoc.external_references[*].external_id, capecId)
            RETURN { id: capecDoc.id, collection: "mitre_capec_vertex_collection" }
        )
        RETURN {
          capecId: capecId,
          capecDocs: capecDocs
        }
    )
    
    RETURN {
      stixObjectId: doc.id,
      cweId: cweId,
      capecIdToDocIdMap
    }
)
```

```json
[
  [
    {
      "stixObjectId": "weakness--94110a45-2221-5fb5-aa09-322b8dfc4b6a",
      "cweId": "CWE-1007",
      "capecIdToDocIdMap": [
        {
          "capecId": "CAPEC-632",
          "capecDocs": [
            {
              "id": "attack-pattern--c4e18b3f-0445-49e8-9bf1-d47a23082501",
              "collection": "mitre_capec_vertex_collection"
            }
          ]
        }
      ]
    },
    {
      "stixObjectId": "weakness--bdb3f8a8-96eb-5572-a201-84451e4d2324",
      "cweId": "CWE-1021",
      "capecIdToDocIdMap": [
        {
          "capecId": "CAPEC-103",
          "capecDocs": [
            {
              "id": "attack-pattern--ec41b2b3-a3b6-4af0-be65-69e82907dfef",
              "collection": "mitre_capec_vertex_collection"
            }
          ]
        },
        {
          "capecId": "CAPEC-181",
          "capecDocs": [
            {
              "id": "attack-pattern--1ff813eb-5def-43a0-a4b2-ea00aede114a",
              "collection": "mitre_capec_vertex_collection"
            }
          ]
        },
        {
          "capecId": "CAPEC-222",
          "capecDocs": [
            {
              "id": "attack-pattern--b9593e93-5589-4ae9-b0e7-09fa5c3136e5",
              "collection": "mitre_capec_vertex_collection"
            }
          ]
        },
        {
          "capecId": "CAPEC-504",
          "capecDocs": [
            {
              "id": "attack-pattern--1995c522-a25d-46e4-b024-65172771a692",
              "collection": "mitre_capec_vertex_collection"
            }
          ]
        },
        {
          "capecId": "CAPEC-506",
          "capecDocs": [
            {
              "id": "attack-pattern--79309efd-dd13-41d2-81c6-ec382bced2b4",
              "collection": "mitre_capec_vertex_collection"
            }
          ]
        },
```

In total 1212 relationships are identified.

## A side (but important) note on versioning of knowledgebases

Most knowledge-bases are versioned.

In the queries I've used in this post you'll see I reference specific versions in the queries, e.g. for ATT&CK I use v4.14;

```sql
FILTER doc._stix2arango_note == "v4.14"
```

Take ATT&CK as an example, [you can see in the ATT&CK repository the various versions of the Enterprise Matrix](https://github.com/mitre-attack/attack-stix-data/tree/master/enterprise-attack).

To always get the latest version of MITRE ATT&CK Enterprise you can use the query:

```sql
FOR doc IN mitre_attack_enterprise_vertex_collection
    FILTER _is_latest == true
    RETURN [doc]
```

Whereas, here is how I would request a specific ATT&CK version (here 14.0);

```sql
FOR doc IN mitre_attack_enterprise_vertex_collection
    FILTER doc._stix2arango_note == "v14.0"
    RETURN [doc]
```

In short, you probably always want to use the filter `_is_latest == true`, unless you have a specific use-case (i.e. I used versions above so anyone following along would get the same results).

## Running Arango CTI Processor

To actually generate these relationships I can run arango_cti_processor.

[Install it using the setup instructions described here](https://github.com/muchdogesec/arango_cti_processor).

Once installed you can run it in different `--relationship` mode to generate the joins.

For example, to create `capec-attack` (shown at the start of this post in CTI Butler);

```shell
python3 arango_cti_processor.py \
  --database blog_demo_database \
  --relationship capec-attack \
  --ignore_embedded_relationships true && \
python3 arango_cti_processor.py \
  --database blog_demo_database \
  --relationship cwe-capec \
  --ignore_embedded_relationships true
```

Once complete, in the Arango DB UI we can search;

```sql
FOR doc IN mitre_capec_edge_collection
    FILTER doc._arango_cti_processor_note == "capec-attack"
    RETURN doc.description
```

Which returns 346 results. Here are the first few records showing a description of the STIX 2.1 SRO arango_cti_processor has created;

```json
[
  "CAPEC-1 uses technique T1574.010",
  "CAPEC-11 uses technique T1036.006",
  "CAPEC-112 uses technique T1110",
  "CAPEC-112 uses technique T1110",
  "CAPEC-114 uses technique T1548",
  "CAPEC-115 uses technique T1548",
  "CAPEC-122 uses technique T1548",
  "CAPEC-125 uses technique T1498.001",
  "CAPEC-125 uses technique T1499",
  "CAPEC-125 uses technique T1499",
```

I can start from a specific object to find out what it is linked to. For example, using the CAPEC-11 example earlier;

```sql
LET capec_id = "attack-pattern--74a4fb36-83cb-4851-b09c-370f1a408523"
FOR edge IN UNION(
    (
        FOR e IN mitre_capec_edge_collection
            FILTER (e.source_ref == capec_id OR e.target_ref == capec_id)
                AND e._arango_cti_processor_note != null
            RETURN e
    ),
    (
        FOR e IN mitre_cwe_edge_collection
            FILTER (e.source_ref == capec_id OR e.target_ref == capec_id)
                AND e._arango_cti_processor_note != null
            RETURN e
    )
)
RETURN edge
```

<img class="img-fluid" src="/assets/images/blog/2024-12-16/arangodb-output-capec-11.png" alt="ArangoDB arango cti processor relationships" title="ArangoDB arango cti processor relationships" />

However, the previous search assumes you know the CAPEC-11 STIX ID to begin with. 

utting it all into one search where you start with a CAPEC ID and want to print the relationships in a human readable way...

```sql
// Step 1: Find the CAPEC vertex for "CAPEC-11"
FOR doc1 IN mitre_capec_vertex_collection
    FILTER doc1.external_references != null 
        AND IS_ARRAY(doc1.external_references)
    FOR ref IN doc1.external_references
        FILTER ref.external_id == "CAPEC-11"
        LET capec_id = doc1.id

        // Step 2: Combine results from both edge collections
        RETURN UNION(
            FOR edge IN mitre_capec_edge_collection
                FILTER (edge.source_ref == capec_id OR edge.target_ref == capec_id)
                    AND edge._arango_cti_processor_note != null
                RETURN edge.description,
                
            FOR edge IN mitre_cwe_edge_collection
                FILTER (edge.source_ref == capec_id OR edge.target_ref == capec_id)
                    AND edge._arango_cti_processor_note != null
                RETURN edge.description
        )
```

```json
[
  [
    "CAPEC-11 uses technique T1036.006",
    "CWE-430 is exploited using CAPEC-11"
  ]
]
```

<iframe width="560" height="315" src="https://www.youtube.com/embed/CcoA18Pa8ZU?si=jEf9HVWeonRjltpJ" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>