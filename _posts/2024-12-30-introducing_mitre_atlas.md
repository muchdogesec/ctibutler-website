---
date: 2024-12-30
last_modified: 2024-12-30
title: "Fortifying AI: How MITRE ATLAS Shields Artificial Intelligence from Adversarial Threats"
description: "Discover how MITRE ATLAS is helping to defend AI systems as I share a detailed explanation of how the knowledge-base is architected."
categories:
  - "RESEARCH"
tags: [
	"MITRE",
  "ATT&CK",
  "STIX",
  "ATT&CK Navigator"
]
products:
  - stix2arango
  - CTIButler
author_staff_member: david-greenwood
image: /assets/images/blog/2024-12-30/atlas-object-graph.jpg
featured_image: /assets/images/blog/2024-12-30/atlas-object-graph.jpg
layout: post
published: true
redirect_from:
  - /blog/introduction-mitre-atlas
---

## Overview

[MITRE ATLAS](https://atlas.mitre.org/) (Adversarial Threat Landscape for Artificial-Intelligence Systems) is a knowledge-base designed to address the growing concern of adversarial threats targeting AI and machine learning (ML) systems.

ATLAS provides a comprehensive framework to identify, classify, and mitigate risks to AI models, ensuring the resilience of these systems in real-world applications.

At its core, ATLAS adapts the principles of the widely acclaimed MITRE ATT&CK framework to the unique challenges posed by AI systems. It catalogs tactics, techniques, and case studies of adversarial threats, ranging from data poisoning during training phases to model evasion and inference attacks.

Our intelligence team is increasingly using the framework to classify parts of our research in a standard way as AI based attacks increase.

Like ATT&CK, [the framework is based around tactics and techniques](https://atlas.mitre.org/);

<img class="img-fluid" src="/assets/images/blog/2024-12-30/atlas-matrix.png" alt="MITRE ATLAS Matrix" title="MITRE ATLAS Matrix" />

In another post on this blog, I showed you the data structure of MITRE ATT&CK, [PSA: MITRE ATT&CK is More Than Tactics and Techniques](/blog/mitre_attack_data_structure/).

I aim to achieve a similar thing in this post by lifting the lid on ATLAS objects so you can use them in your research.

## ATLAS STIX objects

Like ATT&CK, ATLAS data is built on STIX objects and structured like so;

<iframe width="768" height="432" src="https://miro.com/app/live-embed/uXjVLyVD5ek=/?moveToViewport=-2101,-1403,3877,1883&embedId=943155884047" frameborder="0" scrolling="no" allow="fullscreen; clipboard-read; clipboard-write" allowfullscreen></iframe>

Lets break this down by looking at each ATLAS object type individually to show how I built this diagram.

## Follow along

In this post I am going to provide queries you can use to analyse and filter MITRE ATLAS data.

If you would like to follow along, and keep a searchable copy of ATLAS locally, you can import the data using [stix2arango](https://github.com/muchdogesec/stix2arango/).

Once you've installed stix2arango by following the instructions described in the repository, you can run the following command to import v4.7.0 of MITRE ATLAS to ArangoDB;

```shell
python3 utilities/arango_cti_processor/insert_archive_atlas.py \
    --database blog_introducing_mitre_atlas \
    --versions 4_7_0
```

You can then use the query interface in the ArangoDB UI to run the AQL queries shown in this post.

## Understanding the STIX objects

### ATLAS object `Collection` = STIX object `x-mitre-collection`

These objects include a list of all objects in ATLAS under the `x_mitre_contents` property. The object provides an easy way to quickly understand all the objects in the framework.

To retrieve all `x-mitre-collection` objects from the DB;

```sql
FOR doc IN mitre_atlas_vertex_collection
  FILTER doc._stix2arango_note == "v4.7.0"
  AND doc.type == "x-mitre-collection"
  LET keys = ATTRIBUTES(doc)
  LET filteredKeys = keys[* FILTER !STARTS_WITH(CURRENT, "_")]
  RETURN [KEEP(doc, filteredKeys)]
```

```json
    {
      "created": "2021-05-13T00:00:00Z",
      "created_by_ref": "identity--960285c2-9771-4b17-bb57-e0bb8ede54b0",
      "description": "Adversarial Threat Landscape for AI Systems - 4.7.0",
      "id": "x-mitre-collection--e5bdfbe4-10e3-4794-82b9-0992f3e4fa09",
      "modified": "2024-10-01T00:00:00Z",
      "name": "ATLAS",
      "spec_version": "2.1",
      "type": "x-mitre-collection",
      "x_mitre_attack_spec_version": "2.1.0",
      "x_mitre_contents": [
        {
          "object_ref": "x-mitre-tactic--9ceaa8fe-57f1-4923-a4a5-121b5111139c",
          "object_modified": "2024-10-29T21:59:42.801158Z"
        },
        {
          "object_ref": "x-mitre-tactic--1fa998a1-d720-488c-b156-b569fe4e6308",
          "object_modified": "2024-10-29T21:59:49.487053Z"
        },
        {
          "OTHER ITEMS IN LIST CUT FOR BREVITY"
        }
      ],
      "x_mitre_version": "0.1"
    }
```

Returns 1 object in v4.7.0.

To see what `x-mitre-collection` object is linked to/from;

```sql
FOR doc IN mitre_atlas_edge_collection
  FILTER CONTAINS(doc.source_ref, "x-mitre-collection") 
  OR CONTAINS(doc.target_ref, "x-mitre-collection")
  AND doc._stix2arango_note == "v4.7.0"
  LET source_ref_prefix = SPLIT(doc.source_ref, "--")[0]
  LET target_ref_prefix = SPLIT(doc.target_ref, "--")[0]
  RETURN DISTINCT {
    "relationship_type": doc.relationship_type,
    "source_ref_object_type": source_ref_prefix,
    "target_ref_object_type": target_ref_prefix,
    "is_property_ref": doc._is_ref
  }
```

| relationship_type       | source_ref_object_type | target_ref_object_type | is_property_ref |
| ----------------------- | ---------------------- | ---------------------- | ------- |
| created-by              | x-mitre-collection     | identity               | true    |
| x_mitre_contents-object | x-mitre-collection     | x-mitre-tactic         | true    |
| x_mitre_contents-object | x-mitre-collection     | attack-pattern         | true    |
| x_mitre_contents-object | x-mitre-collection     | course-of-action       | true    |
| x_mitre_contents-object | x-mitre-collection     | relationship           | true    |
| x_mitre_contents-object | x-mitre-collection     | x-mitre-matrix         | true    |

### ATLAS object `Matrix` = STIX object `x-mitre-matrix`

`x-mitre-matrix` objects are similar to `x-mitre-collection` objects, however they only contain a list of Tactics (under `tactic_refs`).

This object is used to define the order of Tactics in the framework.

To retrieve all `x-mitre-matrix` objects from the DB;

```sql
FOR doc IN mitre_atlas_vertex_collection
  FILTER doc._stix2arango_note == "v4.7.0"
  AND doc.type == "x-mitre-matrix"
  AND doc.x_mitre_deprecated != true
  AND doc.revoked != true
  LET keys = ATTRIBUTES(doc)
  LET filteredKeys = keys[* FILTER !STARTS_WITH(CURRENT, "_")]
  RETURN [KEEP(doc, filteredKeys)]
```

```json
    {
      "created": "2021-05-13T00:00:00.000Z",
      "description": "ATLAS matrix for ATLAS Matrix - 4.7.0",
      "external_references": [
        {
          "source_name": "mitre-atlas",
          "url": "https://atlas.mitre.org",
          "external_id": "mitre-atlas"
        }
      ],
      "id": "x-mitre-matrix--70183b8a-1660-4cfe-b05b-50d2ed9adbc2",
      "modified": "2024-10-01T00:00:00.000Z",
      "name": "ATLAS Matrix",
      "spec_version": "2.1",
      "tactic_refs": [
        "x-mitre-tactic--9ceaa8fe-57f1-4923-a4a5-121b5111139c",
        "x-mitre-tactic--1fa998a1-d720-488c-b156-b569fe4e6308",
        "x-mitre-tactic--14ef1e2d-f902-450a-a7e8-b032e318bb86",
        "x-mitre-tactic--2666e534-bf47-4656-9404-e90afe41f4a7",
        "x-mitre-tactic--b777d4af-fbe8-4e44-9917-c5c5542a7147",
        "x-mitre-tactic--4a088a36-6786-4486-a3ea-3c3576d61daa",
        "x-mitre-tactic--ef06a48d-1ccb-42c6-b5dd-2770a58f02d8",
        "x-mitre-tactic--35a4b685-8a9f-4f66-bef0-92c8a5fd8411",
        "x-mitre-tactic--b7c3883a-1ae7-47cd-bd53-024c79ac833a",
        "x-mitre-tactic--b3f5fda4-a31a-4a74-9588-995b143d3436",
        "x-mitre-tactic--76d8d1bc-98fb-406a-a88d-a70649ad9365",
        "x-mitre-tactic--528bc2da-8855-44c0-9e45-ab92c179bf6f",
        "x-mitre-tactic--55e80a13-be94-43ba-aa57-e6c5cb822864",
        "x-mitre-tactic--4386734e-fa57-4700-95b8-e76b8cab8ab3"
      ],
      "type": "x-mitre-matrix"
    }
```

Only returns 1 result in v4.7.0.

To see what the `x-mitre-matrix` object is linked to/from;

```sql
FOR doc IN mitre_atlas_edge_collection
  FILTER CONTAINS(doc.source_ref, "x-mitre-matrix") 
  OR CONTAINS(doc.target_ref, "x-mitre-matrix")
  AND doc._stix2arango_note == "v4.7.0"
  LET source_ref_prefix = SPLIT(doc.source_ref, "--")[0]
  LET target_ref_prefix = SPLIT(doc.target_ref, "--")[0]
  RETURN DISTINCT {
    "relationship_type": doc.relationship_type,
    "source_ref_object_type": source_ref_prefix,
    "target_ref_object_type": target_ref_prefix,
    "is_property_ref": doc._is_ref
  }
```

| relationship_type       | source_ref_object_type | target_ref_object_type | is_property_ref |
| ----------------------- | ---------------------- | ---------------------- | --------------- |
| tactic                  | x-mitre-matrix         | x-mitre-tactic         | true            |
| x_mitre_contents-object | x-mitre-collection     | x-mitre-matrix         | true            |

### ATLAS object `Tactic` = STIX object `x-mitre-tactic`

[ATLAS Tactics](https://atlas.mitre.org/tactics) represent the “why” of a technique: the reason for performing an action. Tactics serve as useful contextual categories for individual techniques and cover standard notations for things adversaries do during an operation.

Tactics have IDs in the format: `AML.TANNNN`

For example, [Tactic AML.TA0002 Reconnaissance](https://atlas.mitre.org/tactics/AML.TA0002), which can be retrieved from the DB using the following query; 

```sql
FOR doc IN mitre_atlas_vertex_collection
  FILTER doc._stix2arango_note == "v4.7.0"
  AND doc.type == "x-mitre-tactic"
  AND IS_ARRAY(doc.external_references)
  LET matchingExtRefs = (
    FOR extRef IN doc.external_references
      FILTER extRef.external_id == "AML.TA0002"
      RETURN extRef
  )
  FILTER LENGTH(matchingExtRefs) > 0
  LET keys = ATTRIBUTES(doc)
  LET filteredKeys = keys[* FILTER !STARTS_WITH(CURRENT, "_")]
  RETURN KEEP(doc, filteredKeys)
```

```json
  {
    "created": "2024-10-29T21:59:42.801158Z",
    "description": "The adversary is trying to gather information about the machine learning system they can use to plan future operations.\n\nReconnaissance consists of techniques that involve adversaries actively or passively gathering information that can be used to support targeting.\nSuch information may include details of the victim organizations' machine learning capabilities and research efforts.\nThis information can be leveraged by the adversary to aid in other phases of the adversary lifecycle, such as using gathered information to obtain relevant ML artifacts, targeting ML capabilities used by the victim, tailoring attacks to the particular models used by the victim, or to drive and lead further Reconnaissance efforts.\n",
    "external_references": [
      {
        "source_name": "mitre-atlas",
        "url": "https://atlas.mitre.org/tactics/AML.TA0002",
        "external_id": "AML.TA0002"
      }
    ],
    "id": "x-mitre-tactic--9ceaa8fe-57f1-4923-a4a5-121b5111139c",
    "modified": "2024-10-29T21:59:42.801158Z",
    "name": "Reconnaissance",
    "spec_version": "2.1",
    "type": "x-mitre-tactic",
    "x_mitre_shortname": "reconnaissance"
  }
```

To return all ATLAS `x-mitre-tactic` objects:

```sql
FOR doc IN mitre_atlas_vertex_collection
  FILTER doc._stix2arango_note == "v4.7.0"
  AND doc.type == "x-mitre-tactic"
  LET keys = ATTRIBUTES(doc)
  LET filteredKeys = keys[* FILTER !STARTS_WITH(CURRENT, "_")]
  RETURN KEEP(doc, filteredKeys)
```

Returns 14 results in v4.7.0, which are;

```sql
FOR doc IN mitre_atlas_vertex_collection
  FILTER doc._stix2arango_note == "v4.7.0"
  AND doc.type == "x-mitre-tactic"
  RETURN doc.name
```

```json
[
  "Reconnaissance",
  "Resource Development",
  "Initial Access",
  "ML Model Access",
  "Execution",
  "Persistence",
  "Privilege Escalation",
  "Defense Evasion",
  "Credential Access",
  "Discovery",
  "Collection",
  "ML Attack Staging",
  "Exfiltration",
  "Impact"
]
```

To see what `x-mitre-tactic` objects are linked to/from;

```sql
FOR doc IN mitre_atlas_edge_collection
  FILTER CONTAINS(doc.source_ref, "x-mitre-tactic") 
  OR CONTAINS(doc.target_ref, "x-mitre-tactic")
  AND doc._stix2arango_note == "v4.7.0"
  LET source_ref_prefix = SPLIT(doc.source_ref, "--")[0]
  LET target_ref_prefix = SPLIT(doc.target_ref, "--")[0]
  RETURN DISTINCT {
    "relationship_type": doc.relationship_type,
    "source_ref_object_type": source_ref_prefix,
    "target_ref_object_type": target_ref_prefix,
    "is_property_ref": doc._is_ref
  }
```

| relationship_type       | source_ref_object_type | target_ref_object_type | is_property_ref |
|-------------------------|------------------------|------------------------|---------|
| tactic                  | x-mitre-matrix         | x-mitre-tactic         | true    |
| x_mitre_contents-object | x-mitre-collection     | x-mitre-tactic         | true    |

If you want to find out what is linked to a specific Tactic, you can use the following search (here I use `AML.TA0002`);

```sql
LET vertexDocs = (
  FOR doc IN mitre_atlas_vertex_collection
    FILTER doc._stix2arango_note == "v4.7.0"
    AND doc.type == "x-mitre-tactic"
    AND IS_ARRAY(doc.external_references)
    LET matchingExtRefs = (
      FOR extRef IN doc.external_references
        FILTER extRef.external_id == "AML.TA0002"
        RETURN extRef
    )
    FILTER LENGTH(matchingExtRefs) > 0
    LET keys = ATTRIBUTES(doc)
    LET filteredKeys = keys[* FILTER !STARTS_WITH(CURRENT, "_")]
    RETURN KEEP(doc, filteredKeys)
)

FOR vertexDoc IN vertexDocs
  FOR edgeDoc IN mitre_atlas_edge_collection
    FILTER edgeDoc.target_ref == vertexDoc.id OR edgeDoc.source_ref == vertexDoc.id
    LET keys = ATTRIBUTES(edgeDoc)
    LET filteredKeys = keys[* FILTER !STARTS_WITH(CURRENT, "_")]
    RETURN KEEP(edgeDoc, filteredKeys)
```

Returns 2 results in v4.7.0.

### ATLAS object `Technique` = STIX object `attack-pattern`

[ATLAS Techniques](https://atlas.mitre.org/techniques) represent “how” an adversary achieves a tactical objective by performing an action. For example, an adversary may gain initial access by compromising the machine learning (ML) supply chain.

Techniques have IDs in the format: `AML.TNNNN`

For example, [Technique AML.T0000 Search for Victim's Publicly Available Research Materials](https://atlas.mitre.org/techniques/AML.T0000), which can be retrieved from the DB using the following query; 

```sql
FOR doc IN mitre_atlas_vertex_collection
  FILTER doc._stix2arango_note == "v4.7.0"
  AND doc.type == "attack-pattern"
  AND doc.x_mitre_is_subtechnique != true
  AND IS_ARRAY(doc.external_references)
  LET matchingExtRefs = (
    FOR extRef IN doc.external_references
      FILTER extRef.external_id == "AML.T0000"
      RETURN extRef
  )
  FILTER LENGTH(matchingExtRefs) > 0
  LET keys = ATTRIBUTES(doc)
  LET filteredKeys = keys[* FILTER !STARTS_WITH(CURRENT, "_")]
  RETURN KEEP(doc, filteredKeys)
```

```json
  {
    "created": "2021-05-13T00:00:00.000Z",
    "description": "Adversaries may search publicly available research to learn how and where machine learning is used within a victim organization.\nThe adversary can use this information to identify targets for attack, or to tailor an existing attack to make it more effective.\nOrganizations often use open source model architectures trained on additional proprietary data in production.\nKnowledge of this underlying architecture allows the adversary to craft more realistic proxy models ([Create Proxy ML Model](/techniques/AML.T0005)).\nAn adversary can search these resources for publications for authors employed at the victim organization.\n\nResearch materials may exist as academic papers published in [Journals and Conference Proceedings](/techniques/AML.T0000.000), or stored in [Pre-Print Repositories](/techniques/AML.T0000.001), as well as [Technical Blogs](/techniques/AML.T0000.002).\n",
    "external_references": [
      {
        "source_name": "mitre-atlas",
        "url": "https://atlas.mitre.org/techniques/AML.T0000",
        "external_id": "AML.T0000"
      }
    ],
    "id": "attack-pattern--65d21e6b-7abe-4623-8f5c-88011cb362cb",
    "kill_chain_phases": [
      {
        "kill_chain_name": "mitre-atlas",
        "phase_name": "reconnaissance"
      }
    ],
    "modified": "2021-05-13T00:00:00.000Z",
    "name": "Search for Victim's Publicly Available Research Materials",
    "spec_version": "2.1",
    "type": "attack-pattern",
    "x_mitre_platforms": [
      "ATLAS"
    ]
  }
```

To return all ATLAS Technique objects:

```sql
FOR doc IN mitre_atlas_vertex_collection
  FILTER doc._stix2arango_note == "v4.7.0"
  AND doc.type == "attack-pattern"
  AND doc.x_mitre_is_subtechnique != true
  LET keys = ATTRIBUTES(doc)
  LET filteredKeys = keys[* FILTER !STARTS_WITH(CURRENT, "_")]
  RETURN KEEP(doc, filteredKeys)
```

Returns 52 results in v4.7.0, which are;

```sql
FOR doc IN mitre_atlas_vertex_collection
  FILTER doc._stix2arango_note == "v4.7.0"
  AND doc.type == "attack-pattern"
  AND doc.x_mitre_is_subtechnique != true
  RETURN doc.name
```

```json
[
  "Search for Victim's Publicly Available Research Materials",
  "Search for Publicly Available Adversarial Vulnerability Analysis",
  "Search Victim-Owned Websites",
  "Search Application Repositories",
  "Active Scanning",
  "Acquire Public ML Artifacts",
  "Obtain Capabilities",
  "Develop Capabilities",
  "Acquire Infrastructure",
  "Publish Poisoned Datasets",
  "ML Supply Chain Compromise",
  "AI Model Inference API Access",
  "ML-Enabled Product or Service",
  "Physical Environment Access",
  "Full ML Model Access",
  "Discover ML Model Ontology",
  "Discover ML Model Family",
  "Poison Training Data",
  "Establish Accounts",
  "Create Proxy ML Model",
  "Discover ML Artifacts",
  "User Execution",
  "Valid Accounts",
  "Evade ML Model",
  "Backdoor ML Model",
  "Exfiltration via ML Inference API",
  "Exfiltration via Cyber Means",
  "Denial of ML Service",
  "Spamming ML System with Chaff Data",
  "Erode ML Model Integrity",
  "Cost Harvesting",
  "ML Artifact Collection",
  "Data from Information Repositories",
  "Data from Local System",
  "Verify Attack",
  "Craft Adversarial Data",
  "External Harms",
  "Exploit Public-Facing Application",
  "Command and Scripting Interpreter",
  "LLM Prompt Injection",
  "Phishing",
  "LLM Plugin Compromise",
  "LLM Jailbreak",
  "Unsecured Credentials",
  "LLM Meta Prompt Extraction",
  "LLM Data Leakage",
  "Publish Poisoned Models",
  "Erode Dataset Integrity",
  "Publish Hallucinated Entities",
  "LLM Prompt Self-Replication",
  "Discover LLM Hallucinations",
  "Discover AI Model Outputs"
]
```

To see what Technique objects are linked to/from;

```sql
LET attack_pattern_ids = (
  FOR doc IN mitre_atlas_vertex_collection
    FILTER doc._stix2arango_note == "v4.7.0"
    AND doc.type == "attack-pattern"
    AND doc.x_mitre_is_subtechnique != true
    RETURN doc.id
)
FOR doc IN mitre_atlas_edge_collection
  FILTER (CONTAINS(doc.source_ref, "attack-pattern") OR CONTAINS(doc.target_ref, "attack-pattern"))
  AND (doc.source_ref IN attack_pattern_ids OR doc.target_ref IN attack_pattern_ids)
  AND doc._stix2arango_note == "v4.7.0"
  LET source_ref_prefix = SPLIT(doc.source_ref, "--")[0]
  LET target_ref_prefix = SPLIT(doc.target_ref, "--")[0]
  RETURN DISTINCT {
    "relationship_type": doc.relationship_type,
    "source_ref_object_type": source_ref_prefix,
    "target_ref_object_type": target_ref_prefix,
    "is_property_ref": doc._is_ref
  }
```

| relationship_type       | source_ref_object_type | target_ref_object_type | is_property_ref |
|-------------------------|------------------------|------------------------|-----------------|
| subtechnique-of         | attack-pattern         | attack-pattern         | false           |
| x_mitre_contents-object | x-mitre-collection     | attack-pattern         | true            |
| mitigates               | course-of-action       | attack-pattern         | false           |

If you want to find out what is linked to a specific Technique, you can use the following search (here I use `AML.T0000`);

```sql
LET vertexDocs = (
  FOR doc IN mitre_atlas_vertex_collection
    FILTER doc._stix2arango_note == "v4.7.0"
    AND doc.type == "attack-pattern"
    AND IS_ARRAY(doc.external_references)
    LET matchingExtRefs = (
      FOR extRef IN doc.external_references
        FILTER extRef.external_id == "AML.T0000"
        RETURN extRef
    )
    FILTER LENGTH(matchingExtRefs) > 0
    LET keys = ATTRIBUTES(doc)
    LET filteredKeys = keys[* FILTER !STARTS_WITH(CURRENT, "_")]
    RETURN KEEP(doc, filteredKeys)
)

FOR vertexDoc IN vertexDocs
  FOR edgeDoc IN mitre_atlas_edge_collection
    FILTER edgeDoc.target_ref == vertexDoc.id OR edgeDoc.source_ref == vertexDoc.id
    LET keys = ATTRIBUTES(edgeDoc)
    LET filteredKeys = keys[* FILTER !STARTS_WITH(CURRENT, "_")]
    RETURN KEEP(edgeDoc, filteredKeys)
```

Returns 5 results in v4.7.0.

### ATLAS object `Sub-Technique` = STIX object `attack-pattern`

ATLAS Sub-Techniques (`attack-pattern` with [STIX Custom Property](/blog/create_custom_stix_objects/) `"x_mitre_is_subtechnique": true`) are a more specific implementation of a Technique (they are children to a parent).

Sub-technique have IDs in the format: `AML.TNNNN.NNN`

For example, [AML.T0000.000 Journals and Conference Proceedings](https://atlas.mitre.org/techniques/AML.T0000.000) is a Sub-Technique of Technique [AML.T0000 Search for Victim's Publicly Available Research Materials](https://atlas.mitre.org/techniques/AML.T0000).

You can retrieve AML.T0000.000 from the database using the following query;

```sql
FOR doc IN mitre_atlas_vertex_collection
  FILTER doc._stix2arango_note == "v4.7.0"
  AND doc.type == "attack-pattern"
  AND doc.x_mitre_is_subtechnique == true
  AND IS_ARRAY(doc.external_references)
  LET matchingExtRefs = (
    FOR extRef IN doc.external_references
      FILTER extRef.external_id == "AML.T0000.000"
      RETURN extRef
  )
  FILTER LENGTH(matchingExtRefs) > 0
  LET keys = ATTRIBUTES(doc)
  LET filteredKeys = keys[* FILTER !STARTS_WITH(CURRENT, "_")]
  RETURN KEEP(doc, filteredKeys)
```

```json
  {
    "created": "2021-05-13T00:00:00.000Z",
    "description": "Many of the publications accepted at premier machine learning conferences and journals come from commercial labs.\nSome journals and conferences are open access, others may require paying for access or a membership.\nThese publications will often describe in detail all aspects of a particular approach for reproducibility.\nThis information can be used by adversaries to implement the paper.\n",
    "external_references": [
      {
        "source_name": "mitre-atlas",
        "url": "https://atlas.mitre.org/techniques/AML.T0000.000",
        "external_id": "AML.T0000.000"
      }
    ],
    "id": "attack-pattern--a17a1941-ca02-4273-9d7f-d864ea122bdb",
    "kill_chain_phases": [
      {
        "kill_chain_name": "mitre-atlas",
        "phase_name": "reconnaissance"
      }
    ],
    "modified": "2021-05-13T00:00:00.000Z",
    "name": "Journals and Conference Proceedings",
    "spec_version": "2.1",
    "type": "attack-pattern",
    "x_mitre_is_subtechnique": true,
    "x_mitre_platforms": [
      "ATLAS"
    ]
  }
```

To return all ATLAS Sub-technique objects:

```sql
FOR doc IN mitre_atlas_vertex_collection
  FILTER doc._stix2arango_note == "v4.7.0"
  AND doc.type == "attack-pattern"
  AND doc.x_mitre_is_subtechnique == true
  LET keys = ATTRIBUTES(doc)
  LET filteredKeys = keys[* FILTER !STARTS_WITH(CURRENT, "_")]
  RETURN KEEP(doc, filteredKeys)
```

39 results in v4.7.0, which are;

```sql
FOR doc IN mitre_atlas_vertex_collection
  FILTER doc._stix2arango_note == "v4.7.0"
  AND doc.type == "attack-pattern"
  AND doc.x_mitre_is_subtechnique == true
  RETURN doc.name
```

```json
[
  "Journals and Conference Proceedings",
  "Pre-Print Repositories",
  "Technical Blogs",
  "Datasets",
  "Models",
  "Adversarial ML Attack Implementations",
  "Software Tools",
  "Adversarial ML Attacks",
  "ML Development Workspaces",
  "Consumer Hardware",
  "Hardware",
  "ML Software",
  "Data",
  "Model",
  "Train Proxy via Gathered ML Artifacts",
  "Train Proxy via Replication",
  "Use Pre-Trained Model",
  "Unsafe ML Artifacts",
  "Poison ML Model",
  "Inject Payload",
  "Infer Training Data Membership",
  "Invert ML Model",
  "Extract ML Model",
  "White-Box Optimization",
  "Black-Box Optimization",
  "Black-Box Transfer",
  "Manual Modification",
  "Insert Backdoor Trigger",
  "Financial Harm",
  "Reputational Harm",
  "Societal Harm",
  "User Harm",
  "ML Intellectual Property Theft",
  "Direct",
  "Indirect",
  "Spearphishing via Social Engineering LLM",
  "Malicious Package",
  "Domains",
  "Physical Countermeasures"
]
```

To see what Sub-technique objects are linked to/from;

```sql
LET attack_pattern_ids = (
  FOR doc IN mitre_atlas_vertex_collection
    FILTER doc._stix2arango_note == "v4.7.0"
    AND doc.type == "attack-pattern"
    AND doc.x_mitre_is_subtechnique == true
    RETURN doc.id
)
FOR doc IN mitre_atlas_edge_collection
  FILTER (CONTAINS(doc.source_ref, "attack-pattern") OR CONTAINS(doc.target_ref, "attack-pattern"))
  AND (doc.source_ref IN attack_pattern_ids OR doc.target_ref IN attack_pattern_ids)
  AND doc._stix2arango_note == "v4.7.0"
  LET source_ref_prefix = SPLIT(doc.source_ref, "--")[0]
  LET target_ref_prefix = SPLIT(doc.target_ref, "--")[0]
  RETURN DISTINCT {
    "relationship_type": doc.relationship_type,
    "source_ref_object_type": source_ref_prefix,
    "target_ref_object_type": target_ref_prefix,
    "is_property_ref": doc._is_ref
  }
```

| relationship_type       | source_ref_object_type | target_ref_object_type | is_property_ref |
|-------------------------|------------------------|------------------------|-----------------|
| subtechnique-of         | attack-pattern         | attack-pattern         | false           |
| x_mitre_contents-object | x-mitre-collection     | attack-pattern         | true            |
| mitigates               | course-of-action       | attack-pattern         | false           |

If you want to find out what is linked to a specific Sub-Technique, you can use the following search (here I use `AML.T0000.000`);

```sql
LET vertexDocs = (
  FOR doc IN mitre_atlas_vertex_collection
    FILTER doc._stix2arango_note == "v4.7.0"
    AND doc.type == "attack-pattern"
    AND IS_ARRAY(doc.external_references)
    LET matchingExtRefs = (
      FOR extRef IN doc.external_references
        FILTER extRef.external_id == "AML.T0000.000"
        RETURN extRef
    )
    FILTER LENGTH(matchingExtRefs) > 0
    LET keys = ATTRIBUTES(doc)
    LET filteredKeys = keys[* FILTER !STARTS_WITH(CURRENT, "_")]
    RETURN KEEP(doc, filteredKeys)
)

FOR vertexDoc IN vertexDocs
  FOR edgeDoc IN mitre_atlas_edge_collection
    FILTER edgeDoc.target_ref == vertexDoc.id OR edgeDoc.source_ref == vertexDoc.id
    LET keys = ATTRIBUTES(edgeDoc)
    LET filteredKeys = keys[* FILTER !STARTS_WITH(CURRENT, "_")]
    RETURN KEEP(edgeDoc, filteredKeys)
```

Returns 2 results in v4.7.0.

### ATLAS object `Mitigation` = STIX object `course-of-action`

[ATLAS Mitigations](https://attack.mitre.org/mitigations/) represent security concepts and classes of technologies that can be used to prevent a technique or sub-technique from being successfully executed.

Mitigations have IDs in the format: `AML.MNNNN`

For example, [Mitigation AML.M0000 - Limit Public Release of Information](https://atlas.mitre.org/mitigations/AML.M0000), which can be retrieved from the database using the following search;

```sql
FOR doc IN mitre_atlas_vertex_collection
  FILTER doc._stix2arango_note == "v4.7.0"
  AND doc.type == "course-of-action"
  AND IS_ARRAY(doc.external_references)
  LET matchingExtRefs = (
    FOR extRef IN doc.external_references
      FILTER extRef.external_id == "AML.M0000"
      RETURN extRef
  )
  FILTER LENGTH(matchingExtRefs) > 0
  LET keys = ATTRIBUTES(doc)
  LET filteredKeys = keys[* FILTER !STARTS_WITH(CURRENT, "_")]
  RETURN KEEP(doc, filteredKeys)
```

```json
[
  {
    "created": "2023-04-12T00:00:00.000Z",
    "description": "Limit the public release of technical information about the machine learning stack used in an organization's products or services. Technical knowledge of how machine learning is used can be leveraged by adversaries to perform targeting and tailor attacks to the target system. Additionally, consider limiting the release of organizational information - including physical locations, researcher names, and department structures - from which technical details such as machine learning techniques, model architectures, or datasets may be inferred.",
    "external_references": [
      {
        "source_name": "mitre-atlas",
        "url": "https://atlas.mitre.org/mitigations/AML.M0000",
        "external_id": "AML.M0000"
      }
    ],
    "id": "course-of-action--40076545-e797-4508-a294-943096a12111",
    "modified": "2024-10-01T00:00:00.000Z",
    "name": "Limit Public Release of Information",
    "spec_version": "2.1",
    "type": "course-of-action"
  }
]
```

To return all ATLAS Mitigation objects:

```sql
FOR doc IN mitre_atlas_vertex_collection
  FILTER doc._stix2arango_note == "v4.7.0"
  AND doc.type == "course-of-action"
  LET keys = ATTRIBUTES(doc)
  LET filteredKeys = keys[* FILTER !STARTS_WITH(CURRENT, "_")]
  RETURN KEEP(doc, filteredKeys)
```

26 results in v4.7.0.

```sql
FOR doc IN mitre_atlas_vertex_collection
  FILTER doc._stix2arango_note == "v4.7.0"
  AND doc.type == "course-of-action"
  RETURN doc.name
```

```json
[
  "Limit Public Release of Information",
  "Limit Model Artifact Release",
  "Passive ML Output Obfuscation",
  "Model Hardening",
  "Restrict Number of ML Model Queries",
  "Control Access to ML Models and Data at Rest",
  "Use Ensemble Methods",
  "Sanitize Training Data",
  "Validate ML Model",
  "Use Multi-Modal Sensors",
  "Input Restoration",
  "Restrict Library Loading",
  "Encrypt Sensitive Information",
  "Code Signing",
  "Verify ML Artifacts",
  "Adversarial Input Detection",
  "Vulnerability Scanning",
  "Model Distribution Methods",
  "User Training",
  "Control Access to ML Models and Data in Production",
  "Generative AI Guardrails",
  "Generative AI Guidelines",
  "Generative AI Model Alignment",
  "AI Bill of Materials",
  "AI Telemetry Logging",
  "Maintain AI Dataset Provenance"
]
```

To see what `course-of-action` objects are linked to/from;

```sql
FOR doc IN mitre_atlas_edge_collection
  FILTER CONTAINS(doc.source_ref, "course-of-action") 
  OR CONTAINS(doc.target_ref, "course-of-action")
  AND doc._stix2arango_note == "v4.7.0"
  LET source_ref_prefix = SPLIT(doc.source_ref, "--")[0]
  LET target_ref_prefix = SPLIT(doc.target_ref, "--")[0]
  RETURN DISTINCT {
    "relationship_type": doc.relationship_type,
    "source_ref_object_type": source_ref_prefix,
    "target_ref_object_type": target_ref_prefix,
    "is_property_ref": doc._is_ref
  }
```

| relationship_type       | source_ref_object_type | target_ref_object_type | is_property_ref |
|-------------------------|------------------------|------------------------|-----------------|
| mitigates               | course-of-action       | attack-pattern         | false           |
| x_mitre_contents-object | x-mitre-collection     | course-of-action       | true            |

If you want to find out what is linked to a specific Mitigation, you can use the following search (here I use `AML.M0000`);

```sql
LET vertexDocs = (
  FOR doc IN mitre_atlas_vertex_collection
    FILTER doc._stix2arango_note == "v4.7.0"
    AND doc.type == "course-of-action"
    AND IS_ARRAY(doc.external_references)
    LET matchingExtRefs = (
      FOR extRef IN doc.external_references
        FILTER extRef.external_id == "AML.M0000"
        RETURN extRef
    )
    FILTER LENGTH(matchingExtRefs) > 0
    LET keys = ATTRIBUTES(doc)
    LET filteredKeys = keys[* FILTER !STARTS_WITH(CURRENT, "_")]
    RETURN KEEP(doc, filteredKeys)
)

FOR vertexDoc IN vertexDocs
  FOR edgeDoc IN mitre_atlas_edge_collection
    FILTER edgeDoc.target_ref == vertexDoc.id OR edgeDoc.source_ref == vertexDoc.id
    LET keys = ATTRIBUTES(edgeDoc)
    LET filteredKeys = keys[* FILTER !STARTS_WITH(CURRENT, "_")]
    RETURN KEEP(edgeDoc, filteredKeys)
```

Returns 5 results in v4.7.0.

### ATLAS Case Studies

[ATLAS case studies](https://atlas.mitre.org/studies) demonstrate AI attacks on production systems.

ATLAS case-studies are not represented as STIX objects in the main STIX bundle that MITRE generate.

However, some selected case studies as STIX Report and Incident objects. [You can find these here](https://github.com/mitre-atlas/atlas-navigator-data/tree/main/dist/opencti-bundles).

## Using ATLAS with ATT&CK Navigator

At the start of the post I showed a screenshot of ATLAS on a matrix.

As the ATLAS STIX objects are modelled in a similar way to ATT&CK, it makes them compatible with the ATT&CK Navigator to load them into a matrix view (and annotate and work with the objects in the matrix)

To add ATLAS v4.7.0 as a layer to Navigator;

<img class="img-fluid" src="/assets/images/blog/2024-12-30/atlas-navigator-upload.png" alt="MITRE ATLAS ATT&CK Navigator" title="MITRE ATLAS ATT&CK Navigator" />

1. Go to `https://mitre-attack.github.io/attack-navigator/`
  * ...[or run it yourself](https://github.com/mitre-attack/attack-navigator/)
2. Select Create New Layer
3. Enter:
  * STIX Bundle URL: `https://downloads.ctibutler.com/mitre-atlas-repo-data/mitre-atlas-v4_7_0.json` (_Note, this file will become outdated with future releases of ATLAS. The latest version of the ATLAS bundle can always be found in [CTI Butler](https://www.ctibutler.com/)_)
  * Bundle Version Number: `4.7`
  * Bundle Domain: `ATLAS`

<img class="img-fluid" src="/assets/images/blog/2024-12-30/atlas-navigator-loaded.png" alt="MITRE ATLAS ATT&CK Navigator" title="MITRE ATLAS ATT&CK Navigator" />