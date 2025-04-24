---
date: 2025-01-06
last_modified: 2025-01-06
title: "Fighting Disinformation: Classifying Your Research Using Standardised Disinformation Tactics and Techniques"
description: "Our intel team is increasingly using the DISARM framework to classify parts of our research as disinformation campaigns continue increase. In this post I will introduce the DISARM data structure."
categories:
  - "RESEARCH"
tags: [
	"DISARM",
  "Disinformation"
]
products:
  - stix2arango
  - CTIButler
  - disarm2stix
author_staff_member: david-greenwood
image: /assets/images/blog/2025-01-06/disarm-graph.jpg
featured_image: /assets/images/blog/2025-01-06/disarm-graph.jpg
layout: post
published: true
redirect_from:
  - 
---

## tl;dr

The [DISARM](https://www.disarm.foundation/framework) (Disinformation Analysis and Risk Management) framework is a structured methodology designed to help organisations identify, assess, and mitigate the risks associated with disinformation campaigns.

It provides a systematic approach to understanding how disinformation threats evolve and how they can impact individuals, businesses, and governments.

In the way MITRE ATT&CK has provided a standard for contextual information about adversary tactics and techniques based on real-world observations, DISARM aims to do the same for disinformation.

Our intel team is increasingly using the framework to classify parts of our research in a standard way as disinformation campaigns increase.

Like ATT&CK, [the framework is based around tactics and techniques](https://disarmfoundation.github.io/disarm-navigator/);

<img class="img-fluid" src="/assets/images/blog/2025-01-06/disarm-navigator.png" alt="DISARM Matrix" title="DISARM Matrix" />

In another post on this blog, I showed you the data structure of MITRE ATT&CK, [PSA: MITRE ATT&CK is More Than Tactics and Techniques](/blog/mitre_attack_data_structure/), and [MITRE ATLAS, Fortifying AI: How MITRE ATLAS Shields Artificial Intelligence from Adversarial Threats](/blog/introducing_mitre_atlas/).

I aim to achieve a similar thing in this post by lifting the lid on DISARM objects so you can use them in your research.

## DISARM STIX objects

Like ATT&CK, DISARM data is built on STIX objects and structured like so;

<iframe width="768" height="432" src="https://miro.com/app/live-embed/uXjVKpP-IGw=/?moveToViewport=-983,-1714,3913,1797&embedId=422393375373" frameborder="0" scrolling="no" allow="fullscreen; clipboard-read; clipboard-write" allowfullscreen></iframe>

Lets break this down by looking at each DISARM object type individually to show how I built this diagram.

## Follow along

In this post I am going to provide queries you can use to analyse and filter DISARM data.

If you would like to follow along, and keep a searchable copy of DISARM locally, you can import the data using [stix2arango](https://github.com/muchdogesec/stix2arango/).

Once you've installed stix2arango by following the instructions described in the repository, you can run the following command to import v1.6 of DISARM to ArangoDB;

```shell
python3 utilities/arango_cti_processor/insert_archive_disarm.py \
    --database blog_introducing_disarm \
    --versions 1_6
```

You can then use the query interface in the ArangoDB UI to run the AQL queries shown in this post.

## Understanding the STIX objects

### DISARM object `Matrix` = STIX object `x-mitre-matrix`

`x-mitre-matrix` contain a list of Tactics (under `tactic_refs`) in the framework.

This object is used to define the order of Tactics in the framework.

To retrieve all `x-mitre-matrix` objects from the DB;

```sql
FOR doc IN disarm_vertex_collection
  FILTER doc._stix2arango_note == "v1.6"
  AND doc.type == "x-mitre-matrix"
  AND doc.x_mitre_deprecated != true
  AND doc.revoked != true
  LET keys = ATTRIBUTES(doc)
  LET filteredKeys = keys[* FILTER !STARTS_WITH(CURRENT, "_")]
  RETURN [KEEP(doc, filteredKeys)]
```

```json
[
  [
    {
      "created": "2020-01-01T00:00:00.000Z",
      "created_by_ref": "identity--8700e156-6ce9-5090-8589-f9d0aef7bdb7",
      "description": "Incident creator TTPs.",
      "external_references": [
        {
          "source_name": "DISARM",
          "url": "https://www.disarm.foundation/",
          "external_id": "DISARM"
        }
      ],
      "id": "x-mitre-matrix--03e1a731-175d-5181-ba28-8be2e2159da9",
      "modified": "2024-11-22T00:00:00.000Z",
      "name": "DISARM Red Framework",
      "object_marking_refs": [
        "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
        "marking-definition--8700e156-6ce9-5090-8589-f9d0aef7bdb7"
      ],
      "spec_version": "2.1",
      "tactic_refs": [
        "x-mitre-tactic--b977ad29-eb0c-5f09-bb2f-6d3f23e2a175",
        "x-mitre-tactic--82beb3f6-7be5-502d-9511-b6264777171e",
        "x-mitre-tactic--10ccaa61-bf44-56ec-b1a7-3fc01942ec6d",
        "x-mitre-tactic--5991cba0-faaf-51ee-9928-4deba0ca83b6",
        "x-mitre-tactic--2c0826a4-1598-5909-810a-792dda66651d",
        "x-mitre-tactic--787a1b03-3797-5ccb-bc2e-049332bd3c94",
        "x-mitre-tactic--fdbba12c-028c-5707-8d12-83cddfd0b9e8",
        "x-mitre-tactic--c8de9ad5-0d1d-5ece-b18b-e474b6162104",
        "x-mitre-tactic--7ebacd41-0ee5-5628-9d85-a7d52db80821",
        "x-mitre-tactic--8a30baff-0b0c-5bab-8066-26655d672640",
        "x-mitre-tactic--2bb32a6b-0893-5d9c-a362-d41cb2a4a6ae",
        "x-mitre-tactic--ec5943c5-cf40-59dd-a7ed-c2175fc9727a",
        "x-mitre-tactic--c597dc51-891f-5fe0-a2ab-dd2c245ed0f4",
        "x-mitre-tactic--a17f30bf-131f-5f29-bd3b-16b801bf4084",
        "x-mitre-tactic--cc6cd844-a777-5265-9216-e439b16b339b",
        "x-mitre-tactic--92928c79-f2cc-5cd3-aaf8-27254fdd79da"
      ],
      "type": "x-mitre-matrix"
    }
  ]
]
```

Only returns 1 result in v1.6.

To see what the `x-mitre-matrix` object is linked to/from;

```sql
FOR doc IN disarm_edge_collection
  FILTER CONTAINS(doc.source_ref, "x-mitre-matrix") 
  OR CONTAINS(doc.target_ref, "x-mitre-matrix")
  AND doc._stix2arango_note == "v1.6"
  LET source_ref_prefix = SPLIT(doc.source_ref, "--")[0]
  LET target_ref_prefix = SPLIT(doc.target_ref, "--")[0]
  RETURN DISTINCT {
    "relationship_type": doc.relationship_type,
    "source_ref_object_type": source_ref_prefix,
    "target_ref_object_type": target_ref_prefix,
    "is_property_ref": doc._is_ref
  }
```

| relationship_type | source_ref_object_type | target_ref_object_type | is_property_ref |
| ----------------- | ---------------------- | ---------------------- | --------------- |
| created-by        | x-mitre-matrix         | identity               | true            |
| tactic            | x-mitre-matrix         | x-mitre-tactic         | true            |
| object-marking    | x-mitre-matrix         | marking-definition     | true            |

### DISARM object `Tactic` = STIX object `x-mitre-tactic`

DISARM Tactics represent the “why” of a technique: the reason for performing an action. Tactics serve as useful contextual categories for individual techniques and cover standard notations for things adversaries do during an operation.

Tactics have IDs in the format: `TANN`

For example, Tactic TA02 Plan Objectives, which can be retrieved from the DB using the following query; 

```sql
FOR doc IN disarm_vertex_collection
  FILTER doc._stix2arango_note == "v1.6"
  AND doc.type == "x-mitre-tactic"
  AND IS_ARRAY(doc.external_references)
  LET matchingExtRefs = (
    FOR extRef IN doc.external_references
      FILTER extRef.external_id == "TA02"
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
    "created": "2020-01-01T00:00:00.000Z",
    "created_by_ref": "identity--8700e156-6ce9-5090-8589-f9d0aef7bdb7",
    "description": "Set clearly defined, measurable, and achievable objectives. In some cases achieving objectives ties execution of tactical tasks to reaching the desired strategic end state. In other cases, where there is no clearly defined strategic end state, the tactical objective may stand on its own. The objective statement should not specify the way and means of accomplishment but rather the goal the threat actor wishes to achieve. ",
    "external_references": [
      {
        "source_name": "DISARM",
        "url": "https://raw.githubusercontent.com/DISARMFoundation/DISARMframeworks/main/generated_pages/tactics/TA02.md",
        "external_id": "TA02"
      }
    ],
    "id": "x-mitre-tactic--82beb3f6-7be5-502d-9511-b6264777171e",
    "modified": "2024-11-22T00:00:00.000Z",
    "name": "Plan Objectives",
    "object_marking_refs": [
      "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
      "marking-definition--8700e156-6ce9-5090-8589-f9d0aef7bdb7"
    ],
    "spec_version": "2.1",
    "type": "x-mitre-tactic",
    "x_mitre_shortname": "plan-objectives"
  }
]
```

To return all DISARM `x-mitre-tactic` objects:

```sql
FOR doc IN disarm_vertex_collection
  FILTER doc._stix2arango_note == "v1.6"
  AND doc.type == "x-mitre-tactic"
  LET keys = ATTRIBUTES(doc)
  LET filteredKeys = keys[* FILTER !STARTS_WITH(CURRENT, "_")]
  RETURN KEEP(doc, filteredKeys)
```

Returns 16 results in v1.6, which are;

```sql
FOR doc IN disarm_vertex_collection
  FILTER doc._stix2arango_note == "v1.6"
  AND doc.type == "x-mitre-tactic"
  RETURN doc.name
```

```json
[
  "Plan Strategy",
  "Plan Objectives",
  "Microtarget",
  "Develop Content",
  "Select Channels and Affordances",
  "Conduct Pump Priming",
  "Deliver Content",
  "Drive Offline Activity",
  "Persist in the Information Environment",
  "Assess Effectiveness",
  "Target Audience Analysis",
  "Develop Narratives",
  "Establish Assets",
  "Establish Legitimacy",
  "Maximise Exposure",
  "Drive Online Harms"
]
```

To see what `x-mitre-tactic` objects are linked to/from;

```sql
FOR doc IN disarm_edge_collection
  FILTER CONTAINS(doc.source_ref, "x-mitre-tactic") 
  OR CONTAINS(doc.target_ref, "x-mitre-tactic")
  AND doc._stix2arango_note == "v1.6"
  LET source_ref_prefix = SPLIT(doc.source_ref, "--")[0]
  LET target_ref_prefix = SPLIT(doc.target_ref, "--")[0]
  RETURN DISTINCT {
    "relationship_type": doc.relationship_type,
    "source_ref_object_type": source_ref_prefix,
    "target_ref_object_type": target_ref_prefix,
    "is_property_ref": doc._is_ref
  }
```

| relationship_type | source_ref_object_type | target_ref_object_type | is_property_ref |
| ----------------- | ---------------------- | ---------------------- | --------------- |
| created-by        | x-mitre-tactic         | identity               | true            |
| object-marking    | x-mitre-tactic         | marking-definition     | true            |
| tactic            | x-mitre-matrix         | x-mitre-tactic         | true            |

If you want to find out what is linked to a specific Tactic, you can use the following search (here I use `TA02`);

```sql
LET vertexDocs = (
  FOR doc IN disarm_vertex_collection
    FILTER doc._stix2arango_note == "v1.6"
    AND doc.type == "x-mitre-tactic"
    AND IS_ARRAY(doc.external_references)
    LET matchingExtRefs = (
      FOR extRef IN doc.external_references
        FILTER extRef.external_id == "TA02"
        RETURN extRef
    )
    FILTER LENGTH(matchingExtRefs) > 0
    LET keys = ATTRIBUTES(doc)
    LET filteredKeys = keys[* FILTER !STARTS_WITH(CURRENT, "_")]
    RETURN KEEP(doc, filteredKeys)
)

FOR vertexDoc IN vertexDocs
  FOR edgeDoc IN disarm_edge_collection
    FILTER edgeDoc.target_ref == vertexDoc.id OR edgeDoc.source_ref == vertexDoc.id
    LET keys = ATTRIBUTES(edgeDoc)
    LET filteredKeys = keys[* FILTER !STARTS_WITH(CURRENT, "_")]
    RETURN KEEP(edgeDoc, filteredKeys)
```

Returns 4 results in v1.6.

### DISARM object `Technique` = STIX object `attack-pattern`

DISARM Techniques represent “how” an adversary achieves a tactical objective by performing an action. For example, an adversary may gain initial access by compromising the machine learning (ML) supply chain.

Techniques have IDs in the format: `TNNNN`

For example, Technique T0002 Facilitate State Propaganda, which can be retrieved from the DB using the following query; 

```sql
FOR doc IN disarm_vertex_collection
  FILTER doc._stix2arango_note == "v1.6"
  AND doc.type == "attack-pattern"
  AND doc.x_mitre_is_subtechnique != true
  AND IS_ARRAY(doc.external_references)
  LET matchingExtRefs = (
    FOR extRef IN doc.external_references
      FILTER extRef.external_id == "T0002"
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
    "created": "2020-01-01T00:00:00.000Z",
    "created_by_ref": "identity--8700e156-6ce9-5090-8589-f9d0aef7bdb7",
    "description": "Organise citizens around pro-state messaging. Coordinate paid or volunteer groups to push state propaganda.",
    "external_references": [
      {
        "source_name": "DISARM",
        "url": "https://raw.githubusercontent.com/DISARMFoundation/DISARMframeworks/main/generated_pages/techniques/T0002.md",
        "external_id": "T0002"
      }
    ],
    "id": "attack-pattern--8ab240c2-6f7a-5c48-a4c8-3ab15b7150f3",
    "kill_chain_phases": [
      {
        "kill_chain_name": "disarm",
        "phase_name": "plan-objectives"
      }
    ],
    "modified": "2024-11-22T00:00:00.000Z",
    "name": "Facilitate State Propaganda",
    "object_marking_refs": [
      "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
      "marking-definition--8700e156-6ce9-5090-8589-f9d0aef7bdb7"
    ],
    "spec_version": "2.1",
    "type": "attack-pattern",
    "x_mitre_is_subtechnique": false,
    "x_mitre_platforms": [
      "Windows",
      "Linux",
      "Mac"
    ],
    "x_mitre_version": "2.1"
  }
]
```

To return all DISARM Technique objects:

```sql
FOR doc IN disarm_vertex_collection
  FILTER doc._stix2arango_note == "v1.6"
  AND doc.type == "attack-pattern"
  AND doc.x_mitre_is_subtechnique != true
  LET keys = ATTRIBUTES(doc)
  LET filteredKeys = keys[* FILTER !STARTS_WITH(CURRENT, "_")]
  RETURN KEEP(doc, filteredKeys)
```

Returns 103 results in v1.6, which are;

```sql
FOR doc IN disarm_vertex_collection
  FILTER doc._stix2arango_note == "v1.6"
  AND doc.type == "attack-pattern"
  AND doc.x_mitre_is_subtechnique != true
  RETURN doc.name
```

```json
[
  "Facilitate State Propaganda",
  "Leverage Existing Narratives",
  "Develop Competing Narratives",
  "Cultivate Ignorant Agents",
  "Prepare Fundraising Campaigns",
  "Create Hashtags and Search Artefacts",
  "Create Clickbait",
  "Conduct Fundraising",
  "Purchase Targeted Advertisements",
  "Trial Content",
  "Leverage Conspiracy Theory Narratives",
  "Distort Facts",
  "Online Polls",
  "Bait Influencer",
  "Demand Insurmountable Proof",
  "Seed Kernel of Truth",
  "Seed Distortions",
  "Use Fake Experts",
  "Use Search Engine Optimisation",
```

...cut for brevity here.

To see what Technique objects are linked to/from;

```sql
LET attack_pattern_ids = (
  FOR doc IN disarm_vertex_collection
    FILTER doc._stix2arango_note == "v1.6"
    AND doc.type == "attack-pattern"
    AND doc.x_mitre_is_subtechnique != true
    RETURN doc.id
)
FOR doc IN disarm_edge_collection
  FILTER (CONTAINS(doc.source_ref, "attack-pattern") OR CONTAINS(doc.target_ref, "attack-pattern"))
  AND (doc.source_ref IN attack_pattern_ids OR doc.target_ref IN attack_pattern_ids)
  AND doc._stix2arango_note == "v1.6"
  LET source_ref_prefix = SPLIT(doc.source_ref, "--")[0]
  LET target_ref_prefix = SPLIT(doc.target_ref, "--")[0]
  RETURN DISTINCT {
    "relationship_type": doc.relationship_type,
    "source_ref_object_type": source_ref_prefix,
    "target_ref_object_type": target_ref_prefix,
    "is_property_ref": doc._is_ref
  }
```

| relationship_type | source_ref_object_type | target_ref_object_type | is_property_ref |
| ----------------- | ---------------------- | ---------------------- | --------------- |
| created-by        | attack-pattern         | identity               | true            |
| object-marking    | attack-pattern         | marking-definition     | true            |
| subtechnique-of   | attack-pattern         | attack-pattern         | false           |

If you want to find out what is linked to a specific Technique, you can use the following search (here I use `AML.T0002`);


```sql
LET vertexDocs = (
  FOR doc IN disarm_vertex_collection
    FILTER doc._stix2arango_note == "v1.6"
    AND doc.type == "attack-pattern"
    AND IS_ARRAY(doc.external_references)
    LET matchingExtRefs = (
      FOR extRef IN doc.external_references
        FILTER extRef.external_id == "T0002"
        RETURN extRef
    )
    FILTER LENGTH(matchingExtRefs) > 0
    LET keys = ATTRIBUTES(doc)
    LET filteredKeys = keys[* FILTER !STARTS_WITH(CURRENT, "_")]
    RETURN KEEP(doc, filteredKeys)
)

FOR vertexDoc IN vertexDocs
  FOR edgeDoc IN disarm_edge_collection
    FILTER edgeDoc.target_ref == vertexDoc.id OR edgeDoc.source_ref == vertexDoc.id
    LET keys = ATTRIBUTES(edgeDoc)
    LET filteredKeys = keys[* FILTER !STARTS_WITH(CURRENT, "_")]
    RETURN KEEP(edgeDoc, filteredKeys)
```

Returns 3 results in v1.6.

### DISARM object `Sub-Technique` = STIX object `attack-pattern`

DISARM Sub-Techniques (`attack-pattern` with [STIX Custom Property](https://www.dogesec.com/blog/create_custom_stix_objects/) `"x_mitre_is_subtechnique": true`) are a more specific implementation of a Technique (they are children to a parent).

Sub-technique have IDs in the format: `TNNNN.NNN`

For example, T0023.002 Edit Open-Source Content is a Sub-Technique of Technique T0023 Distort Facts.

You can retrieve T0023.002 from the database using the following query;

```sql
FOR doc IN disarm_vertex_collection
  FILTER doc._stix2arango_note == "v1.6"
  AND doc.type == "attack-pattern"
  AND doc.x_mitre_is_subtechnique == true
  AND IS_ARRAY(doc.external_references)
  LET matchingExtRefs = (
    FOR extRef IN doc.external_references
      FILTER extRef.external_id == "T0023.002"
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
    "created": "2020-01-01T00:00:00.000Z",
    "created_by_ref": "identity--8700e156-6ce9-5090-8589-f9d0aef7bdb7",
    "description": "An influence operation may edit open-source content, such as collaborative blogs or encyclopaedias, to promote its narratives on outlets with existing credibility and audiences. Editing open-source content may allow an operation to post content on platforms without dedicating resources to the creation and maintenance of its own assets.",
    "external_references": [
      {
        "source_name": "DISARM",
        "url": "https://raw.githubusercontent.com/DISARMFoundation/DISARMframeworks/main/generated_pages/techniques/T0023.002.md",
        "external_id": "T0023.002"
      }
    ],
    "id": "attack-pattern--cf8bc0a8-2e55-5b0f-9e41-5ed189605f37",
    "kill_chain_phases": [
      {
        "kill_chain_name": "disarm",
        "phase_name": "develop-content"
      }
    ],
    "modified": "2024-11-22T00:00:00.000Z",
    "name": "Edit Open-Source Content",
    "object_marking_refs": [
      "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
      "marking-definition--8700e156-6ce9-5090-8589-f9d0aef7bdb7"
    ],
    "spec_version": "2.1",
    "type": "attack-pattern",
    "x_mitre_is_subtechnique": true,
    "x_mitre_platforms": [
      "Windows",
      "Linux",
      "Mac"
    ],
    "x_mitre_version": "2.1"
  }
]
```

To return all DISARM Sub-technique objects:

```sql
FOR doc IN disarm_vertex_collection
  FILTER doc._stix2arango_note == "v1.6"
  AND doc.type == "attack-pattern"
  AND doc.x_mitre_is_subtechnique == true
  LET keys = ATTRIBUTES(doc)
  LET filteredKeys = keys[* FILTER !STARTS_WITH(CURRENT, "_")]
  RETURN KEEP(doc, filteredKeys)
```

288 results in v1.6, which are;

```sql
FOR doc IN disarm_vertex_collection
  FILTER doc._stix2arango_note == "v1.6"
  AND doc.type == "attack-pattern"
  AND doc.x_mitre_is_subtechnique == true
  RETURN doc.name
```

```json
[
  "Raise Funds from Malign Actors",
  "Raise Funds from Ignorant Agents",
  "Use Existing Hashtag",
  "Create New Hashtag",
  "Conduct Crowdfunding Campaigns",
  "Amplify Existing Conspiracy Theory Narratives",
  "Develop Original Conspiracy Theory Narratives",
  "Reframe Context",
  "Edit Open-Source Content",
  "Boycott/\"Cancel\" Opponents",
  "Harass People Based on Identities",
  "Threaten to Dox",
  "Dox",
  "Trolls Amplify and Manipulate",
  "Flood Existing Hashtag",
  "Bots Amplify via Automated Forwarding and Reposting",
  "Utilise Spamoflauge",
  "Conduct Swarming",
  "Conduct Keyword Squatting",
  "Inauthentic Sites Amplify News and Narratives",
  "Generate Information Pollution",
  "Pay for Physical Action",
  "Conduct Symbolic Action",
  "Geographic Segmentation",
  "Demographic Segmentation",
  "Economic Segmentation",
  "Psychographic Segmentation",
  "Political Segmentation",
  "Geopolitical Advantage",
  "Domestic Political Advantage",
  "Economic Advantage",
  "Ideological Advantage",
  "Discredit Credible Sources",
  "Monitor Social Media Analytics",
  "Evaluate Media Surveys",
  "Identify Trending Topics/Hashtags",
  "Conduct Web Traffic Analysis",
  "Assess Degree/Type of Media Access",
  "Find Echo Chambers",
  "Identify Data Voids",
  "Identify Existing Prejudices",
  "Identify Existing Fissures",
  "Identify Existing Conspiracy Narratives/Suspicions",
  "Identify Wedge Issues",
  "Identify Target Audience Adversaries",
  "Identify Media System Vulnerabilities",
```

...cut for brevity here.

To see what Sub-technique objects are linked to/from;

```sql
LET attack_pattern_ids = (
  FOR doc IN disarm_vertex_collection
    FILTER doc._stix2arango_note == "v1.6"
    AND doc.type == "attack-pattern"
    AND doc.x_mitre_is_subtechnique == true
    RETURN doc.id
)
FOR doc IN disarm_edge_collection
  FILTER (CONTAINS(doc.source_ref, "attack-pattern") OR CONTAINS(doc.target_ref, "attack-pattern"))
  AND (doc.source_ref IN attack_pattern_ids OR doc.target_ref IN attack_pattern_ids)
  AND doc._stix2arango_note == "v1.6"
  LET source_ref_prefix = SPLIT(doc.source_ref, "--")[0]
  LET target_ref_prefix = SPLIT(doc.target_ref, "--")[0]
  RETURN DISTINCT {
    "relationship_type": doc.relationship_type,
    "source_ref_object_type": source_ref_prefix,
    "target_ref_object_type": target_ref_prefix,
    "is_property_ref": doc._is_ref
  }
```

| relationship_type | source_ref_object_type | target_ref_object_type | is_property_ref |
| ----------------- | ---------------------- | ---------------------- | --------------- |
| subtechnique-of   | attack-pattern         | attack-pattern         | false           |
| created-by        | attack-pattern         | identity               | true            |
| object-marking    | attack-pattern         | marking-definition     | true            |

If you want to find out what is linked to a specific Sub-Technique, you can use the following search (here I use `T0023.002`);

```sql
LET vertexDocs = (
  FOR doc IN disarm_vertex_collection
    FILTER doc._stix2arango_note == "v1.6"
    AND doc.type == "attack-pattern"
    AND IS_ARRAY(doc.external_references)
    LET matchingExtRefs = (
      FOR extRef IN doc.external_references
        FILTER extRef.external_id == "T0023.002"
        RETURN extRef
    )
    FILTER LENGTH(matchingExtRefs) > 0
    LET keys = ATTRIBUTES(doc)
    LET filteredKeys = keys[* FILTER !STARTS_WITH(CURRENT, "_")]
    RETURN KEEP(doc, filteredKeys)
)

FOR vertexDoc IN vertexDocs
  FOR edgeDoc IN disarm_edge_collection
    FILTER edgeDoc.target_ref == vertexDoc.id OR edgeDoc.source_ref == vertexDoc.id
    LET keys = ATTRIBUTES(edgeDoc)
    LET filteredKeys = keys[* FILTER !STARTS_WITH(CURRENT, "_")]
    RETURN KEEP(edgeDoc, filteredKeys)
```

Returns 4 results in v1.6.

## Using DISARM with ATT&CK Navigator

[disarm2stix](https://github.com/muchdogesec/disarm2stix/) is a small utility we built that converted the DISARM Framework (stored in an Excel file) into STIX 2.1 objects so we could work with it in our other tooling (all built on STIX).

In modelling those objects, we wanted to ensure they were compliant with the ATT&CK structure so we could work with it in existing ATT&CK tools, like Navigator.

[Here is a full bundle file of objects produced by disarm2stix for 1.6](https://downloads.ctibutler.com/disarm2stix-manual-output/disarm-bundle-v1_6.json).

To add DISARM v1.6 as a layer to Navigator;

<img class="img-fluid" src="/assets/images/blog/2025-01-06/disarm-navigator-load.png" alt="DISARM ATT&CK Navigator" title="DISARM ATT&CK Navigator" />

1. Go to `https://mitre-attack.github.io/attack-navigator/`
  * ...[or run it yourself](https://github.com/mitre-attack/attack-navigator/)
2. Select Create New Layer
3. Enter:
  * STIX Bundle URL: `https://downloads.ctibutler.com/disarm2stix-manual-output/disarm-bundle-v1_6.json` (_Note, this file will become outdated with future releases of DISARM. The latest version of the DISARM bundle can always be found in [CTI Butler](https://www.ctibutler.com/)_)
  * Bundle Version Number: `1.6`
  * Bundle Domain: `DISARM`

<img class="img-fluid" src="/assets/images/blog/2025-01-06/disarm-navigator.png" alt="DISARM ATT&CK Navigator" title="DISARM ATT&CK Navigator" />