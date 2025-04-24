---
date: 2024-11-25
last_modified: 2024-11-25
title: "An Analysis of the Latest CWE Release"
description: "Last week saw the release of CWE v4.16. I took a deeper look into the latest release so you don't have to."
categories:
  - RESEARCH
tags: [
    MITRE,
    CWE,
    CVE,
    Vulnerability
    STIX
]
products:
    - stix2arango
    - cwe2stix
    - arango_cti_processor
    - CTIButler
    - Vulmatch
author_staff_member: david-greenwood
image: /assets/images/blog/2024-11-25/cwe-object-count-by-version-meta.png
featured_image: /assets/images/blog/2024-11-25/cwe-object-count-by-version-meta.png
layout: post
published: true
redirect_from:
  - 
---

## tl;dr

Last week saw the release of CWE v4.16. I took a deeper look into the latest release so you don't have to.

## Overview

I mostly work with CWEs (Common Weakness Enumeration) for vulnerability classification. NVD analyses each CVE submission for weaknesses. This makes it possible to search for vulnerabilities by weakness.

Our tool [cwe2stix](https://github.com/muchdogesec/cwe2stix) (which all the CWE data shown in this post was generated from) was created to turn all CWEs into STIX 2.1 objects so these queries between CVEs and CWEs could be run on a single intelligence graph.

<iframe width="560" height="315" src="https://www.youtube.com/embed/HWRa8kLad80?si=CakFj_BaUcLG_GaN" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>

As such, [when I heard the new CWE Version 4.16 had been released](https://cwe.mitre.org/news/archives/news2024.html#november19_CWE_Version_4.16_Now_Available), I was keen to take a deeper look (good news, it didn't break any of our software!).

This post is a summary of my "deeper look".

## Follow along

In this post I am going to provide ArangoDB queries you can use to analyse and filter MITRE CWE data.

If you would like to follow along, and keep a searchable copy of CWE STIX objects locally, you can import the data using [stix2arango](https://github.com/muchdogesec/stix2arango/).

Once you've installed stix2arango, you can run the following command to import all versions of CWE that are available at the time of writing (`4.5` - `4.16`)

```shell
python3 utilities/arango_cti_processor/insert_archive_cwe.py \
    --database blog_demo \
    --ignore_embedded_relationships
```

## CWE (weaknesses) releases over time

To begin, here is a query that shows the addition of the CWE weaknesses over each release;

```sql
FOR doc IN mitre_cwe_vertex_collection
  FILTER doc._stix2arango_note != "automatically imported on collection creation"
  AND doc.type == "weakness"
  AND doc.revoked != true
  COLLECT note = doc._stix2arango_note WITH COUNT INTO count
  LET release = SUBSTRING(note, 1) // Remove "v" prefix
  SORT TO_NUMBER(SPLIT(release, ".")[0]) ASC, TO_NUMBER(SPLIT(release, ".")[1]) ASC
  RETURN { release: release, count: count }
```

<img class="img-fluid" src="/assets/images/blog/2024-11-25/cwe-object-count-by-version.png" alt="CWE Objects by version" title="CWE Objects by version" />

Since 4.5, 18 Weaknesses have been added.

## Weakness changes in version 4.16

```sql
LET version1Docs = (
  FOR doc IN mitre_cwe_vertex_collection
  FILTER doc._stix2arango_note == "v4.15"
  AND doc.type == "weakness"
  AND doc.revoked != true
  RETURN { id: doc.id, modified: doc.modified }
)

LET version2Docs = (
  FOR doc IN mitre_cwe_vertex_collection
  FILTER doc._stix2arango_note == "v4.16"
  AND doc.type == "weakness"
  AND doc.revoked != true
  RETURN { id: doc.id, modified: doc.modified }
)

LET version1IDs = (FOR v IN version1Docs RETURN v.id)
LET version2IDs = (FOR v IN version2Docs RETURN v.id)

LET added = (
  FOR v IN version2Docs
  FILTER v.id NOT IN version1IDs
  RETURN v.id
)

LET removed = (
  FOR v IN version1Docs
  FILTER v.id NOT IN version2IDs
  RETURN v.id
)

LET unchanged = (
  FOR v2 IN version2Docs
  FILTER v2.id IN version1IDs
  LET v1 = FIRST(FOR v1Doc IN version1Docs FILTER v1Doc.id == v2.id RETURN v1Doc)
  FILTER v1.modified == v2.modified // Same ID and modified time
  RETURN v2.id
)

LET modified = (
  FOR v2 IN version2Docs
  FILTER v2.id IN version1IDs
  LET v1 = FIRST(FOR v1Doc IN version1Docs FILTER v1Doc.id == v2.id RETURN v1Doc)
  FILTER v1.modified != v2.modified // Same ID but different modified time
  RETURN v2.id
)

RETURN {
  added: LENGTH(added),
  removed: LENGTH(removed),
  unchanged: LENGTH(unchanged),
  modified: LENGTH(modified)
}
```

<img class="img-fluid" src="/assets/images/blog/2024-11-25/cwe-object-change-v4_15-v4_16.png" alt="Count of change type between CWE v4.15 and v4.16" title="Count of change type between CWE v4.15 and v4.16" />

Between 4.15 and 4.16, 1 weakness object was added and 46 were modified.

## The new weakness object in v4.16

```sql
FOR doc IN mitre_cwe_vertex_collection
FILTER doc._stix2arango_note IN ["v4.15", "v4.16"]
AND doc.type == "weakness"
AND doc.revoked != true
COLLECT id = doc.id INTO groupedDocs

LET versions = groupedDocs[*].doc
LET count_versions = LENGTH(versions)

// Only include objects that are classified as "new" (present in only one version)
FILTER count_versions == 1

// Extract external_id where source_name is "cwe"
LET cwe_id = FIRST(
    FOR ref IN versions[0].external_references
    FILTER ref.source_name == "cwe"
    RETURN ref.external_id
)

// Return only the specified fields
RETURN {
    "type": versions[0].type,
    "external_id": cwe_id,
    "name": versions[0].name
}
```

| type     | external_id | name                                                    |
| -------- | ----------- | ------------------------------------------------------- |
| weakness | CWE-1427    | Improper Neutralization of Input Used for LLM Prompting |

I expect many more AI weaknesses to be added in subsequent releases.

## Changes in CWE Views

If you're familiar with CWEs you'll know MITRE also curate "CWE Views".

CWE Views are perspectives on the CWE entries (weaknesses). They categorise and group weaknesses based on specific goals, domains, or analysis needs.

For example;

* Authentication Errors
* Authorization Errors
* Cryptographic Issues

In our data (created by [cwe2stix](https://github.com/muchdogesec/cwe2stix)), STIX `grouping` objects represent these views.

You can return a list of all current views as follows

```sql
FOR doc IN mitre_cwe_vertex_collection
FILTER doc._stix2arango_note == "v4.16"
AND doc.type == "grouping"
AND doc.revoked != true
RETURN doc.name
```

There are a total of 332 views in 4.16.

To find what Weaknesses are categorised under a View, you can use this search (this example uses the View `Authentication Errors`):

```sql
// Step 1: Retrieve the grouping document
LET grouping = FIRST(
  FOR doc IN mitre_cwe_vertex_collection
  FILTER doc._stix2arango_note == "v4.16"
  AND doc.type == "grouping"
  AND doc.name == "Authentication Errors"
  AND doc.revoked != true
  RETURN doc
)

// Step 2: Use object_refs to lookup related weaknesses
LET weaknesses = (
  FOR ref IN grouping.object_refs
  FOR doc IN mitre_cwe_vertex_collection
  FILTER doc._stix2arango_note == "v4.16"
  AND doc.revoked != true
  AND doc.id == ref
  // Extract external_id where source_name is "cwe"
  LET external_id = FIRST(
    FOR ext IN doc.external_references
    FILTER ext.source_name == "cwe"
    RETURN ext.external_id
  )
  RETURN { external_id: external_id, name: doc.name }
)

// Return the related weaknesses
RETURN weaknesses
```

| external_id | name                                                        |
| ----------- | ----------------------------------------------------------- |
| CWE-289     | Authentication Bypass by Alternate Name                     |
| CWE-290     | Authentication Bypass by Spoofing                           |
| CWE-294     | Authentication Bypass by Capture-replay                     |
| CWE-295     | Improper Certificate Validation                             |
| CWE-301     | Reflection Attack in an Authentication Protocol             |
| CWE-303     | Incorrect Implementation of Authentication Algorithm        |
| CWE-305     | Authentication Bypass by Primary Weakness                   |
| CWE-306     | Missing Authentication for Critical Function                |
| CWE-307     | Improper Restriction of Excessive Authentication Attempts   |
| CWE-308     | Use of Single-factor Authentication                         |
| CWE-309     | Use of Password System for Primary Authentication           |
| CWE-322     | Key Exchange without Entity Authentication                  |
| CWE-603     | Use of Client-Side Authentication                           |
| CWE-645     | Overly Restrictive Account Lockout Mechanism                |
| CWE-804     | Guessable CAPTCHA                                           |
| CWE-836     | Use of Password Hash Instead of Password for Authentication |

This type of search is very useful when trying to identify the correct weakness to use (for example, in vulnerability classification).

Here's what it looks like on a graph;

<div class="stixview" data-stix-url="/assets/images/blog/2024-11-25/cwe-grouping-authentication-errors.json" data-stix-allow-dragdrop="false" data-show-idrefs="false" data-show-markings="true" data-show-sidebar="true" data-graph-layout="cise" data-caption="Authentication Errors CWE View" data-disable-mouse-zoom="false" data-graph-width="100%" data-graph-height="85vh" data-show-footer="true"></div>

## How this data can be used

Earlier I mentioned how CVEs can be classified with Weaknesses on analysis.

For example, [CVE-2024-7593](https://nvd.nist.gov/vuln/detail/cve-2024-7593) is classified with the Weaknesses;

* CWE-287
* CWE-303

In [Vulmatch](https://www.vulmatch.com/) all CVEs are linked to CWEs (amongst many other contextual sources). Considering CWEs only, you get an intelligence graph that looks as follows;

<div class="stixview" data-stix-url="/assets/images/blog/2024-11-25/CVE-2024-7593.json" data-stix-allow-dragdrop="false" data-show-idrefs="false" data-show-markings="true" data-show-sidebar="true" data-graph-layout="cise" data-caption="CVE-2024-7593 Weaknesses" data-disable-mouse-zoom="false" data-graph-width="100%" data-graph-height="85vh" data-show-footer="true"></div>

## Now available on CTI Butler

CWE version 4.16 STIX objects (and those for all previous versions) can now be downloaded from [CTI Butler](https://www.ctibutler.com/).