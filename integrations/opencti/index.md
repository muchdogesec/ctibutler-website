---
title: CTI Butler OpenCTI Integration
description: Use CTI Butler with OpenCTI workflows to import and maintain major CTI knowledge bases in an environment built for graph-driven operational intelligence.
featured_image: /assets/images/global/ctibutler-github.png
breadcrumbs:
  - name: Home
    url: /
  - name: Integrations
    url: /integrations/
  - name: OpenCTI Integration
    url: /integrations/opencti/
---
### Overview

CTI Butler supports OpenCTI-oriented workflows by giving teams a cleaner way to source major CTI knowledge bases and feed them into a graph intelligence environment.

This is useful for teams that want consistent reference intelligence inside OpenCTI without managing many separate framework ingestion paths.

It also helps clarify the boundary between the two products. CTI Butler supplies structured knowledge-base content and connected context. OpenCTI remains the broader graph intelligence platform where many organisations operationalise, correlate, and investigate that content alongside other intelligence sources.

The integration path here is concrete rather than theoretical. OpenCTI publishes a `dogesec-ctibutler` external-import connector that syncs intelligence from CTI Butler knowledge bases into OpenCTI. According to the connector documentation, this can be used to replace separate framework connectors for MITRE ATT&CK, MITRE ATLAS, and DISARM in some OpenCTI deployments.

### Why Teams Use It

- To keep major CTI knowledge bases available in OpenCTI workflows
- To simplify ingestion of ATT&CK, CAPEC, CWE, ATLAS, DISARM, and related data
- To connect reference intelligence with broader operational graph workflows

The connector documentation specifically lists support for knowledge bases including ATT&CK Enterprise, Mobile, and ICS, CAPEC, DISARM, ATLAS, location, and sector data. In practice, that gives teams a single upstream path for several widely used reference datasets instead of maintaining separate ingestion points for each one.

That is a strong operational advantage for teams that want consistency. Instead of curating many separate reference-dataset import paths over time, they can use CTI Butler as the source layer and OpenCTI as the wider operational graph environment.

### Example Use Cases

- Maintaining authoritative reference datasets in OpenCTI
- Supporting investigations, detections, and analytics with consistent CTI context
- Reducing connector sprawl around common CTI frameworks

### Interoperability

CTI Butler produces structured CTI that can be operationalised downstream. In this model, CTI Butler acts as a context and content source, while OpenCTI acts as a wider operational graph platform.

That distinction avoids a common mistake in product positioning. CTI Butler is valuable precisely because it feeds other systems cleanly rather than trying to masquerade as the entire destination platform.

One important limitation from the current connector documentation is that this OpenCTI connector works with CTI Butler Web and does not currently support self-hosted CTI Butler installations. That is worth stating clearly so teams evaluating deployment options understand which product surface the integration depends on.

<div class="related-links">
  <h3>Related Links</h3>
  <ul>
    <li><a href="/solutions/connect-threat-intelligence-across-frameworks/">Connect Threat Intelligence Across Frameworks</a></li>
    <li><a href="/use-cases/developer-and-ai-agent-workflows/">Developer and AI Agent Workflows</a></li>
    <li><a href="/integrations/taxii-2-1-api/">TAXII 2.1 API</a></li>
    <li><a href="https://github.com/OpenCTI-Platform/connectors/tree/master/external-import/dogesec-ctibutler" target="_blank">OpenCTI CTI Butler connector</a></li>
  </ul>
</div>
