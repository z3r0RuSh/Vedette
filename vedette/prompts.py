"""Research prompts for the five OSINT assessment axes, plus triage/synthesis.

Modeled on the enterprise security/privacy comparison playbook (jurisdiction,
contractual protections, compliance assurance, incident history, posture
signals). Every research prompt demands source URLs with publication dates and
requires "NOT FOUND" for anything that could not be verified.
"""

SYSTEM_RESEARCH = (
    "You are an OSINT researcher producing a security assessment "
    "of the target below, for a security-conscious enterprise buyer. "
    "Rules you must follow:\n"
    "1. Every factual claim must cite a source URL and, where available, the "
    "source's publication or last-updated date.\n"
    "2. Write NOT FOUND (in capitals) for anything you searched for but could "
    "not verify. Never guess, and never present an unverified claim as fact.\n"
    "3. Distinguish pages you read directly (verified live) from search-index "
    "snippets (lower confidence).\n"
    "4. End your answer with a '## Sources' section: a bullet list of every "
    "source URL you cited.\n"
    "5. Keep findings concise, structured with short headings, and free of "
    "marketing language.\n"
    "6. Stay in scope: this is a security/OSINT assessment. Do not answer "
    "non-security questions about the target (recipes, entertainment, trivia, "
    "etc.); note the request is out of scope instead."
)

SYSTEM_SYNTHESIS = (
    "You are synthesizing OSINT research into an enterprise security "
    "assessment brief for a security-conscious buyer. Be direct, cite the "
    "research you were given, and call out gaps and uncertainties explicitly. "
    "Do not invent facts beyond the research."
)

IDENTITY_PROMPT = """Resolve the identity of the organization below from public information.

Organization name: {org}
URL (may be empty): {url}

Reply with a single JSON object and nothing else, with these keys:
- "name": canonical organization name
- "domain": primary website domain
- "description": one-line description of what the company does
- "hq_country": country of headquarters, or "NOT FOUND"
- "notes": any identity ambiguities (name collisions, parent companies, rebrands)

If you cannot confidently identify the organization, set "name" to the input
and "notes" to "IDENTITY UNRESOLVED".
"""

SOFTWARE_IDENTITY_PROMPT = """Resolve the identity of the software below from public information.

Software name: {org}
URL (may be empty): {url}

Reply with a single JSON object and nothing else, with these keys:
- "name": canonical software/project name
- "version": latest known stable version, or "NOT FOUND"
- "vendor": vendor or maintaining organization, or "NOT FOUND"
- "repository": official source repository URL, or "NOT FOUND"
- "description": one-line description of what the software does
- "notes": any identity ambiguities (forks, similarly named projects)

If you cannot confidently identify the software, set "name" to the input
and "notes" to "IDENTITY UNRESOLVED".
"""

DOMAIN_IDENTITY_PROMPT = """Resolve the identity of the domain below from public information.

Domain or URL: {url}
Name (may be empty): {org}

Reply with a single JSON object and nothing else, with these keys:
- "domain": canonical domain
- "owner": organization operating the domain, or "NOT FOUND"
- "description": one-line description of what the domain is used for
- "notes": any identity ambiguities (lookalike domains, parking, redirects)

If you cannot confidently identify the domain, set "domain" to the input
and "notes" to "IDENTITY UNRESOLVED".
"""

TARGET_TYPES = ("company", "software", "domain")

IDENTITY_PROMPTS = {
    "company": IDENTITY_PROMPT,
    "software": SOFTWARE_IDENTITY_PROMPT,
    "domain": DOMAIN_IDENTITY_PROMPT,
}

AXES = ("jurisdiction", "contractual", "compliance", "incidents", "posture")

AXES_BY_TYPE = {
    "company": AXES,
    "software": ("supply_chain", "vulnerabilities", "maintenance",
                 "data_handling", "assurance"),
    "domain": ("registration", "hosting", "tls", "phishing", "infra"),
}

AXIS_TITLES = {
    # company axes
    "jurisdiction": "Jurisdiction, legal exposure & state access",
    "contractual": "Contractual customer-data protections",
    "compliance": "Compliance & assurance certifications",
    "incidents": "Incident & breach history",
    "posture": "Security posture signals",
    # software axes
    "supply_chain": "Supply chain & provenance",
    "vulnerabilities": "Vulnerability history (CVEs, advisories)",
    "maintenance": "Update cadence & support",
    "data_handling": "Data handling, telemetry & licensing",
    "assurance": "Assurance: audits & bug bounty",
    # domain axes
    "registration": "WHOIS & registration",
    "hosting": "DNS, hosting & jurisdiction",
    "tls": "TLS posture",
    "phishing": "Incident & phishing history",
    "infra": "Related infrastructure",
}


def axes_for_type(target_type):
    """Return the research axes for a target type; raises on unknown type."""
    target_type = (target_type or "company").lower()
    if target_type not in AXES_BY_TYPE:
        raise ValueError(
            "Unknown target type %r (expected one of: %s)."
            % (target_type, ", ".join(TARGET_TYPES)))
    return AXES_BY_TYPE[target_type]

AXIS_PROMPTS = {
    "jurisdiction": """Research the jurisdiction and legal exposure of this provider.

Organization identity:
{identity}

Answer:
1. Company domicile / contracting entity named in its terms, and the governing law stated in its terms of service (quote the exact clause if found; write NOT FOUND if the terms name no governing law).
2. Data center locations (countries/regions) as stated by the provider.
3. Which national governments could compel access to customer data (e.g. the provider's home-country cybersecurity/data-localization laws, US CLOUD Act exposure for US-domiciled firms, EU frameworks). Cite the specific laws.
4. Any known government-access demands, law-enforcement investigations, or raids involving the company or its parent -- include dates and outcomes, or NOT FOUND if none are public.
5. Net assessment: one paragraph on jurisdictional risk for an enterprise buyer.
""",
    "contractual": """Research the provider's contractual customer-data protections from its public terms of service, data processing agreement (DPA), master services agreement, and privacy policy.

Organization identity:
{identity}

Answer:
1. Customer ownership of data: does the provider expressly state the customer owns its data?
2. Purpose limitation: may the provider sell, rent, share, or reuse customer data, including for AI model training? Quote any no-training or no-resale clause, or write NOT FOUND if no such clause exists.
3. Sub-processors: is there a public sub-processor list, with notice/objection rights?
4. Breach notification: what notification commitment and timeline does the DPA/terms promise?
5. Government-access handling: must the provider notify the customer, redirect demands, minimize disclosure, or challenge overbroad requests?
6. Post-termination deletion: what is the deletion deadline for customer workloads/data after termination, and what is retained for how long?
7. Any notable one-sided clauses (broad liability waivers, brand-use consent, account-info retention).
""",
    "compliance": """Research the provider's compliance and assurance certifications.

Organization identity:
{identity}

Answer:
1. List each certification claimed: SOC 2 Type II, ISO 27001/27017/27018/27701/22301, HIPAA, PCI-DSS, or equivalents. For each, state the auditor if named and whether the evidence is publicly verifiable (downloadable certificate, report available under NDA, trust-center listing) or merely claimed on a marketing page.
2. Note any discrepancies between claims on different pages (different ISO numbers, vague acronyms).
3. Is a SOC 2 report or equivalent audit report obtainable? How (public download, NDA, request form)?
4. Net assessment: one paragraph on how verifiable the assurance posture is.
""",
    "incidents": """Research the provider's security incident and breach history.

Organization identity:
{identity}

Answer:
1. Any public security incidents, breaches, or customer-data exposures involving the provider's platform. Include dates, scope, and the provider's response.
2. Any law-enforcement actions, investigations, or raids involving the company or its parent company, with dates and outcomes (or NOT FOUND if no outcome is public).
3. Exclude incidents involving different companies with similar names -- verify attribution and say so.
4. If nothing is found, write NOT FOUND and describe what you searched.
""",
    "posture": """Research the provider's public security posture signals.

Organization identity:
{identity}

Answer:
1. Does the provider run a trust center or publish a security whitepaper? What does it contain?
2. Is there a public vulnerability disclosure program or bug bounty?
3. Does the provider publish a customer penetration-testing policy?
4. Any third-party reviews, analyst notes, or community assessments of the provider's trustworthiness (with dates).
5. Any recent security-relevant product announcements (e.g. encryption features) and their availability status.
""",
    # ---- software axes ----
    "supply_chain": """Research the software's supply chain and provenance.

Software identity:
{identity}

Answer:
1. Official source repository (URL) and the maintaining organization or core maintainers.
2. Release artifact signing: are releases signed (GPG, Sigstore, etc.) and is there a documented verification process?
3. Is a software bill of materials (SBOM) published for releases?
4. Dependency risk: notable heavyweight dependencies, vendored code, or past supply-chain incidents involving this project or its maintainers.
5. Forks or similarly named projects that could be confused with this one -- verify you are describing the right project.
""",
    "vulnerabilities": """Research the software's vulnerability history.

Software identity:
{identity}

Answer:
1. Known CVEs affecting this software: list CVE IDs with dates, severity (CVSS where published), and affected versions.
2. Security advisories published by the vendor/maintainers; where are they published and are they complete?
3. Time-to-patch: for the most serious CVEs, how quickly was a fix released after disclosure?
4. Any evidence of vulnerabilities being exploited in the wild.
5. If none are publicly known, write NOT FOUND and describe what you searched -- do not present absence of CVEs as proof of security.
""",
    "maintenance": """Research the software's update cadence and support status.

Software identity:
{identity}

Answer:
1. Release cadence: how often are releases cut, and what was the most recent release (version + date)?
2. Support policy: LTS branches, end-of-life dates, and what happens after EOL.
3. Is the project actively maintained (recent commits, responsive maintainers), in maintenance mode, or abandoned? Cite dates.
4. How are security fixes distributed (backported to supported branches, or upgrade-only)?
""",
    "data_handling": """Research the software's data handling, telemetry, and licensing.

Software identity:
{identity}

Answer:
1. Telemetry: does the software phone home (usage stats, crash reports)? Is it opt-in or opt-out, what is collected, and where is it sent?
2. Network behavior: what external connections does it make by default?
3. License: the exact license(s) (e.g. MIT, GPL-3.0, Apache-2.0, proprietary) and any commercial-use restrictions or CLA requirements.
4. Any data-processing terms if the software is offered as a hosted service.
""",
    "assurance": """Research the software's security assurance: audits and bug bounty.

Software identity:
{identity}

Answer:
1. Independent security audits or code reviews: who performed them, when, and are the reports public?
2. Is there a public vulnerability disclosure policy (SECURITY.md) or bug bounty program? What are the scope and response SLAs?
3. Fuzzing or continuous testing signals (e.g. OSS-Fuzz integration).
4. Net assessment: one paragraph on how seriously the project treats security.
""",
    # ---- domain axes ----
    "registration": """Research the domain's registration (WHOIS/RDAP).

Domain identity:
{identity}

Answer:
1. Registrar, creation date, expiry date, and last-updated date.
2. Registrant organization and country where visible; note if privacy/proxy redaction is in use.
3. Suspicious registration signals: very recent creation, short registration period, lookalike/typosquat patterns, bulk-registered sibling domains.
4. If WHOIS data is unavailable, write NOT FOUND and describe what you searched.
""",
    "hosting": """Research the domain's DNS, hosting, and hosting jurisdiction.

Domain identity:
{identity}

Answer:
1. Authoritative nameservers and the DNS provider.
2. A/AAAA records: hosting provider(s) and the country of the serving IPs.
3. CDN or edge provider in front of the origin, if any.
4. Jurisdictional note: which governments could compel the hosting/DNS provider to act against the domain (provider domicile, data-center countries).
""",
    "tls": """Research the domain's TLS posture.

Domain identity:
{identity}

Answer:
1. Certificate: issuer, validity period, SAN coverage, and whether it is DV/OV/EV.
2. HSTS: is it enabled, with what max-age, and is the domain on the HSTS preload list?
3. Supported TLS versions and any known weak configurations reported publicly.
4. Certificate transparency: any unexpected or suspicious certificates issued for the domain.
""",
    "phishing": """Research the domain's incident and phishing/abuse history.

Domain identity:
{identity}

Answer:
1. Any appearance on phishing, malware, or spam blocklists (with dates and the listing authority where known).
2. Public abuse reports, takedowns, or sinkholing actions involving the domain.
3. Breaches or defacements of the site served at the domain.
4. If nothing is found, write NOT FOUND and describe what you searched -- do not present a clean record as proof of legitimacy.
""",
    "infra": """Research the domain's related infrastructure.

Domain identity:
{identity}

Answer:
1. Mail infrastructure: MX records and the mail provider (relevant for phishing/BEC assessment).
2. Known subdomains and what they serve.
3. Sibling domains on the same IPs/ASN that suggest shared infrastructure or a broader operation.
4. Any passive-DNS or infrastructure pivots that expand the footprint, with sources.
""",
}

SYNTHESIS_PROMPT = """Synthesize the OSINT research below into a security assessment brief.

Target identity:
{identity}

Research by axis:
{axes_text}

Write a brief with these sections:
## Verdict
A 3-5 sentence overall judgment for a security-conscious buyer: is this target trustworthy, and what is the single biggest risk?
## Key findings
The 5-7 most important findings, each one line with its source.
## Risks & gaps
Numbered risks, plus open questions where the research came back NOT FOUND.
## Diligence checklist
What to request or verify before relying on this target (audit report, SBOM, current terms, WHOIS history, etc.).
"""

COMPARISON_PROMPT = """You are comparing multiple targets assessed with the same OSINT security playbook.

Target summaries:
{summaries}

Write:
## Ranking
Rank the targets from best to worst for a security-conscious buyer, with a one-paragraph justification per target. When the targets are of different types, rank within each type group first, then give an overall ordering.
## Head-to-head
Compare them on: {criteria}. A short paragraph each.
## Bottom line
One paragraph: which target would you choose and why, plus the key caveat for each of the others.
"""

COMPARISON_CRITERIA = {
    "company": "(a) jurisdictional risk / state access, (b) contractual data protection, (c) verifiable compliance/assurance, (d) incident history",
    "software": "(a) supply-chain trust, (b) vulnerability history & patch cadence, (c) data handling/telemetry & license, (d) assurance (audits, bug bounty)",
    "domain": "(a) registration legitimacy, (b) hosting jurisdiction & provider, (c) TLS posture, (d) abuse/phishing history",
    "mixed": "the security dimensions relevant to each target's type (jurisdiction, contracts, assurance, incidents for companies; supply chain, CVEs, maintenance for software; registration, hosting, TLS for domains)",
}


def build_identity_prompt(org, url, target_type="company"):
    template = IDENTITY_PROMPTS.get((target_type or "company").lower(),
                                    IDENTITY_PROMPT)
    return template.format(org=org or "NOT GIVEN", url=url or "NOT GIVEN")


def build_axis_prompt(axis, identity):
    if axis not in AXIS_PROMPTS:
        raise ValueError("Unknown research axis: %r" % axis)
    return AXIS_PROMPTS[axis].format(identity=identity)


def build_synthesis_prompt(identity, axis_texts, axes=None):
    axes = axes or AXES
    axes_text = "\n\n".join(
        "### %s\n%s" % (AXIS_TITLES[a], axis_texts.get(a, "NOT FOUND"))
        for a in axes
    )
    return SYNTHESIS_PROMPT.format(identity=identity, axes_text=axes_text)


def build_comparison_prompt(summaries, target_type="company"):
    criteria = COMPARISON_CRITERIA.get((target_type or "company").lower(),
                                       COMPARISON_CRITERIA["mixed"])
    return COMPARISON_PROMPT.format(summaries=summaries, criteria=criteria)
