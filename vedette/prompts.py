"""Research prompts for the Vedette's OSINT collection profiles, plus triage/synthesis.

Two brief styles:
- "security" profile: the enterprise security/privacy comparison playbook
  (jurisdiction, contractual protections, compliance assurance, incident
  history, posture signals).
- OSINT profiles (corporate, financial, reputation, technology) and the
  person target type: classic intelligence-collection requirements with
  analytic confidence and collection gaps in the brief.

Every research prompt demands source URLs with publication dates and
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

# Research system prompt for the OSINT collection profiles (corporate,
# financial, reputation, technology) and the person target type: same source
# discipline as SYSTEM_RESEARCH, without the security-buyer framing.
SYSTEM_RESEARCH_OSINT = (
    "You are an OSINT researcher producing an intelligence collection brief "
    "on the target below. "
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
    "6. Stay in scope: this is an OSINT intelligence collection task. Do not "
    "answer questions unrelated to the target's public footprint (recipes, "
    "entertainment, trivia, etc.); note the request is out of scope instead.\n"
    "7. For people: report only what the person has made public or what is "
    "credibly reported by reputable sources. Do not publish private personal "
    "data (home addresses, family members' private identities, contact "
    "details, or non-public identifiers)."
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

PERSON_IDENTITY_PROMPT = """Resolve the identity of the person below from public information.

Person name: {org}
URL (may be empty): {url}

Reply with a single JSON object and nothing else, with these keys:
- "name": canonical full name
- "aliases": other names, handles, or aliases, or "NOT FOUND"
- "role": current role and organization, or "NOT FOUND"
- "location": city/country, or "NOT FOUND"
- "handles": known social-media handles/usernames (without the @), or "NOT FOUND"
- "description": one-line description of who this person is publicly
- "notes": any identity ambiguities (common names, impersonators, name changes)

If you cannot confidently identify the person, set "name" to the input
and "notes" to "IDENTITY UNRESOLVED".
"""

EMAIL_IDENTITY_PROMPT = """Resolve the identity of the email address below from public information.

Email address: {org}
URL (may be empty): {url}

Reply with a single JSON object and nothing else, with these keys:
- "email": canonical email address
- "local": local part (before the @)
- "domain": domain part (after the @)
- "domain_owner": organization operating the domain, or "NOT FOUND"
- "description": one-line description of what this address appears to be (personal mailbox, role-based address, disposable, etc.)
- "notes": any identity ambiguities

If the input is not a valid email address, set "email" to the input
and "notes" to "IDENTITY UNRESOLVED".
"""

TARGET_TYPES = ("company", "software", "domain", "person", "email")

IDENTITY_PROMPTS = {
    "company": IDENTITY_PROMPT,
    "software": SOFTWARE_IDENTITY_PROMPT,
    "domain": DOMAIN_IDENTITY_PROMPT,
    "person": PERSON_IDENTITY_PROMPT,
    "email": EMAIL_IDENTITY_PROMPT,
}

AXES = ("jurisdiction", "contractual", "compliance", "incidents", "posture")

AXES_BY_TYPE = {
    "company": AXES,
    "software": ("supply_chain", "vulnerabilities", "maintenance",
                 "data_handling", "assurance"),
    "domain": ("registration", "hosting", "tls", "phishing", "infra"),
    "person": ("p_background", "p_career", "p_affiliations", "p_presence",
               "p_controversies", "p_social"),
    "email": ("e_format", "e_deliverability", "e_breaches", "e_associations"),
}

# Collection profiles: named OSINT playbooks selectable via --profile.
# "security" is the default and preserves the historic per-type axes.
# The OSINT profiles override the company axes; software, domain, and person
# targets keep their type axes under every profile. "full" runs the security
# axes plus every OSINT profile's company axes.
PROFILES = ("security", "corporate", "financial", "reputation", "technology",
            "full")

PROFILE_AXES = {
    "corporate": {
        "company": ("ownership", "leadership", "financials", "footprint",
                    "partnerships"),
    },
    "financial": {
        "company": ("funding", "investors", "revenue", "manda", "valuation"),
    },
    "reputation": {
        "company": ("coverage", "controversies", "regulatory", "sentiment"),
    },
    "technology": {
        "company": ("techstack", "engineering", "patents", "opensource"),
    },
}

# Profiles whose briefs use the intelligence style (key judgments with
# analytic confidence + collection gaps) instead of the buyer brief.
INTEL_PROFILES = ("corporate", "financial", "reputation", "technology",
                  "full")

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
    # corporate profile axes (company)
    "ownership": "Ownership & corporate structure",
    "leadership": "Leadership & key people",
    "financials": "Financials & scale",
    "footprint": "Geographic & physical footprint",
    "partnerships": "Partnerships, customers & ecosystem",
    # financial profile axes (company)
    "funding": "Funding history",
    "investors": "Investors & backers",
    "revenue": "Revenue signals",
    "manda": "M&A activity",
    "valuation": "Valuation",
    # reputation profile axes (company)
    "coverage": "Media coverage",
    "controversies": "Controversies & lawsuits",
    "regulatory": "Regulatory actions",
    "sentiment": "Public & employee sentiment",
    # technology profile axes (company)
    "techstack": "Technology stack signals",
    "engineering": "Engineering organization signals",
    "patents": "Patents & R&D",
    "opensource": "Open-source presence",
    # person axes
    "p_background": "Background & biography",
    "p_career": "Career history",
    "p_affiliations": "Affiliations & network",
    "p_presence": "Public presence",
    "p_controversies": "Controversies & legal issues",
    "p_social": "Social media profiles",
    # email axes
    "e_format": "Address format & pattern analysis",
    "e_deliverability": "Domain & deliverability signals",
    "e_breaches": "Breach exposure",
    "e_associations": "Associated accounts & profiles",
}


def check_profile(profile):
    """Validate a collection profile name; returns the normalized profile."""
    profile = (profile or "security").lower()
    if profile not in PROFILES:
        raise ValueError(
            "Unknown collection profile %r (expected one of: %s)."
            % (profile, ", ".join(PROFILES)))
    return profile


def axes_for_type(target_type, profile="security"):
    """Return the research axes for a target type under a collection profile.

    The "security" profile preserves the historic per-type axes. The OSINT
    profiles override the company axes; software, domain, and person keep
    their type axes under every profile. "full" runs the security axes plus
    every OSINT profile's company axes for company targets.
    """
    target_type = (target_type or "company").lower()
    if target_type not in AXES_BY_TYPE:
        raise ValueError(
            "Unknown target type %r (expected one of: %s)."
            % (target_type, ", ".join(TARGET_TYPES)))
    profile = check_profile(profile)
    if target_type != "company" or profile == "security":
        return AXES_BY_TYPE[target_type]
    if profile == "full":
        axes = list(AXES_BY_TYPE["company"])
        for prof in ("corporate", "financial", "reputation", "technology"):
            axes.extend(PROFILE_AXES[prof]["company"])
        return tuple(axes)
    return PROFILE_AXES[profile]["company"]


def is_intel_brief(profile, target_type="company"):
    """True when the brief should use the intelligence style.

    OSINT profiles always do; the person and email target types do under any
    profile.
    """
    return (check_profile(profile) in INTEL_PROFILES
            or (target_type or "company").lower() in ("person", "email"))

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
    # ---- corporate profile axes (company) ----
    "ownership": """Research the company's ownership and corporate structure.

Organization identity:
{identity}

Answer:
1. Legal entity name(s), incorporation country/state, and company registration number where public.
2. Parent company, ultimate beneficial owner(s), and major shareholders where disclosed.
3. Subsidiaries, divisions, and sister companies -- what does the corporate family look like?
4. Any recent restructurings, spinoffs, or holding-company changes, with dates.
5. If ownership is opaque (shell structures, undisclosed owners), say so explicitly rather than guessing.
""",
    "leadership": """Research the company's leadership and key people.

Organization identity:
{identity}

Answer:
1. CEO/founder(s) and the current executive team (names + titles).
2. Board of directors or equivalent governing body, where disclosed.
3. Brief backgrounds of the top 2-3 leaders: prior companies, notable history.
4. Any recent leadership changes (departures, appointments) with dates.
5. Write NOT FOUND for anything not publicly attributable to a named individual.
""",
    "financials": """Research the company's financials and scale.

Organization identity:
{identity}

Answer:
1. Revenue: latest reported or credibly estimated annual revenue, with the source and date of the estimate. Distinguish reported figures from analyst estimates.
2. Profitability status (profitable, loss-making, unknown) with the basis for the claim.
3. Headcount: latest employee count and source/date; note growth or layoffs if reported.
4. For private companies, note explicitly where figures are estimates rather than filings.
""",
    "footprint": """Research the company's geographic and physical footprint.

Organization identity:
{identity}

Answer:
1. Headquarters location (city, country) and any secondary HQs.
2. Office locations by country/city as stated by the company or reported.
3. Data center or infrastructure regions, if the company operates its own.
4. Manufacturing, logistics, or other physical operations where relevant.
5. Note the as-of date for location claims; companies move.
""",
    "partnerships": """Research the company's partnerships, customers, and ecosystem.

Organization identity:
{identity}

Answer:
1. Named enterprise customers or flagship clients (only those the company itself publicizes or that are credibly reported -- do not infer customers).
2. Strategic partnerships, alliances, and channel partners.
3. Key vendors or technology providers the company depends on, where public.
4. Industry memberships, consortiums, or standards bodies it participates in.
5. Distinguish announced partnerships from rumored ones.
""",
    # ---- financial profile axes (company) ----
    "funding": """Research the company's funding history.

Organization identity:
{identity}

Answer:
1. Funding rounds: for each known round, the date, amount, round type (seed, Series A, etc.), and source of the information.
2. Total capital raised to date, with the as-of date.
3. For bootstrapped or self-funded companies, state that explicitly if credible sources support it; otherwise NOT FOUND.
4. Any failed raises, down rounds, or bridge financing reported publicly.
""",
    "investors": """Research the company's investors and backers.

Organization identity:
{identity}

Answer:
1. Lead investor(s) per round where disclosed.
2. Notable institutional investors (VC firms, corporate venture arms, sovereign funds).
3. Notable angel investors or strategic backers, where public.
4. Any investor controversies or investor-driven governance changes (board seats tied to rounds).
""",
    "revenue": """Research the company's revenue signals.

Organization identity:
{identity}

Answer:
1. Reported revenue figures with period, source, and date. Prefer filings and audited statements.
2. Credible third-party revenue estimates (analyst, data provider) -- label them as estimates and name the estimator.
3. Revenue growth trajectory: what do the last 2-3 data points show?
4. Revenue mix if disclosed (product lines, geographies, segments).
5. If nothing credible exists, write NOT FOUND and describe what you searched.
""",
    "manda": """Research the company's M&A activity.

Organization identity:
{identity}

Answer:
1. Acquisitions made by the company: target, date, and price/terms where disclosed.
2. Times the company itself was acquired, merged, or taken private, with dates and acquirers.
3. Credible acquisition rumors or reported sale processes -- label rumors as rumors with the reporting outlet and date.
4. Divestitures or asset sales, with dates.
""",
    "valuation": """Research the company's valuation.

Organization identity:
{identity}

Answer:
1. Latest known valuation figure, the date it was set, and what event set it (funding round, secondary sale, analyst estimate).
2. Valuation history: how it has moved across rounds, if public.
3. For public companies, market capitalization as of a stated date instead.
4. Distinguish 409A/fair-market-value figures from priced-round valuations where the source makes that clear.
""",
    # ---- reputation profile axes (company) ----
    "coverage": """Research recent media coverage of the company.

Organization identity:
{identity}

Answer:
1. The 5-10 most significant news stories about the company in the last 24 months: headline, outlet, date, one-line summary.
2. Overall tone of coverage (positive, negative, mixed) with examples.
3. Which outlets cover it most (tech press, national media, trade press)?
4. Exclude press releases republished verbatim; prefer independent reporting.
""",
    "controversies": """Research controversies and lawsuits involving the company.

Organization identity:
{identity}

Answer:
1. Lawsuits: parties, filing date, court/jurisdiction, status or outcome. Distinguish filed cases from decided ones.
2. Public controversies: scandals, executive misconduct allegations, product-harm claims -- with dates and the company's response where reported.
3. Labor disputes, whistleblower claims, or regulatory complaints that became public.
4. Verify attribution: exclude cases involving similarly named companies and say so.
""",
    "regulatory": """Research regulatory actions involving the company.

Organization identity:
{identity}

Answer:
1. Fines, sanctions, consent orders, or enforcement actions by regulators: authority, date, amount/remedy, and status.
2. Ongoing investigations disclosed by the company or reported credibly.
3. Licenses revoked, suspended, or conditioned by regulators.
4. If nothing is found, write NOT FOUND and describe what you searched -- do not present a clean record as proof of compliance.
""",
    "sentiment": """Research public and employee sentiment toward the company.

Organization identity:
{identity}

Answer:
1. Employee review aggregates (e.g. Glassdoor-style ratings): overall score, as-of date, and recurring themes in reviews. Treat anonymous reviews as low-confidence signals.
2. Customer sentiment signals: review platforms, social media tone, notable praise or complaint patterns.
3. Any viral negative or positive moments with dates.
4. Keep this clearly labeled as sentiment (opinion), not fact.
""",
    # ---- technology profile axes (company) ----
    "techstack": """Research the company's public technology stack signals.

Organization identity:
{identity}

Answer:
1. Languages, frameworks, and platforms evidenced by job postings, engineering blogs, or public documentation.
2. Cloud/infrastructure providers evidenced publicly (not guessed from IP ownership alone).
3. Notable build vs. buy signals: in-house platforms the company has written about.
4. Mark every claim with how it was evidenced (job post, blog, docs); do not assert a stack from a single weak signal.
""",
    "engineering": """Research the company's engineering organization signals.

Organization identity:
{identity}

Answer:
1. Engineering headcount or team size signals (job posting volume, stated team sizes).
2. Engineering blog or public tech talks: what do they reveal about practices and scale?
3. Hiring signals: which roles are being hired aggressively, and what does that imply about direction?
4. Open engineering roles by location as a footprint signal.
""",
    "patents": """Research the company's patents and R&D signals.

Organization identity:
{identity}

Answer:
1. Patents filed or granted: counts, notable filings, and the patent offices involved, with sources (e.g. USPTO, EPO, Google Patents).
2. R&D spending if disclosed in filings.
3. Research publications or academic collaborations.
4. Do not treat patent counts as a quality signal without basis; report the numbers and let them speak.
""",
    "opensource": """Research the company's open-source presence.

Organization identity:
{identity}

Answer:
1. Official GitHub/GitLab organization(s) and the most notable repositories.
2. Significant open-source projects maintained or heavily contributed to by the company.
3. Contribution patterns: sustained maintenance vs. one-off code drops.
4. Any license controversies around its open-source projects (relicensing, CLA disputes).
""",
    # ---- person axes ----
    "p_background": """Research the person's background and biography.

Person identity:
{identity}

Answer:
1. Biographical basics: age/date of birth only if widely and credibly reported; nationality; education history (institutions, degrees, dates).
2. Early career and path to their current prominence.
3. Family or personal details ONLY where the person has made them public themselves; otherwise write NOT FOUND and move on. Do not publish private personal data (home addresses, family members' identities, contact details).
4. Distinguish well-sourced biography from thin or single-source claims.
""",
    "p_career": """Research the person's career history.

Person identity:
{identity}

Answer:
1. Career timeline: roles, organizations, and dates in chronological order.
2. Notable achievements, exits, or milestones per role, with sources.
3. Current role and responsibilities.
4. Gaps or ambiguous periods: note them rather than filling them in.
""",
    "p_affiliations": """Research the person's affiliations and network.

Person identity:
{identity}

Answer:
1. Board seats, advisory roles, and formal affiliations (current and past), with dates.
2. Organizations founded or co-founded.
3. Professional memberships, fellowships, or honors that are publicly documented.
4. Close professional associates only where the association is public and relevant (co-founders, long-term collaborators) -- not a social graph of private contacts.
""",
    "p_presence": """Research the person's public presence.

Person identity:
{identity}

Answer:
1. Public profiles: official website, verified social accounts, professional profiles -- with follower/subscriber counts as of a stated date where visible.
2. Talks, interviews, podcasts, and publications: the most notable ones with dates.
3. Books, newsletters, or regular columns authored.
4. Note impersonator or parody accounts if they are prominent enough to cause confusion.
""",
    "p_controversies": """Research controversies and legal issues involving the person.

Person identity:
{identity}

Answer:
1. Lawsuits, charges, or legal proceedings: what, when, jurisdiction, status/outcome. Distinguish allegations from findings.
2. Public controversies: scandals, misconduct allegations, public feuds -- with dates and the person's response where reported.
3. Verify attribution carefully: common names collide; exclude items that belong to a different person with the same name and say so.
4. If nothing is found, write NOT FOUND and describe what you searched.
""",
    "p_social": """Research the person's social media profiles and online handles.

Person identity:
{identity}

A keyless handle-enumeration tool has probed candidate handles across
platforms; its hits are included as tool context where available. Use them
as leads, not proof.

Answer:
1. Confirmed social profiles: for each, the platform, profile URL, and why you believe it belongs to this person (bio details, photos, cross-links, follower overlap). Distinguish confirmed from likely.
2. Professional profiles (LinkedIn, GitHub, etc.): current role as stated, and whether it matches the known career history.
3. Notable content: what the person posts about, posting frequency, audience size as of a stated date.
4. Impersonator, fan, or parody accounts that could cause confusion.
5. Platforms where the person appears absent: note explicitly rather than inventing profiles.
""",
    # ---- email axes ----
    "e_format": """Analyze the email address format and pattern.

Email identity:
{identity}

Answer:
1. Parse the address: local part, domain, any sub-addressing (plus-tags) or dot tricks.
2. Address type: personal mailbox, role-based (info@, support@), automated/noreply, or disposable -- with the reasoning.
3. Pattern analysis: does the local part look like firstname.lastname, initials, a handle, or random? If the domain belongs to an organization, what email pattern does that organization publicly use, and does this address match it?
4. Provider signal: major mailbox provider (Gmail, Outlook, etc.) vs. custom domain -- what does each imply about attribution?
""",
    "e_deliverability": """Research the email domain's deliverability signals.

Email identity:
{identity}

Keyless DNS checks (MX records) are included as tool context where available.

Answer:
1. Does the domain have MX records (can it receive mail)? Which mail provider handles it (Google Workspace, Microsoft 365, etc.)?
2. Domain registration: registrar, creation date, age. Very young domains are a risk signal.
3. Email authentication: are SPF, DKIM, DMARC records published for the domain? Quote what you find.
4. Is the domain a known disposable/throwaway-mail provider?
5. Net assessment: one paragraph on whether this address looks deliverable and legitimate.
""",
    "e_breaches": """Research the email address's breach exposure.

Email identity:
{identity}

A HaveIBeenPwned lookup is included as tool context when the HIBP_API_KEY
is configured. If it was skipped (no key), treat breach exposure as NOT
FOUND unless other sources show it -- do not guess.

Answer:
1. Breaches the address appears in: breach name, breach date, and what data classes were exposed, per breach.
2. For the most significant breach, one line on what happened (per the breach's public writeup).
3. Credential-exposure implication: does the exposure include passwords (even hashed)? State what this means for credential-reuse risk without prescribing attacks.
4. If no breach data is available, write NOT FOUND and describe what you searched.
""",
    "e_associations": """Research accounts and profiles associated with the email address.

Email identity:
{identity}

Keyless checks (Gravatar, handle enumeration on the local part) are included
as tool context where available. Use them as leads, not proof.

Answer:
1. Gravatar: does the address have one? What does the avatar/profile reveal?
2. Social and platform accounts plausibly tied to the address or its local part as a handle: platform, URL, confidence, and why you believe the association holds.
3. Appearances of the address in public sources: forum posts, code commits, WHOIS records, leaks, paste sites -- with URLs and dates. Quote minimally; do not republish private data beyond the address itself.
4. For each association, distinguish confirmed (cross-corroborated) from speculative.
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

INTEL_SYNTHESIS_PROMPT = """Synthesize the OSINT collection below into an intelligence brief.

Target identity:
{identity}

Collection by requirement:
{axes_text}

Write a brief with these sections:
## Key Judgments
The 3-5 most important judgments, each tagged with analytic confidence
[High/Medium/Low] and a one-line reason for the confidence call. Confidence
reflects source quality and corroboration, not how strongly you feel.
## Findings by collection requirement
One short paragraph per requirement, sticking to what the collection
verified. Cite the research you were given.
## Collection gaps
What came back NOT FOUND or thin: list each gap and what collection would
close it (e.g. corporate registry lookup, filing review, direct source).
## Outlook
What to watch or collect next, in priority order.
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
    "person": "(a) career trajectory & current standing, (b) affiliations & network strength, (c) public presence & reputation, (d) controversies & legal exposure",
    "email": "(a) address legitimacy & deliverability, (b) breach exposure, (c) associated accounts, (d) domain reputation",
    "mixed": "the dimensions relevant to each target's type (jurisdiction, contracts, assurance, incidents for companies; supply chain, CVEs, maintenance for software; registration, hosting, TLS for domains; career, affiliations, reputation for people; deliverability, breaches, associations for emails)",
}


def build_identity_prompt(org, url, target_type="company"):
    template = IDENTITY_PROMPTS.get((target_type or "company").lower(),
                                    IDENTITY_PROMPT)
    return template.format(org=org or "NOT GIVEN", url=url or "NOT GIVEN")


def build_axis_prompt(axis, identity):
    if axis not in AXIS_PROMPTS:
        raise ValueError("Unknown research axis: %r" % axis)
    return AXIS_PROMPTS[axis].format(identity=identity)


def build_synthesis_prompt(identity, axis_texts, axes=None, intel_style=False):
    axes = axes or AXES
    axes_text = "\n\n".join(
        "### %s\n%s" % (AXIS_TITLES[a], axis_texts.get(a, "NOT FOUND"))
        for a in axes
    )
    template = INTEL_SYNTHESIS_PROMPT if intel_style else SYNTHESIS_PROMPT
    return template.format(identity=identity, axes_text=axes_text)


def build_comparison_prompt(summaries, target_type="company"):
    criteria = COMPARISON_CRITERIA.get((target_type or "company").lower(),
                                       COMPARISON_CRITERIA["mixed"])
    return COMPARISON_PROMPT.format(summaries=summaries, criteria=criteria)
