# Administration interface review

## Public observation
The runner classifies explicit administration-link advertisements in the already downloaded homepage HTML, including accessible labels and links explicitly pointing to a descendant hostname. It never attempts the link. A warning is a Low configuration observation only; it does not establish reachability. NOT FOUND is not a security pass. DNS discovery and destination verification remain NOT TESTED.

## Owner inventory review
Ask the operator for their approved hostname inventory, intended public and private administration interfaces, and exported configuration from their own DNS, routing, identity provider, or CMS. Review owner-provided records for intended internet exposure, enforced HTTPS, MFA, network restrictions, authentication and authorization. Do not infer reachability from names, sitemap or robots directives, or raw JavaScript strings alone. Do not publish URLs, credentials or tokens.

### Local review command (implemented)

Copy `templates/admin-inventory.example.json` privately. Assign each interface an opaque alias and fill in the exposure and five control fields. Exposure accepts internet/restricted/unknown; controls accept yes/no/unknown. Use configuration records already held by the owner. No credentials, actual URL, DNS record or token belongs in this input. Do not publish owner inventories or review results.

Run locally:
```bash
python3 -m auditor review-admin-inventory --input owner-inventory.json --out private-inventory-review.json
```

The report separates reported exposure (Low), reported gaps, owner-reported configured controls and unknowns. Severity is a remediation priority, not verified exploitability. All results are owner-reported; live verification remains NOT TESTED and network_requests is zero.

Additional hostnames remain independently scoped. For any authorized audit, use a separate exact-host permission file and fresh challenge for each hostname; a parent domain's consent is not inherited. Do not broaden the authorization schema or use guessed hostnames. The existing runner remains one exact hostname per run.

Robots/sitemap, script bundles and additional pages are not automatically fetched or mined for hidden administration destinations. No active discovery or authentication attempts are included in this revision.

## Top 10 priority subset

Public mode counts up to ten distinct explicitly advertised descendant hostnames, with an overflow indicator; no names are returned and no destination is contacted. Offline inventory permits optional owner-declared `publicly_advertised` and `name_prevalence`. Eligible records are advertised or have medium/high declared prevalence. Advertised records rank first, then declared prevalence, then alias. Limit the priority subset to ten while retaining all records for control review. Prevalence is not independently measured. Unknown data cannot establish popularity.

## Offline browser observation

The optional `review-admin-snapshot` command renders an operator-supplied local HTML snapshot with Playwright Chromium, offline, JavaScript disabled, service workers blocked, and network routes aborted. It observes page title, visible headings, form and password-input visibility only. It never navigates to a target URL. A Low candidate label requires explicit administration evidence and visible login controls; error, ordinary customer login and ambiguous cases are distinct. Live reachability and authentication are NOT TESTED. Do not publish input snapshots or reports.
