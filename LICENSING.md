# Grob Licensing

Grob Core is dual-licensed:

1. **GNU Affero General Public License v3.0 (AGPL-3.0)**
2. A **commercial license** from A00 SASU

The AGPL-3.0 applies by default to the public source code. A commercial license
is an alternative for organizations that do not want AGPL-3.0 obligations, need
to keep modifications private, embed Grob in a proprietary product, require
support / SLA / procurement terms, or need the Enterprise / Admin editions.

> The AGPL-3.0 edition is fully functional and suitable for self-managed use.
> **It is not limited by company size or user count** — open source rights cannot
> be restricted that way. User counts and deployment scope only size the
> commercial tiers below.

## Open Source License: AGPL-3.0

You may use, study, modify, and distribute Grob Core under AGPL-3.0, **at any
scale**.

- If you modify Grob and let users interact with the modified version over a
  network, AGPL-3.0 **§13** requires you to offer those users the *Corresponding
  Source* of your modified version.
- Derivative works are licensed under AGPL-3.0.
- See the [LICENSE](LICENSE) file for the full legal text.

## Commercial Licensing

A commercial license grants the right to use Grob outside AGPL-3.0 terms, under a
separate agreement. Depending on the tier, you are buying: the AGPL waiver, the
right to keep modifications private, redistribution / OEM rights, support & SLA,
procurement-friendly terms (warranty / indemnity / SBOM / provenance), the
Enterprise modules, the Admin console, and managed hosting.

Recommended when you need: proprietary deployment, private modifications,
regulated environments, managed services, redistribution, OEM embedding,
enterprise support, enterprise modules, air-gapped deployment, or non-AGPL
procurement terms.

## Editions

| Edition | License | Includes |
|---------|---------|----------|
| **Grob Core** | AGPL-3.0 *or* commercial | LLM gateway & routing, OpenAI-compatible API, providers, DLP, signed audit log, policy engine, HIT approval (single-level), basic RBAC, compliance foundations (EU AI Act audit, GDPR/region flags, risk classification), CLI, OIDC, JSONL audit export, Helm chart |
| **Grob Commercial** | Commercial | Grob Core under commercial terms — AGPL waiver, private modifications, support |
| **Grob Enterprise** | Commercial | Enterprise modules: HA / clustering / active-active, multi-region, advanced SIEM connectors (Splunk/Sentinel/Elastic/QRadar), turnkey compliance packs (NIS2/DORA/ISO 27001/AI Act), advanced RBAC, multi-level approval, air-gap bundle, long-term retention |
| **Grob Admin** | Commercial | Web console: policy builder, audit explorer, compliance dashboard, fleet & tenant management, GitOps manifest generation, license management, multi-instance health |
| **Grob Cloud** | Commercial SaaS | Dedicated hosted instance-per-tenant, Admin included, managed operations |

The Core / Enterprise / Admin boundary follows
[ADR-0028](docs/decisions/0028-open-core-boundary.md): security **primitives and
foundations** are open (AGPL); **packaged products, advanced tiers, and the web
console** are commercial.

## Pricing (indicative)

| Plan | Use case | Starting price |
|------|----------|---------------:|
| **Developer** | Local workstation, evaluation, development | Free |
| **Community** | AGPL-3.0 self-managed use, any size | Free |
| **Pro** | Small production deployment under commercial terms | 5 000 EUR/year |
| **Business** | Production deployment with support | 12 000 EUR/year |
| **Enterprise** | Regulated or larger deployments + Enterprise modules | from 25 000 EUR/year |
| **Regulated / Defense** | Source review under NDA, air-gap, security package | from 40 000 EUR/year |
| **Integrator** | Deploy Grob for end clients (ESN / MSSP) | from 20 000 EUR/year + per-client terms |
| **OEM** | Embed Grob in a third-party product | from 50 000 EUR/year |
| **Grob Cloud** | Dedicated hosted tenant | from 1 000 EUR/month |

Prices are indicative and may vary with deployment size, support level,
regulatory requirements, and redistribution rights. Quoted prices are locked for
12 months from contract signature.

## Personal / local use

For a single user on their own workstation (localhost), Grob is **free** under
either:

- the **AGPL-3.0**, or
- a **free commercial grant for localhost-only use** (no AGPL obligations).

No license key, no sign-up.

## Contributor License Agreement

Contributions are accepted under the [Grob CLA](CLA.md). The CLA lets A00 SASU
distribute contributed code under **both** the AGPL-3.0 and the commercial
license; contributors retain copyright in their contributions. It is enforced by
the `cla-check` job in CI, and is what makes dual-licensing possible.

## FAQ

### Can I use Grob internally under AGPL-3.0?
Yes, at any scale. Running unmodified Grob internally under AGPL-3.0 is fine. If
you **modify** Grob and let users interact with the modified version **over a
network**, §13 requires you to offer those users the *Corresponding Source* of
your modified version. Organizations that do not want to manage AGPL obligations
can buy a commercial license.

### Do I have to publish my private internal modifications to the world?
No. AGPL-3.0 requires offering source to users who **interact with the modified
software over a network** — it does not, by itself, turn every private
modification into a public release. For confidential, regulated, or proprietary
deployments, a commercial license removes the obligation entirely.

### Is the free edition limited by company size or user count?
No. The AGPL-3.0 edition has **no** user-count or company-size limit — open
source rights cannot be restricted that way. User counts only size the
**commercial** tiers.

### Do I need a commercial license to use Grob with Claude Code locally?
No. Local single-user use on your own workstation is free (AGPL-3.0, or the free
local commercial grant). No license key, no sign-up.

### I'm a developer — can I use Grob for free?
Yes. On your own machine (localhost) it is free, even for commercial work, under
the AGPL-3.0 or the free local commercial grant.

### We are a defense contractor and need to audit the code.
The **Regulated / Defense** tier provides source review under NDA, an air-gap
bundle, and a security package (SBOM / signatures / offline updates), without
AGPL redistribution obligations. Contact licensing@a00.fr.

## Contact

For commercial licensing: **licensing@a00.fr**
