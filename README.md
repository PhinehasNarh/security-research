# Security Research

Hey, I'm ph1n3y ([@PhinehasNarh](https://github.com/PhinehasNarh)). This is the index of my open-source security work: writeups, PRs I've landed or have in flight, bugs I've reported, and targets I've audited.

Most of my time goes into two things: **app security** (broken access control, path traversal, injection, that kind of thing) and **LLM security** (making red-teaming tools actually catch what they're supposed to, judge-prompt injection, etc).

Quick note on ethics: I only test stuff I run myself or have permission to test, and I sit on findings until the vendor ships a fix. So the juicy writeups show up here a bit later than the bug does, on purpose.

---

## Writeups

Some of these are my own finds; others are my take on / collaboration around someone else's discovery (a fresh angle, a deeper root cause, a variant). When the find isn't mine, the original researcher gets credited up top and I'm clear about what I actually contributed.

| Date | What | Class | Origin |
|------|------|-------|--------|
| 2026-07 | [Rating-rail injection in garak's LLM-judge](writeups/2026-07-garak-llm-judge-rating-injection.md) | LLM-as-judge prompt injection | AUTHENSOR reported ([#1868](https://github.com/NVIDIA/garak/issues/1868)); my fix + writeup |
| 2026-07 | [Unicode homoglyph evasion of garak's string detectors](writeups/2026-07-garak-unicode-detector-evasion.md) | Detection evasion | AUTHENSOR reported ([#1867](https://github.com/NVIDIA/garak/issues/1867)); my fix + writeup |
| 2026-07 | [Tar-slip path traversal in MLRun's archive extraction](writeups/2026-07-mlrun-tarslip-path-traversal.md) | Path traversal (CWE-22) | my find + fix |

More land here as the underlying bugs go public.

---

## Merged PRs

| Project | PR | What |
|---------|----|----|
| mlrun/mlrun | [#9919](https://github.com/mlrun/mlrun/pull/9919) | Hardened archive extraction against tar-slip so a malicious source archive can't write outside the clone dir. [Writeup](writeups/2026-07-mlrun-tarslip-path-traversal.md). |
| canonical/cloud-init | [#6916](https://github.com/canonical/cloud-init/pull/6916) | Type annotations for the hosts-file parser. |

## Open PRs

**LLM / AI security**
- **NVIDIA/garak [#1884](https://github.com/NVIDIA/garak/pull/1884)** - Unicode-normalize `StringDetector` inputs so a model can't dodge detection with homoglyphs or weird compatibility forms. (my fix for AUTHENSOR's [#1867](https://github.com/NVIDIA/garak/issues/1867))
- **NVIDIA/garak [#1885](https://github.com/NVIDIA/garak/pull/1885)** - stop a jailbreak target from forging the TAP/PAIR judge's verdict by injecting rating markers into its own output. (my fix for AUTHENSOR's [#1868](https://github.com/NVIDIA/garak/issues/1868))

**DevSecOps / detection**
- **bridgecrewio/checkov [#7595](https://github.com/bridgecrewio/checkov/pull/7595)** - flag AWS Secrets Manager policies that grant access to any principal.
- **gitleaks/gitleaks [#2181](https://github.com/gitleaks/gitleaks/pull/2181)** - secret-scanning rules for Groq and xAI API keys.
- **trufflesecurity/trufflehog [#5129](https://github.com/trufflesecurity/trufflehog/pull/5129)** - a Cerebras API-key detector with live verification.

**Other**
- **svinota/pyroute2 [#1481](https://github.com/svinota/pyroute2/pull/1481)** - fix an `AttributeError` decoding string NLA arrays.

---

## Reported, waiting on a fix

Found these, told the vendor, holding the details until they patch. I'll name names and drop the full writeup once it's public.

| When | Where | What | Severity |
|------|-------|------|----------|
| 2026-07 | self-hosted backup manager | authed operator -> host RCE via argument injection (CWE-78) | Critical (9.9) |
| 2026-07 | self-hosted audiobook server | cross-library broken access control (CWE-285/639) | Medium (5.4) |
| 2026-07 | Puppet dashboard | stored XSS (CWE-79) | Moderate (5.4) |
| 2026-07 | workflow/SOAR platform | tenant-isolation (RLS) off by default, defense-in-depth hardening | Low / hardening |

---

## Audits with no findings

Not every target has a bug, and I think it's worth being honest about that. These I went through properly and came away clean - the authz/SSRF/injection surfaces were solid. Listing them so it's clear the findings above are the ones that actually held up.

- **navidrome/navidrome** - sort/filter/criteria SQL + Jellyfin authz, all allowlisted/scoped.
- **paperless-ngx/paperless-ngx** - object-level authz across the viewsets, consistently enforced.
- **go-vikunja/vikunja** - per-object rights model + webhook SSRF, both solid.
- **docmost/docmost** - public-share access control, restricted pages don't leak.
- **linkwarden/linkwarden** - link/collection authz + a genuinely best-in-class SSRF setup.

---

## Didn't land (for the record)

- **projectdiscovery/nuclei-templates [#16470](https://github.com/projectdiscovery/nuclei-templates/pull/16470)** - CVE detection templates; maintainer wanted debug output proving detection before merge.
- **mitmproxy/mitmproxy [#8291](https://github.com/mitmproxy/mitmproxy/pull/8291)** - a WireGuard port-conflict error message; maintainer wanted it fixed in the Rust layer instead.

---

## How I usually go about it

Map the trust boundary and permission model first, then hammer the spots that matter: authz checks, how commands/args get built, path handling, server-side fetches. Plenty of targets come back clean after a real audit (see above), and that's fine - I only write up the ones that are actually broken.
