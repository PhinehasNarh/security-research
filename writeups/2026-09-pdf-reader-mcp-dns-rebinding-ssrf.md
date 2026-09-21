# Two engines, one bug: a DNS-rebinding SSRF hiding behind a correct SSRF check

**Project:** [@sylphx/pdf-reader-mcp](https://github.com/SylphxAI/pdf-reader-mcp) (MCP server that reads PDFs, including from URLs)
**Class:** SSRF (CWE-918) via a DNS resolve-then-connect TOCTOU (CWE-367)
**Severity:** Medium
**Status:** fixed and public. Advisory [GHSA-rgg9-pwc3-jg39](https://github.com/SylphxAI/pdf-reader-mcp/security/advisories/GHSA-rgg9-pwc3-jg39), reported 2026-07 via GitHub PVR, patched in **3.2.0** and published 2026-09-20. My find, credited as reporter.

## TL;DR

I set out to write a "how MCP servers do SSRF *right*" teardown, and pdf-reader-mcp looked like a perfect good example: its Rust engine does DNS-pinned fetching with a rebinding regression test. Then I looked at the *default* engine (the TypeScript one the npm package actually ships) and it doesn't pin. It resolves the hostname to check it isn't internal, and then calls `fetch()`, which resolves the hostname *again* to connect. Two resolutions, and nothing ties them together, so DNS rebinding walks right past the check to `169.254.169.254` and friends. Same project, same threat modeled correctly in one engine and missed in the one that's on by default.

## The setup that looked airtight

pdf-reader-mcp reads PDFs. One of the sources you can hand it is a URL, and fetching a URL server-side is textbook SSRF territory, so they built a guard. On paper it's thorough:

- non-http(s) schemes rejected
- optional host allowlist
- `assertUrlNotPrivate(hostname)` that actually resolves DNS and rejects RFC1918 / loopback / link-local
- manual redirect following that re-validates every hop
- and, in the Rust core, this at the top of the file: *"HTTP(S) PDF body fetch with DNS-pinned SSRF protection per redirect hop"*, plus a `PinnedResolver` and a test that rebinds to `127.0.0.2` to prove it holds.

That last part is the tell that they *get it*. Pinning is the correct fix for rebinding. So I almost moved on.

## The gap: the default engine resolves twice

The npm package's `bin` is `dist/index.js`, the TypeScript server. The pinned Rust engine is opt-in (`PDF_READER_ENGINE_MODE=pure-rust`, described in the repo as "experiments"). So what most people run is the TS path, and the TS path fetches like this (`src/pdf/loader.ts`):

```ts
const validateUrlHop = async (urlString, config) => {
  if (!isUrlAllowed(urlString, config)) throw ...;      // scheme + host allowlist
  if (!config.allowPrivateIps) {
    const hostname = new URL(urlString).hostname;
    await assertUrlNotPrivate(hostname);                 // DNS resolve #1 + private-IP check
  }
};

const fetchUrlBody = async (url, config) => {
  let currentUrl = url;
  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    await validateUrlHop(currentUrl, config);            // resolve #1: validate
    const response = await fetch(currentUrl, {           // resolve #2: connect, unpinned
      redirect: 'manual', signal: controller.signal,
    });
    ...
  }
};
```

`assertUrlNotPrivate` does `dns.promises.lookup(hostname, { all: true })`, checks the addresses, and returns nothing. Then `fetch(currentUrl)` is called with no custom dispatcher, so undici does its *own* DNS lookup to open the connection. The address you validated and the address you connect to are resolved by two separate calls. On an attacker-controlled domain with a zero TTL, those two calls can get two different answers:

- resolve #1 (the check): a public IP you own -> passes `assertUrlNotPrivate`
- resolve #2 (the connect): `169.254.169.254` (cloud metadata), `127.0.0.1`, or any internal host -> the server connects there

Classic DNS rebinding. The check isn't wrong, it's just checking a different lookup than the one that matters.

## Why it bit by default

None of this needed the operator to loosen anything. The defaults were `allowHttp: true` (URL fetching on), `allowedHosts: null` (any host), `allowPrivateIps: false` (guard on). So the private-IP check was the *only* thing standing between an agent and your internal network, and rebinding is exactly the technique that check can't stop without pinning.

Who triggers it? Anyone who can get the server to read a PDF from a URL they chose. In an MCP/agent deployment that's a low bar: an indirect prompt injection that makes the agent call the read tool with `http://rebind.attacker.com/x.pdf`, or an attacker-supplied link that ends up in the agent's context.

It's mostly a *blind* SSRF, since the response has to parse as a PDF for content to come back, but blind SSRF still gets you internal-service reachability, GET-triggered actions, metadata endpoints, and a connect/timeout/parse-error oracle for probing. Plenty.

## A note on finding it twice

Worth recording, because it's the part I nearly got wrong. When I first traced this the package was mid-way through a run of SSRF fixes: one advisory had just closed "no SSRF check at all," another an IPv6-encoding bypass of the private-IP test. It would have been easy to assume the guard was now solid and move on. It wasn't: re-reading the *current* loader showed the validate-then-unpinned-fetch shape was still there, untouched by either of those fixes, because they were fixing the check, not the resolve-twice structure around it. The lesson: when a component is actively being patched for a bug class, re-verify against the head of the line rather than trusting that the latest fix covered your variant.

## The fix

Pin the connection to the address you validated, which is what the Rust engine already did. In Node that means handing `fetch` a custom undici dispatcher whose `connect`/`lookup` returns the exact IP you checked, while keeping the hostname for the `Host` header and TLS SNI, and doing it again on each redirect hop. Or just make the hardened Rust fetch the default instead of gating it behind an env var.

The maintainer resolved it in **3.2.0**: the line moved onto the Rust binary (which pinned throughout), and the residual TypeScript loader got the pin with a regression test (`test/pdf/rebind.test.ts`) verified to fail without it. Affected npm range was `>= 3.1.2, <= 3.1.4`.

## Takeaway

"Validate the host, then fetch" is a TOCTOU any time the fetch re-resolves DNS, which the default HTTP client does. Checking the hostname, or even resolving it and checking the IP, isn't enough, because the connection is a *separate* resolution. The only thing that actually closes it is pinning the connection to the address you validated.

And the meta-lesson I keep running into: when a project has two implementations of the same security-sensitive thing, check both. The team clearly understood rebinding, they wrote a pinned resolver and a test for it, in the engine that isn't the default. The bug wasn't a missing idea. It was a correct idea that didn't make it into the path that ships.
