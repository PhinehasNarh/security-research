# Fetching a URL server-side without the SSRF: the three states, and why you have to pin

**Topic:** SSRF protection for server-side URL fetchers (MCP servers, link previewers, webhook senders, anything that fetches a user-supplied URL)
**Good example:** [linkwarden](https://github.com/linkwarden/linkwarden)'s `safeFetch` (public, and it does this right)
**Type:** analysis / pattern writeup. No bug here - this is the defensive playbook.

## Why now

If your server takes a URL from a user (or from an LLM agent, which is the same thing but worse) and fetches it, you have an SSRF surface. The agent version is worse because an indirect prompt injection can make the agent fetch `http://169.254.169.254/latest/meta-data/...` or your internal admin panel on the attacker's behalf, and the "user" supplying the URL isn't a person you can blame. MCP servers do this constantly - fetch tools, scrapers, PDF/image readers, RSS pollers - so it's worth being precise about what "safe" means.

I've read a bunch of these lately. They fall into three states.

## State 1: protocol-only (the common non-answer)

The most common thing I see is a validator that checks the *scheme* and calls it security:

```ts
const ALLOWED_PROTOCOLS = ["http:", "https:"];
if (!ALLOWED_PROTOCOLS.includes(new URL(url).protocol)) throw new Error("bad protocol");
// ...then fetch(url)
```

Blocking `file:`, `gopher:`, `data:` is good and necessary. But it does nothing about *where* the http request goes. `http://169.254.169.254/`, `http://127.0.0.1:6379/`, `http://192.168.1.1/` are all valid https-or-http URLs. If protocol-checking is the whole guard, the fetcher will happily hit your metadata endpoint and your internal network. This is "we thought about URL safety" without thinking about the destination.

## State 2: validate the host, then fetch (the trap)

The next tier actually resolves the host and checks it's not internal:

```ts
const host = new URL(url).hostname;
await assertNotPrivate(host);   // dns.lookup(host) -> reject if any IP is RFC1918/loopback/link-local
const res = await fetch(url);   // <-- and here's the problem
```

This *looks* right, and it stops the naive cases. But it has a TOCTOU: `assertNotPrivate` resolves the hostname once, and then `fetch(url)` resolves it *again* to open the connection. Two separate DNS lookups. Nothing guarantees they return the same address.

That gap is DNS rebinding. An attacker who controls DNS for `rebind.evil.com` serves it with a zero TTL and alternates answers: the check's lookup gets a public IP (passes), the fetch's lookup gets `127.0.0.1` (connects). Same hostname, two answers, and the one that mattered was never checked. Redirects are the same story - re-validating the redirected URL's *hostname* doesn't help if the subsequent fetch re-resolves it.

This is the subtle one, because the check is genuinely there and genuinely correct. It's checking a different DNS resolution than the one the socket uses.

## State 3: resolve, check, and pin (the answer)

The only thing that actually closes it is making the connection go to the address you validated. Resolve once, check that address, then connect to *that address* while keeping the hostname around only for the `Host` header and TLS SNI.

linkwarden's `safeFetch` is a clean public example. The important move is a custom agent `lookup` that hands the connection the already-validated address instead of letting the HTTP client re-resolve:

```ts
function createSafeLookup() {
  return (hostname, options, callback) => {
    resolveHostnameForServerSideFetch(hostname, defaultHostnameLookup)  // resolve + reject private
      .then((resolved) => {
        const match = resolved.find(e => !family || e.family === family) ?? resolved[0];
        callback(null, match.address, match.family);  // connection uses THIS checked address
      })
      .catch(callback);
  };
}
// ...used as the agent for fetch, so validate-and-connect are the same resolution
```

And it follows redirects manually, re-running the full check on every hop:

```ts
for (let i = 0; i <= maxRedirects; i++) {
  const validatedUrl = await assertUrlIsSafeForServerSideFetch(currentUrl);
  const response = await fetch(validatedUrl, { agent: createAgent(validatedUrl), redirect: "manual" });
  if (!isRedirect(response.status)) return response;
  currentUrl = new URL(response.headers.get("location"), validatedUrl).toString();  // re-validated next loop
}
```

Because the agent's `lookup` is what the socket uses, the address that gets checked *is* the address that gets connected to. Rebinding has nothing to flip. (A Rust equivalent I've seen does the same thing with a "pinned resolver" and even ships a test that rebinds to `127.0.0.2` to prove the connection ignores it.)

## The checklist

If you're fetching user/agent-supplied URLs server-side:

1. **Reject non-http(s) schemes.** Necessary, not sufficient.
2. **Resolve the host and reject private/loopback/link-local/CGNAT/metadata IPs** - IPv4 *and* IPv6, and remember IPv4-mapped IPv6 (`::ffff:169.254.169.254`) and weird encodings.
3. **Pin the connection to the validated address.** This is the step people skip. Custom agent `lookup` (Node) or a pinned resolver (Rust/Go). Without it, steps 1-2 are a TOCTOU.
4. **Handle redirects manually and re-run 1-3 on every hop.** Auto-follow re-resolves and re-opens; don't let it.
5. **Add the belt-and-suspenders:** timeouts, response size caps, an optional host allowlist, and don't reflect the response body/error text back to the caller (SSRF plus verbose errors is how blind turns into not-blind).

## Takeaway

The whole SSRF problem for fetchers compresses to one sentence: **check the address you're going to connect to, not a hostname you'll resolve again later.** Protocol allowlists don't do it. Even resolving-and-checking doesn't do it if the fetch re-resolves. Pin the connection to the address you validated, and the DNS rug can't be pulled. For MCP servers specifically, where an agent's URL is attacker-influenceable by design, this isn't optional hardening, it's the difference between a fetch tool and an internal-network proxy.
