# Tar-slip path traversal in MLRun's archive extraction

**Project:** [mlrun/mlrun](https://github.com/mlrun/mlrun) (MLOps orchestration framework)
**Class:** Path traversal / tar-slip (CWE-22)
**Fix:** [PR #9919](https://github.com/mlrun/mlrun/pull/9919), merged 2026-07

## TL;DR

MLRun can pull a project's code from a remote `.tar.gz` or `.zip` and unpack it locally. The extraction didn't check where the archive members were writing to, so a crafted archive with `../` entries could drop files outside the intended directory. I reworked both code paths to validate every member before it's written, added regression tests, and fixed a couple of real review findings along the way. The interesting part was a third review finding that turned out to be wrong, and being able to show that with a two-line experiment instead of just arguing about it.

## The setup

MLRun lets you point a project at a source archive and it'll clone it for you. Two functions do the unpacking, `clone_tgz` and `clone_zip`, and they both followed the same shape: download the archive to a temp file, then extract the whole thing into a target dir.

The original tar path was basically:

```python
with tarfile.open(tmpfile, "r:*") as tf:
    tf.extractall(target_dir)
```

`tarfile.extractall()` will happily honor whatever paths are inside the archive. If a member's name is `../../../../etc/cron.d/x` or an absolute path, it writes there. That's tar-slip: you control a file inside the archive, you get to write outside the extraction dir. On a system that later executes what it wrote, that's a straight line to code execution.

Since MLRun pulls these archives from a source you might not fully trust (a URL, a shared artifact store), that's a real trust boundary being crossed.

## The fix

I routed both functions through shared safe-extract helpers instead of calling `extractall` blind.

For tar, the modern answer is the [PEP 706](https://peps.python.org/pep-0706/) `data` filter, which rejects members that escape the target, plus a pre-flight check on every member so nothing sneaks through on older behavior:

```python
def _safe_extract_tar(tf, target_dir):
    for member in tf.getmembers():
        target = os.path.join(target_dir, member.name)
        if not _is_path_under(target, target_dir):
            raise mlrun.errors.MLRunInvalidArgumentError(
                f"archive member escapes target dir: {member.name}"
            )
    tf.extractall(target_dir, filter="data")
```

`_is_path_under` resolves both sides with `os.path.realpath` before comparing, so `..` and symlink tricks both collapse to a real path first.

Then the callers got a `try/finally` so the downloaded archive gets cleaned up even if extraction blows up:

```python
def clone_tgz(source, target_dir, secrets=None, clone=True):
    tmpfile = _prep_dir(source, target_dir, ".tar.gz", secrets, clone)
    try:
        with tarfile.TarFile.open(tmpfile, "r:*") as tf:
            _safe_extract_tar(tf, target_dir)
    finally:
        remove(tmpfile)
```

Plus regression tests that build a malicious archive with a `../` member, run it through the real function, and assert the traversal file never lands and the archive gets cleaned up.

## The part I actually want to talk about

The maintainer's review came back with three findings. Two were legit and I took them:

1. clean up the temp archive on failure (the `try/finally` above)
2. tighten the member check

The third one said `clone_zip` had the "identical zip-slip" bug and needed the same member-validation treatment as the tar path.

That sounds right on the surface, zip archives can absolutely carry `../` entries, and it would've been easy to just say "yep" and bolt on the same code. But I wanted to actually check, because if it's not true you're adding dead validation and implying the old code was vulnerable when it wasn't.

Turns out CPython's `zipfile` already sanitizes this. `ZipFile.extractall()` runs every member name through `_extract_member`, which strips drive letters, leading slashes, and `..` components before joining to the target. So the two classic payloads just... don't escape:

```python
import zipfile, io, os, tempfile

buf = io.BytesIO()
with zipfile.ZipFile(buf, "w") as z:
    z.writestr("../evil.txt", "nope")
    z.writestr("/abs.txt", "nope")

d = tempfile.mkdtemp()
with zipfile.ZipFile(buf) as z:
    z.extractall(d)

print(sorted(os.listdir(d)))            # ['abs.txt', 'evil.txt']
print(os.path.exists(os.path.join(d, "..", "evil.txt")))  # False
```

Both files land *inside* the target dir. The `../` and the leading `/` get flattened, not honored. So `clone_zip` wasn't vulnerable the way tar was, `tarfile` is the odd one out here because its `extractall` predates the safe-by-default behavior.

I still routed `clone_zip` through a `_safe_extract_zip` helper for consistency and defense-in-depth (belt and suspenders, and it documents the intent), but I said clearly in the review that the "identical zip-slip" framing wasn't accurate and showed the experiment. Maintainer agreed, and it merged.

## Takeaways

- **tar and zip are not the same threat.** Python's `tarfile.extractall` will write wherever the archive tells it (pre-3.14); `zipfile.extractall` sanitizes member paths for you. If you're reasoning about archive extraction, know which library you're actually calling.
- **`filter="data"` is the right default for tar** on 3.12+. Add a member pre-flight if you want to be explicit or support older runtimes.
- **Check the claim, don't just take the change.** A reviewer being senior doesn't make every finding correct. A two-line repro beats a paragraph of arguing, and it keeps you from shipping code that quietly implies a bug that was never there.

Fix is live in [mlrun#9919](https://github.com/mlrun/mlrun/pull/9919).
