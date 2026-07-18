# "Read-only" SQL is harder than it looks: how an MCP database server actually keeps an agent from writing

**Topic:** read-only enforcement in MCP database servers (LLM agents running SQL)
**Case study:** [bytebase/dbhub](https://github.com/bytebase/dbhub), a universal database MCP server
**Type:** analysis / threat-model teardown. dbhub's code here is the *good* example - I'm using it to walk the bypass classes, not reporting a bug. Credit to the bytebase folks for a genuinely careful implementation.

## Why I'm writing this

MCP database servers are having a moment. You point an LLM agent at your Postgres/MySQL/SQLite through an MCP server and it can query your data in plain English. Most of them ship a **read-only mode**, because letting a model that's one prompt-injection away from doing whatever an attacker wants run `DELETE FROM users` is a bad time. Between January and April 2026 the MCP ecosystem racked up 40+ CVEs, so "the guardrail actually holds" is not a given.

Here's the uncomfortable part: **enforcing "this SQL is read-only" is deceptively hard.** I went through dbhub's implementation expecting to find a bypass, and instead found a nice worked example of doing it right. So this is a teardown of every way a naive read-only check gets popped, and what a real one looks like.

## The naive version (and why it dies)

Almost everyone starts here:

```js
if (!sql.trim().toLowerCase().startsWith("select")) throw new Error("read-only!");
```

This falls over immediately. Walk the bypass classes:

**1. Comments hide the keyword.**
`/* hi */ DELETE FROM users` doesn't start with `select`... but neither does it start with `delete` if you only look after trimming whitespace. And `SELECT 1 -- \nDROP TABLE t` sneaks a second statement past a naive check. So step one is you have to *strip comments and string literals first*, before you look at anything. dbhub does exactly this (`stripCommentsAndStrings`), and it denies anything that reduces to empty after stripping (a favorite evasion: craft input that becomes empty so the keyword check has nothing to reject).

**2. The comment rules are dialect-specific.**
This is the subtle one. In MySQL/MariaDB, `--` only starts a comment if it's followed by whitespace or a control char. `SELECT 1--1` is `SELECT 1 - (-1)`, not a comment. So a stripper that treats `--x` as a comment on MySQL would happily discard `--1;DROP TABLE t` and misjudge the statement, while the engine runs the DROP. dbhub's parser encodes this rule per-dialect. If your comment stripper doesn't match your database's lexer *exactly*, that gap is a bypass.

**3. Multiple statements.**
`SELECT 1; DROP TABLE users` starts with `select`. You have to split into statements and check that *every one* is read-only, not just the first. dbhub splits (`splitSQLStatements`) and does `statements.every(isReadOnlySQL)`. And splitting correctly is its own parsing problem, get the string/comment/quoting boundaries wrong and a `;` inside a string wrongly splits (or a real `;` wrongly doesn't), and something rides through.

**4. Data-modifying CTEs.**
This one gets people who think "it starts with WITH/SELECT, it's a read." In Postgres:

```sql
WITH gone AS (DELETE FROM users RETURNING *) SELECT * FROM gone;
```

Starts with `WITH`. Deletes every row. dbhub special-cases this: for a `WITH` statement it scans the whole (comment-stripped) text for mutating keywords (`insert|update|delete|drop|alter|create|truncate|merge|grant|revoke|rename`) and denies if any appear.

**5. `SELECT ... INTO` writes.**
`SELECT * INTO new_table FROM users` (or MySQL's `SELECT ... INTO OUTFILE '/path'`) creates a table or writes a file. Starts with `select`. dbhub has a dedicated `SELECT ... INTO` check.

**6. Setters that don't look like writes.**
SQLite `PRAGMA query_only = OFF` turns the safety off. It's not `UPDATE`, it starts with an allowed keyword (`pragma`). And SQLite accepts both `PRAGMA x = v` *and* `PRAGMA x(v)` as setters, so checking for `=` isn't enough. dbhub allow-lists only the read-only introspection pragmas (`table_info`, `index_info`, ...) and denies the rest of the parenthesized/`=` forms.

**7. `EXPLAIN` that actually runs.**
`EXPLAIN ANALYZE DELETE FROM users` executes the statement to measure it. `EXPLAIN` is allow-listed. dbhub detects the `ANALYZE` form and recursively checks what comes after.

## The class you cannot regex your way out of

Even after all that, there's a category keyword inspection *fundamentally* can't catch: **side-effect functions callable from inside a plain `SELECT`.**

```sql
SELECT setval('user_id_seq', 1);              -- mutates a sequence (Postgres)
SELECT lo_export(16384, '/tmp/pwn');          -- writes a file (Postgres, superuser)
SELECT LOAD_FILE('/etc/passwd');              -- reads a server file (MySQL, FILE priv)
SELECT dblink_exec('...', 'DELETE FROM ...'); -- runs arbitrary SQL (Postgres, dblink)
SELECT my_helper_that_inserts();              -- any volatile UDF with side effects
```

Every one of these is a single statement that starts with `SELECT`, contains no mutating keyword, and isn't a CTE. A pure syntactic check *will* pass them. This is the wall: you cannot decide, from the text alone, whether an arbitrary function has side effects.

So the only real answer is: **stop trying to be complete at the parser, and enforce at the engine too.**

## What "done right" looks like: defense in depth

dbhub's actual guarantee isn't the keyword check. It's the keyword check *plus* a database-level read-only mode, applied per dialect:

- **Postgres:** connection runs with `default_transaction_read_only=on`. The engine itself refuses writes, including `setval` and `lo_export`.
- **MySQL / MariaDB:** the batch runs inside `START TRANSACTION READ ONLY`.
- **SQLite:** the database is *opened* read-only, plus `PRAGMA query_only = ON` as a backstop.
- **SQL Server:** which has no native read-only transaction, so the batch runs in a transaction that gets rolled back.

That second layer is what actually closes the side-effect-function hole. The keyword check is there to give a clean, fast "no" with a useful error (and to catch things before they hit the engine); the engine-level mode is there because the keyword check *can't* be complete and everyone building this should assume theirs isn't either.

## Takeaways if you're building one of these

1. **Never trust keyword inspection alone.** It cannot catch side-effect functions. Treat it as a fast-fail UX layer, not the security boundary.
2. **Enforce at the engine.** Postgres `default_transaction_read_only`, MySQL `START TRANSACTION READ ONLY`, SQLite read-only open + `query_only`, a read-only replica/role, whatever your DB gives you. That's the layer that actually holds.
3. **If you do parse, match the database's lexer exactly, per dialect.** Comments, string escapes, dollar-quoting, the MySQL `--` rule. A parser that disagrees with the engine is a bypass generator.
4. **Split statements and check all of them.** First-statement-only is a classic miss.
5. **Test the bypass classes explicitly:** multi-statement, CTE-DML, `SELECT INTO`, PRAGMA/`SET` toggles, `EXPLAIN ANALYZE`, and a side-effect function. If your "read-only" mode lets any of those through, it isn't one.

And the meta-point for the MCP moment we're in: an LLM agent hitting your database is untrusted input with a SQL console. "Read-only" is a load-bearing security control now, not a convenience toggle. Build it like one, and if you're evaluating an MCP DB server, go read how it enforces read-only before you point it at prod. dbhub's is a good bar to measure against.
