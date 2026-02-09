# Big Idea

SQLite programs typically do:

```c
sqlite3_prepare_v2(db, sql, ...);
sqlite3_step(stmt);
```

The SQL string is parsed inside `sqlite3_prepare_v2`.

So if you can intercept that function, you can:

1. see the SQL text before SQLite parses it
2. rewrite LazySQL → normal SQLite
3. pass the rewritten SQL into the real SQLite

That’s the whole trick.

LD_PRELOAD lets you override symbols at runtime:

```
your_program → libsqlite3.so
             ↑
        liblazyshim.so (preloaded)
```

---

# User Ergonomics

## The Dream

### Run any SQLite client with LazySQL enabled:

```bash
LD_PRELOAD=/usr/lib/liblazyshim.so sqlite3 my.db
```

Now inside:

```sql
CREATE POLICY invoices_policy
ON invoices
USING has_role('finance');
```

…and it works.

### Enable globally for a service:

```bash
export LD_PRELOAD=/usr/lib/liblazyshim.so
./my_app
```

No code changes.

---

## Packaging UX

You might ship:

### `lazy-sqlite-run`

```bash
lazy-sqlite-run sqlite3 my.db
lazy-sqlite-run python app.py
lazy-sqlite-run myservice
```

Internally does:

```bash
LD_PRELOAD=liblazyshim.so exec "$@"
```

So users don’t have to remember LD_PRELOAD incantations.

---

## Debugging / Opt-out

```bash
LAZYSQL_DEBUG=1 lazy-sqlite-run sqlite3 my.db
```

Print rewritten SQL.

Or:

```bash
LAZYSQL_DISABLE=1 ./app
```

Skip rewriting.

---

# Technical Architecture

The shim is just a shared library that defines the same symbols as SQLite.

## Core components

### 1. Symbol interposition layer

Override key entrypoints:

* `sqlite3_prepare_v2`
* `sqlite3_prepare_v3`
* maybe `sqlite3_exec`

Example:

```c
int sqlite3_prepare_v2(
    sqlite3 *db,
    const char *zSql,
    int nByte,
    sqlite3_stmt **ppStmt,
    const char **pzTail
) {
    // rewrite zSql
    // call real sqlite3_prepare_v2
}
```

---

### 2. Call the real SQLite function

You load the original symbol via `dlsym`:

```c
static int (*real_prepare_v2)(...) = NULL;

if (!real_prepare_v2) {
    real_prepare_v2 = dlsym(RTLD_NEXT, "sqlite3_prepare_v2");
}
```

So:

* your shim runs first
* then forwards to the real implementation

---

### 3. SQL rewrite engine

Inside the shim:

```c
char *rewritten = lazysql_rewrite(zSql);
```

This can be:

* simple token rewriting
* a tiny parser
* or call out to an embedded Rust/WASM compiler

Then forward:

```c
return real_prepare_v2(db, rewritten, ...);
```

---

## What Does Rewriting Mean?

### Example: CREATE POLICY

User writes:

```sql
CREATE POLICY p ON invoices USING has_role('finance');
```

Shim rewrites into:

```sql
INSERT INTO lazysql_policies(table, expr)
VALUES ('invoices', 'has_role("finance")');

CREATE VIEW invoices_secure AS
SELECT * FROM invoices
WHERE policy_check('invoices', rowid);
```

So the shim expands one statement into many.

---

# Handling Multi-Statement Expansion

This is tricky: `sqlite3_prepare_v2` expects *one statement*.

So you need to do one of:

## Option A: Only rewrite DDL through sqlite3_exec

Most tools run migrations via:

```c
sqlite3_exec(db, sql_script);
```

So you intercept `sqlite3_exec` instead, which supports multiple statements.

That’s easier.

## Option B: Statement queueing

When a single statement expands into multiple:

* prepare the first
* stash the rest
* feed them into subsequent prepare calls

Kind of like a macro expander.

---

# Where Do Policies Live?

The shim must ensure metadata tables exist:

```sql
CREATE TABLE IF NOT EXISTS lazysql_policies(...);
```

You can auto-bootstrap on first connection.

Intercept:

* `sqlite3_open`
* or first `prepare`

---

# Context Passing (Users/Roles)

You need per-connection state.

Shim can intercept:

```c
sqlite3_open(...)
```

and attach:

* current user
* tenant
* roles

Expose SQL functions:

```sql
SELECT set_context('user','alice');
```

Implemented via `sqlite3_create_function`.

---

# Enforcing Security (Prevent Bypass)

Rewriting alone is not security.

Users could still do:

```sql
SELECT * FROM invoices;
```

So you also install:

### sqlite3_set_authorizer

In the shim:

* deny direct table access
* only allow `_secure` views

This makes it mandatory.

---

# What Works Really Well

## Tools that become magically dialect-aware

* `sqlite3` CLI
* `dbmate`
* `flyway` (SQLite mode)
* Python sqlite3 module
* Ruby sqlite3 gem
* Go apps using CGO sqlite

Basically anything dynamically linked.

---

# Sharp Edges / Reality Checks

## 1. Static linking breaks everything

If the app bundles SQLite:

* no dynamic symbols
* LD_PRELOAD can’t intercept

Many Go/Rust builds do this.

---

## 2. Platform limitations

LD_PRELOAD is:

* Linux/Unix only
* macOS has `DYLD_INSERT_LIBRARIES` (restricted)
* Windows requires DLL injection

So portability is hard.

---

## 3. Version skew

Your shim assumes ABI stability.

If system SQLite updates, your shim must match.

---

## 4. Performance overhead

Every prepare call goes through rewrite logic.

You’ll want:

* fast path for normal SQL
* caching rewritten forms

---

## 5. Security boundary

LD_PRELOAD is not a sandbox.

If attacker controls environment, they can disable it.

So it’s a *developer ergonomics tool*, not a hard security boundary.

For real security you still want:

* extension-level enforcement
* authorizer hooks inside DB

---

# Best Practical Positioning

LD_PRELOAD shim is amazing for:

✅ migrations
✅ local tooling
✅ drop-in enhanced CLI
✅ prototyping dialect

Not sufficient alone for:

❌ strong production security
❌ cross-platform distribution
❌ statically linked apps

---

# A Realistic Product Shape

### Core enforcement = SQLite extension (authorizer, VFS)

### Dialect sugar = optional shim/compiler

* `lazy-sqlite compile schema.lsql`
* `lazy-sqlite-run sqlite3 my.db`

So:

* serious guarantees live in-extension
* LD_PRELOAD is just UX magic

---

# Concrete Minimal Shim MVP

Intercept only:

* `sqlite3_exec` (for migrations)
* `sqlite3_prepare_v2` (for small sugar)

Support only:

* `CREATE POLICY`
* `CREATE TEMPORAL TABLE`

Everything else passes through untouched.
