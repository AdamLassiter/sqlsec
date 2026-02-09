# 1. Policy-Aware Query Rewriting + Secure Views

### Goal

Make access control **automatic**, not something every developer has to remember in every query.

SQLite has no native RLS, so without rewriting, people end up doing:

```sql
SELECT * FROM invoices WHERE tenant_id = ?;
```

…and then someone forgets once, and boom.

### The Feature

Introduce **secure objects**:

* secure tables
* secure views
* policy-bound queries

Example:

```sql
CREATE POLICY invoices_policy
ON invoices
FOR SELECT
USING (
  has_role('finance')
  AND has_project_membership(project_id)
);
```

Now:

```sql
SELECT * FROM invoices;
```

is transparently rewritten to:

```sql
SELECT * FROM invoices
WHERE (
  has_role('finance')
  AND has_project_membership(project_id)
);
```

### Implementation Layer

SQLite gives you a few hooks:

* `sqlite3_set_authorizer` (approve/deny operations)
* query planner hooks are limited
* easiest: wrap via **views**
* advanced: modify AST in `sqlite3_prepare_v3`

### Secure Views as the Lazy Default

```sql
CREATE SECURE VIEW invoices_secure AS
SELECT * FROM invoices WHERE policy_check(...);
```

Then you can hide the base table entirely:

```sql
DENY DIRECT SELECT ON invoices;
```

### Bonus Features

* **Policy explainability**

```sql
EXPLAIN POLICY ON invoices FOR user='alice';
```

* **Policy debugging mode**

```sql
SET policy_debug=ON;
```

### Sharp Edges

* query rewriting must avoid bypass via joins/subqueries
* timing leaks unless paired with planner safety (see #6-ish)

---

# 2. Transparent Encryption (VFS Level)

### Goal

Make “SQLite but encrypted” a default baseline, not a paid addon.

SQLite doesn’t ship encryption because it’s a library, so you add it at the storage layer.

### The Feature

A custom VFS:

* encrypt pages before writing
* decrypt pages after reading
* keys managed per DB / per tenant

### Encryption Granularity Options

#### Whole-file encryption

Simplest: everything is encrypted.

Pros: easy
Cons: no selective sharing

#### Page-level encryption (best)

Encrypt each 4KB page independently.

Pros:

* random access stays fast
* works naturally with WAL

#### Column-level encryption (harder)

Only encrypt sensitive fields:

```sql
ENCRYPT COLUMN users.ssn WITH key('pii');
```

This requires encoding blobs + query limitations.

### Key Models

* single DB key (local apps)
* tenant keys (multi-tenant SaaS)
* envelope encryption (KMS-managed master key)

### Implementation Detail

VFS hooks:

* `xRead`
* `xWrite`
* `xFileControl`

Encryption sits *below* SQLite.

So the DB file is useless without keys.

### Bonus Feature: Key Rotation

```sql
ROTATE ENCRYPTION KEY;
```

Implemented by rewriting pages gradually, not all at once.

### Sharp Edges

* must encrypt WAL too
* must avoid leaking plaintext via temp files
* performance: needs hardware AES

---

# 3. Auditing + Access Logs

### Goal

If you’re doing labelled data, you need:

* who accessed what
* what was denied
* compliance trails

### The Feature

Automatic audit events for:

* SELECT on protected objects
* UPDATE/DELETE changes
* policy denials

Example:

```sql
SELECT * FROM invoices;
```

Emits:

```json
{
  "user": "alice",
  "action": "SELECT",
  "table": "invoices",
  "rows_returned": 12,
  "timestamp": ...
}
```

### Implementation Layers

#### SQL-level triggers (limited)

Only for writes:

```sql
CREATE TRIGGER audit_update AFTER UPDATE ON invoices ...
```

#### Extension-level query hooks (better)

Intercept prepares/steps:

* log query text
* log affected tables
* attach user context

#### Authorizer hook (best for denied access)

`sqlite3_set_authorizer` gives:

* operation type
* table name
* column name

### Audit Storage Options

* append-only table:

```sql
CREATE TABLE audit_log(...);
```

* external sink (syslog, Kafka)

### Bonus Features

* tamper-evident audit chain (hash chaining)
* audit queries:

```sql
SELECT * FROM audit_log WHERE user='bob';
```

### Sharp Edges

* logging SELECT row-level is expensive
* you want sampling or aggregation

---

# 4. Multi-Tenancy Primitives

### Goal

Make “tenant scoping” a first-class primitive, not a convention.

### The Feature

Instead of every table having ad hoc tenant filters, you declare:

```sql
CREATE TENANT TABLE invoices;
```

Which implies:

* tenant_id column exists
* tenant_id is always filtered
* tenant_id is part of every unique key

### Tenant Context

```sql
SET tenant='acme';
```

Now:

```sql
SELECT * FROM invoices;
```

means:

```sql
SELECT * FROM invoices WHERE tenant_id='acme';
```

### Tenant-Safe Constraints

Without this, you get bugs like:

* invoice number must be unique globally

Instead:

```sql
UNIQUE(tenant_id, invoice_number)
```

### Tenant-Aware Foreign Keys

```sql
FOREIGN KEY (tenant_id, customer_id)
REFERENCES customers(tenant_id, id)
```

### Implementation

This is basically:

* policy injection (feature #1)
* schema helpers/macros

### Bonus: Tenant Migration Tools

```sql
EXPORT TENANT 'acme';
IMPORT TENANT 'acme';
```

### Sharp Edges

* cross-tenant queries must require explicit override
* admin mode must be carefully controlled

---

# 5. CDC / Changefeeds

### Goal

Make SQLite usable for sync, replication, and event-driven systems.

People always reinvent:

* “updated_at” columns
* polling loops
* triggers writing to outbox tables

Just bake it in.

### The Feature

Changefeed declarations:

```sql
CREATE CHANGEFEED invoices_feed ON invoices;
```

Now you can do:

```sql
SELECT * FROM changes('invoices_feed')
WHERE seq > ?;
```

Returns:

* insert/update/delete events
* before/after images
* timestamp
* user context

### Implementation Options

#### Trigger-based outbox (easy)

```sql
CREATE TABLE invoices_changes(...);
```

Triggers append rows.

#### WAL-based decoding (hard but powerful)

Read WAL frames directly, like Postgres logical decoding.

Pros:

* no trigger overhead
* captures everything

Cons:

* complicated format parsing

### Bonus Features

* filtered feeds:

```sql
CREATE CHANGEFEED projectx_feed
ON invoices WHERE project_id='x';
```

* policy-aware feeds (don’t leak hidden rows)

### Sharp Edges

* ordering guarantees
* retention/cleanup needed

---

# 6. Temporal / History Tables

### Goal

Make “what did this look like last week” easy.

Services always need:

* auditability
* undo
* point-in-time recovery

### The Feature

```sql
CREATE TEMPORAL TABLE invoices;
```

Automatically creates history:

* valid_from
* valid_to
* version id

Now:

```sql
SELECT * FROM invoices AS OF '2026-01-01';
```

Or:

```sql
SELECT * FROM invoices HISTORY
WHERE id=5;
```

### Implementation

#### Trigger-based versioning

On update:

* copy old row into invoices_history
* mark validity ranges

#### Append-only storage

Never mutate rows, only insert new versions.

### Bonus Features

* diff queries:

```sql
SELECT diff(invoices, id=5, t1, t2);
```

* rollback:

```sql
RESTORE invoices TO '2026-01-01';
```

### Sharp Edges

* history grows fast
* needs pruning policies

---

# The Real Magic: These Six Reinforce Each Other

This is the fun part:

* Policies (#1) define tenant scoping (#4)
* Audit (#3) records policy decisions
* Temporal (#6) gives compliance history
* Encryption (#2) protects everything at rest
* CDC (#5) powers sync + event outbox
* Tenant primitives (#4) make SaaS trivial

Together, you get:

**SQLite-as-a-secure-service-core**

---

# If You Were Packaging This…

You could ship it as:

### SQL Surface

```sql
CREATE POLICY ...
CREATE TENANT TABLE ...
CREATE CHANGEFEED ...
CREATE TEMPORAL TABLE ...
SET CONTEXT user=...
```

### Extension Core

* authorizer enforcement
* query rewriting
* audit hooks

### VFS Layer

* encryption
* resilience
* WAL shipping