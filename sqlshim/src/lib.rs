use std::ffi::{CStr, CString};

use libc::{RTLD_NEXT, c_char, c_int, c_void};

type Sqlite3 = c_void;
type SqliteStmt = c_void;

type PrepareV2 = unsafe extern "C" fn(
    db: *mut Sqlite3,
    z_sql: *const c_char,
    n_byte: c_int,
    pp_stmt: *mut *mut SqliteStmt,
    pz_tail: *mut *const c_char,
) -> c_int;

type PrepareV3 = unsafe extern "C" fn(
    db: *mut Sqlite3,
    z_sql: *const c_char,
    n_byte: c_int,
    prep_flags: u32,
    pp_stmt: *mut *mut SqliteStmt,
    pz_tail: *mut *const c_char,
) -> c_int;

// ============================================================================
// Configuration
// ============================================================================

fn debug() -> bool {
    std::env::var("LAZYSQL_DEBUG").is_ok()
}

fn disabled() -> bool {
    std::env::var("LAZYSQL_DISABLE").is_ok()
}

// ============================================================================
// Custom Statement Types
// ============================================================================

/// Represents all custom SQL extensions supported by the shim.
#[derive(Debug, Clone)]
pub enum CustomStatement {
    // ========================================================================
    // sqlsec: Row-Level & Column-Level Security (IMPLEMENTED)
    // ========================================================================
    /// CREATE POLICY name ON table [FOR operation] USING (expr)
    CreatePolicy(CreatePolicyStmt),

    /// DROP POLICY name ON table
    DropPolicy(DropPolicyStmt),

    /// SET CONTEXT key = 'value'
    SetContext(SetContextStmt),

    /// CLEAR CONTEXT
    ClearContext,

    /// PUSH CONTEXT
    PushContext,

    /// POP CONTEXT
    PopContext,

    /// REFRESH SECURITY VIEWS
    RefreshSecurityViews,

    /// CREATE SECURE VIEW name AS SELECT ... (with automatic policy injection)
    CreateSecureView(CreateSecureViewStmt),

    /// REGISTER SECURE TABLE logical ON physical WITH ROW LABEL column
    ///     [TABLE LABEL label_expr] [INSERT LABEL label_expr]
    RegisterSecureTable(RegisterSecureTableStmt),

    /// DEFINE LABEL 'expr'
    DefineLabel(DefineLabelStmt),

    /// DEFINE LEVEL attr 'name' = value
    DefineLevelStmt(DefineLevelStmt),

    /// SET COLUMN SECURITY table.column READ 'label_expr' [UPDATE 'label_expr']
    SetColumnSecurity(SetColumnSecurityStmt),

    // ========================================================================
    // Multi-Tenancy (STUB)
    // ========================================================================
    /// CREATE TENANT TABLE name (...)
    /// Expected: sec_tenant_register_table(name), auto-add tenant_id column
    CreateTenantTable(CreateTenantTableStmt),

    /// SET TENANT = 'value'
    /// Expected: sec_set_tenant(value), auto-filter all tenant tables
    SetTenant(SetTenantStmt),

    /// EXPORT TENANT 'name' [TO 'path']
    /// Expected: Generate INSERT statements for all tenant data
    ExportTenant(ExportTenantStmt),

    /// IMPORT TENANT 'name' [FROM 'path']
    /// Expected: Import tenant data with conflict resolution
    ImportTenant(ImportTenantStmt),

    // ========================================================================
    // Temporal Tables (STUB)
    // ========================================================================
    /// CREATE TEMPORAL TABLE name (...)
    /// Expected: Create table + history table + versioning triggers
    CreateTemporalTable(CreateTemporalTableStmt),

    /// SELECT ... FROM table AS OF 'timestamp'
    /// Expected: Rewrite to query history with valid_from/valid_to filter
    AsOfQuery(AsOfQueryStmt),

    /// SELECT ... FROM table HISTORY [WHERE ...]
    /// Expected: Query the history table directly
    HistoryQuery(HistoryQueryStmt),

    /// RESTORE table TO 'timestamp' [WHERE ...]
    /// Expected: Copy rows from history back to main table
    RestoreTable(RestoreTableStmt),

    // ========================================================================
    // Change Data Capture (STUB)
    // ========================================================================
    /// CREATE CHANGEFEED name ON table [WHERE ...]
    /// Expected: Create outbox table + triggers for CDC
    CreateChangefeed(CreateChangefeedStmt),

    /// DROP CHANGEFEED name
    /// Expected: Remove CDC infrastructure
    DropChangefeed(DropChangefeedStmt),

    // ========================================================================
    // Encryption (STUB - requires VFS layer)
    // ========================================================================
    /// ENCRYPT COLUMN table.column WITH KEY('keyname')
    /// Expected: Mark column for encryption, rewrite queries
    EncryptColumn(EncryptColumnStmt),

    /// ROTATE ENCRYPTION KEY [FOR table]
    /// Expected: Re-encrypt all data with new key
    RotateEncryptionKey(RotateKeyStmt),

    // ========================================================================
    // Auditing (STUB)
    // ========================================================================
    /// ENABLE AUDIT ON table [FOR operations]
    /// Expected: Create audit triggers
    EnableAudit(EnableAuditStmt),

    /// EXPLAIN POLICY ON table FOR USER = 'name'
    /// Expected: Show which rows/columns would be visible
    ExplainPolicy(ExplainPolicyStmt),
}

// ============================================================================
// Statement Structs
// ============================================================================

// --- sqlsec (Implemented) ---

#[derive(Debug, Clone)]
pub struct CreatePolicyStmt {
    pub name: String,
    pub table: String,
    pub operation: Option<PolicyOperation>,
    pub using_expr: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyOperation {
    Select,
    Insert,
    Update,
    Delete,
    All,
}

#[derive(Debug, Clone)]
pub struct DropPolicyStmt {
    pub name: String,
    pub table: String,
}

#[derive(Debug, Clone)]
pub struct SetContextStmt {
    pub key: String,
    pub value: String,
}

#[derive(Debug, Clone)]
pub struct CreateSecureViewStmt {
    pub name: String,
    pub query: String,
}

#[derive(Debug, Clone)]
pub struct RegisterSecureTableStmt {
    pub logical_name: String,
    pub physical_name: String,
    pub row_label_column: String,
    pub table_label: Option<String>,
    pub insert_label: Option<String>,
}

#[derive(Debug, Clone)]
pub struct DefineLabelStmt {
    pub expr: String,
}

#[derive(Debug, Clone)]
pub struct DefineLevelStmt {
    pub attribute: String,
    pub name: String,
    pub value: i64,
}

#[derive(Debug, Clone)]
pub struct SetColumnSecurityStmt {
    pub table: String,
    pub column: String,
    pub read_label: Option<String>,
    pub update_label: Option<String>,
}

// --- Multi-Tenancy (Stubs) ---

#[derive(Debug, Clone)]
pub struct CreateTenantTableStmt {
    pub name: String,
    pub columns: String, // Raw column definitions
}

#[derive(Debug, Clone)]
pub struct SetTenantStmt {
    pub tenant_id: String,
}

#[derive(Debug, Clone)]
pub struct ExportTenantStmt {
    pub tenant_id: String,
    pub path: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ImportTenantStmt {
    pub tenant_id: String,
    pub path: Option<String>,
}

// --- Temporal (Stubs) ---

#[derive(Debug, Clone)]
pub struct CreateTemporalTableStmt {
    pub name: String,
    pub columns: String,
}

#[derive(Debug, Clone)]
pub struct AsOfQueryStmt {
    pub original_sql: String,
    pub table: String,
    pub timestamp: String,
}

#[derive(Debug, Clone)]
pub struct HistoryQueryStmt {
    pub table: String,
    pub where_clause: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RestoreTableStmt {
    pub table: String,
    pub timestamp: String,
    pub where_clause: Option<String>,
}

// --- CDC (Stubs) ---

#[derive(Debug, Clone)]
pub struct CreateChangefeedStmt {
    pub name: String,
    pub table: String,
    pub filter: Option<String>,
}

#[derive(Debug, Clone)]
pub struct DropChangefeedStmt {
    pub name: String,
}

// --- Encryption (Stubs) ---

#[derive(Debug, Clone)]
pub struct EncryptColumnStmt {
    pub table: String,
    pub column: String,
    pub key_name: String,
}

#[derive(Debug, Clone)]
pub struct RotateKeyStmt {
    pub table: Option<String>,
}

// --- Auditing (Stubs) ---

#[derive(Debug, Clone)]
pub struct EnableAuditStmt {
    pub table: String,
    pub operations: Vec<PolicyOperation>,
}

#[derive(Debug, Clone)]
pub struct ExplainPolicyStmt {
    pub table: String,
    pub user: String,
}

// ============================================================================
// Parser Module
// ============================================================================

mod parser {
    use std::sync::LazyLock;

    use regex::Regex;

    use super::*;

    // Regex patterns for custom statements
    static RE_CREATE_POLICY: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(
            r"(?is)^\s*CREATE\s+POLICY\s+(\w+)\s+ON\s+(\w+)(?:\s+FOR\s+(SELECT|INSERT|UPDATE|DELETE|ALL))?\s+USING\s*\((.+)\)\s*;?\s*$"
        ).unwrap()
    });

    static RE_DROP_POLICY: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(?is)^\s*DROP\s+POLICY\s+(\w+)\s+ON\s+(\w+)\s*;?\s*$").unwrap()
    });

    static RE_SET_CONTEXT: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(?is)^\s*SET\s+CONTEXT\s+(\w+)\s*=\s*'([^']+)'\s*;?\s*$").unwrap()
    });

    static RE_CLEAR_CONTEXT: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"(?is)^\s*CLEAR\s+CONTEXT\s*;?\s*$").unwrap());

    static RE_PUSH_CONTEXT: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"(?is)^\s*PUSH\s+CONTEXT\s*;?\s*$").unwrap());

    static RE_POP_CONTEXT: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"(?is)^\s*POP\s+CONTEXT\s*;?\s*$").unwrap());

    static RE_REFRESH_VIEWS: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"(?is)^\s*REFRESH\s+SECURITY\s+VIEWS\s*;?\s*$").unwrap());

    static RE_REGISTER_SECURE_TABLE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(
            r"(?is)^\s*REGISTER\s+SECURE\s+TABLE\s+(\w+)\s+ON\s+(\w+)\s+WITH\s+ROW\s+LABEL\s+(\w+)(?:\s+TABLE\s+LABEL\s+'([^']+)')?(?:\s+INSERT\s+LABEL\s+'([^']+)')?\s*;?\s*$"
        ).unwrap()
    });

    static RE_DEFINE_LABEL: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"(?is)^\s*DEFINE\s+LABEL\s+'([^']+)'\s*;?\s*$").unwrap());

    static RE_DEFINE_LEVEL: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(?is)^\s*DEFINE\s+LEVEL\s+(\w+)\s+'([^']+)'\s*=\s*(\d+)\s*;?\s*$").unwrap()
    });

    static RE_SET_COLUMN_SECURITY: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(
            r"(?is)^\s*SET\s+COLUMN\s+SECURITY\s+(\w+)\.(\w+)(?:\s+READ\s+'([^']+)')?(?:\s+UPDATE\s+'([^']+)')?\s*;?\s*$"
        ).unwrap()
    });

    // Multi-tenancy patterns
    static RE_CREATE_TENANT_TABLE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(?is)^\s*CREATE\s+TENANT\s+TABLE\s+(\w+)\s*\((.+)\)\s*;?\s*$").unwrap()
    });

    static RE_SET_TENANT: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"(?is)^\s*SET\s+TENANT\s*=\s*'([^']+)'\s*;?\s*$").unwrap());

    static RE_EXPORT_TENANT: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(?is)^\s*EXPORT\s+TENANT\s+'([^']+)'(?:\s+TO\s+'([^']+)')?\s*;?\s*$").unwrap()
    });

    static RE_IMPORT_TENANT: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(?is)^\s*IMPORT\s+TENANT\s+'([^']+)'(?:\s+FROM\s+'([^']+)')?\s*;?\s*$")
            .unwrap()
    });

    // Temporal patterns
    static RE_CREATE_TEMPORAL_TABLE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(?is)^\s*CREATE\s+TEMPORAL\s+TABLE\s+(\w+)\s*\((.+)\)\s*;?\s*$").unwrap()
    });

    static RE_RESTORE_TABLE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(?is)^\s*RESTORE\s+(\w+)\s+TO\s+'([^']+)'(?:\s+WHERE\s+(.+))?\s*;?\s*$")
            .unwrap()
    });

    // CDC patterns
    static RE_CREATE_CHANGEFEED: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(
            r"(?is)^\s*CREATE\s+CHANGEFEED\s+(\w+)\s+ON\s+(\w+)(?:\s+WHERE\s+(.+))?\s*;?\s*$",
        )
        .unwrap()
    });

    static RE_DROP_CHANGEFEED: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"(?is)^\s*DROP\s+CHANGEFEED\s+(\w+)\s*;?\s*$").unwrap());

    // Encryption patterns
    static RE_ENCRYPT_COLUMN: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(
            r"(?is)^\s*ENCRYPT\s+COLUMN\s+(\w+)\.(\w+)\s+WITH\s+KEY\s*\(\s*'([^']+)'\s*\)\s*;?\s*$",
        )
        .unwrap()
    });

    static RE_ROTATE_KEY: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(?is)^\s*ROTATE\s+ENCRYPTION\s+KEY(?:\s+FOR\s+(\w+))?\s*;?\s*$").unwrap()
    });

    // Audit patterns
    static RE_ENABLE_AUDIT: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(
            r"(?is)^\s*ENABLE\s+AUDIT\s+ON\s+(\w+)(?:\s+FOR\s+(SELECT|INSERT|UPDATE|DELETE|ALL)(?:\s*,\s*(SELECT|INSERT|UPDATE|DELETE|ALL))*)?\s*;?\s*$"
        ).unwrap()
    });

    static RE_EXPLAIN_POLICY: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(?is)^\s*EXPLAIN\s+POLICY\s+ON\s+(\w+)\s+FOR\s+USER\s*=\s*'([^']+)'\s*;?\s*$")
            .unwrap()
    });

    fn parse_operation(s: &str) -> PolicyOperation {
        match s.to_uppercase().as_str() {
            "SELECT" => PolicyOperation::Select,
            "INSERT" => PolicyOperation::Insert,
            "UPDATE" => PolicyOperation::Update,
            "DELETE" => PolicyOperation::Delete,
            _ => PolicyOperation::All,
        }
    }

    /// Attempt to parse a custom statement. Returns None if it's standard SQL.
    pub fn parse(sql: &str) -> Option<CustomStatement> {
        // CREATE POLICY
        if let Some(caps) = RE_CREATE_POLICY.captures(sql) {
            return Some(CustomStatement::CreatePolicy(CreatePolicyStmt {
                name: caps.get(1).unwrap().as_str().to_string(),
                table: caps.get(2).unwrap().as_str().to_string(),
                operation: caps.get(3).map(|m| parse_operation(m.as_str())),
                using_expr: caps.get(4).unwrap().as_str().trim().to_string(),
            }));
        }

        // DROP POLICY
        if let Some(caps) = RE_DROP_POLICY.captures(sql) {
            return Some(CustomStatement::DropPolicy(DropPolicyStmt {
                name: caps.get(1).unwrap().as_str().to_string(),
                table: caps.get(2).unwrap().as_str().to_string(),
            }));
        }

        // SET CONTEXT
        if let Some(caps) = RE_SET_CONTEXT.captures(sql) {
            return Some(CustomStatement::SetContext(SetContextStmt {
                key: caps.get(1).unwrap().as_str().to_string(),
                value: caps.get(2).unwrap().as_str().to_string(),
            }));
        }

        // CLEAR CONTEXT
        if RE_CLEAR_CONTEXT.is_match(sql) {
            return Some(CustomStatement::ClearContext);
        }

        // PUSH CONTEXT
        if RE_PUSH_CONTEXT.is_match(sql) {
            return Some(CustomStatement::PushContext);
        }

        // POP CONTEXT
        if RE_POP_CONTEXT.is_match(sql) {
            return Some(CustomStatement::PopContext);
        }

        // REFRESH SECURITY VIEWS
        if RE_REFRESH_VIEWS.is_match(sql) {
            return Some(CustomStatement::RefreshSecurityViews);
        }

        // REGISTER SECURE TABLE
        if let Some(caps) = RE_REGISTER_SECURE_TABLE.captures(sql) {
            return Some(CustomStatement::RegisterSecureTable(
                RegisterSecureTableStmt {
                    logical_name: caps.get(1).unwrap().as_str().to_string(),
                    physical_name: caps.get(2).unwrap().as_str().to_string(),
                    row_label_column: caps.get(3).unwrap().as_str().to_string(),
                    table_label: caps.get(4).map(|m| m.as_str().to_string()),
                    insert_label: caps.get(5).map(|m| m.as_str().to_string()),
                },
            ));
        }

        // DEFINE LABEL
        if let Some(caps) = RE_DEFINE_LABEL.captures(sql) {
            return Some(CustomStatement::DefineLabel(DefineLabelStmt {
                expr: caps.get(1).unwrap().as_str().to_string(),
            }));
        }

        // DEFINE LEVEL
        if let Some(caps) = RE_DEFINE_LEVEL.captures(sql) {
            return Some(CustomStatement::DefineLevelStmt(DefineLevelStmt {
                attribute: caps.get(1).unwrap().as_str().to_string(),
                name: caps.get(2).unwrap().as_str().to_string(),
                value: caps.get(3).unwrap().as_str().parse().unwrap_or(0),
            }));
        }

        // SET COLUMN SECURITY
        if let Some(caps) = RE_SET_COLUMN_SECURITY.captures(sql) {
            return Some(CustomStatement::SetColumnSecurity(SetColumnSecurityStmt {
                table: caps.get(1).unwrap().as_str().to_string(),
                column: caps.get(2).unwrap().as_str().to_string(),
                read_label: caps.get(3).map(|m| m.as_str().to_string()),
                update_label: caps.get(4).map(|m| m.as_str().to_string()),
            }));
        }

        // CREATE TENANT TABLE
        if let Some(caps) = RE_CREATE_TENANT_TABLE.captures(sql) {
            return Some(CustomStatement::CreateTenantTable(CreateTenantTableStmt {
                name: caps.get(1).unwrap().as_str().to_string(),
                columns: caps.get(2).unwrap().as_str().to_string(),
            }));
        }

        // SET TENANT
        if let Some(caps) = RE_SET_TENANT.captures(sql) {
            return Some(CustomStatement::SetTenant(SetTenantStmt {
                tenant_id: caps.get(1).unwrap().as_str().to_string(),
            }));
        }

        // EXPORT TENANT
        if let Some(caps) = RE_EXPORT_TENANT.captures(sql) {
            return Some(CustomStatement::ExportTenant(ExportTenantStmt {
                tenant_id: caps.get(1).unwrap().as_str().to_string(),
                path: caps.get(2).map(|m| m.as_str().to_string()),
            }));
        }

        // IMPORT TENANT
        if let Some(caps) = RE_IMPORT_TENANT.captures(sql) {
            return Some(CustomStatement::ImportTenant(ImportTenantStmt {
                tenant_id: caps.get(1).unwrap().as_str().to_string(),
                path: caps.get(2).map(|m| m.as_str().to_string()),
            }));
        }

        // CREATE TEMPORAL TABLE
        if let Some(caps) = RE_CREATE_TEMPORAL_TABLE.captures(sql) {
            return Some(CustomStatement::CreateTemporalTable(
                CreateTemporalTableStmt {
                    name: caps.get(1).unwrap().as_str().to_string(),
                    columns: caps.get(2).unwrap().as_str().to_string(),
                },
            ));
        }

        // RESTORE TABLE
        if let Some(caps) = RE_RESTORE_TABLE.captures(sql) {
            return Some(CustomStatement::RestoreTable(RestoreTableStmt {
                table: caps.get(1).unwrap().as_str().to_string(),
                timestamp: caps.get(2).unwrap().as_str().to_string(),
                where_clause: caps.get(3).map(|m| m.as_str().to_string()),
            }));
        }

        // CREATE CHANGEFEED
        if let Some(caps) = RE_CREATE_CHANGEFEED.captures(sql) {
            return Some(CustomStatement::CreateChangefeed(CreateChangefeedStmt {
                name: caps.get(1).unwrap().as_str().to_string(),
                table: caps.get(2).unwrap().as_str().to_string(),
                filter: caps.get(3).map(|m| m.as_str().to_string()),
            }));
        }

        // DROP CHANGEFEED
        if let Some(caps) = RE_DROP_CHANGEFEED.captures(sql) {
            return Some(CustomStatement::DropChangefeed(DropChangefeedStmt {
                name: caps.get(1).unwrap().as_str().to_string(),
            }));
        }

        // ENCRYPT COLUMN
        if let Some(caps) = RE_ENCRYPT_COLUMN.captures(sql) {
            return Some(CustomStatement::EncryptColumn(EncryptColumnStmt {
                table: caps.get(1).unwrap().as_str().to_string(),
                column: caps.get(2).unwrap().as_str().to_string(),
                key_name: caps.get(3).unwrap().as_str().to_string(),
            }));
        }

        // ROTATE ENCRYPTION KEY
        if let Some(caps) = RE_ROTATE_KEY.captures(sql) {
            return Some(CustomStatement::RotateEncryptionKey(RotateKeyStmt {
                table: caps.get(1).map(|m| m.as_str().to_string()),
            }));
        }

        // ENABLE AUDIT
        if let Some(caps) = RE_ENABLE_AUDIT.captures(sql) {
            let mut ops = Vec::new();
            for i in 2..=4 {
                if let Some(m) = caps.get(i) {
                    ops.push(parse_operation(m.as_str()));
                }
            }
            if ops.is_empty() {
                ops.push(PolicyOperation::All);
            }
            return Some(CustomStatement::EnableAudit(EnableAuditStmt {
                table: caps.get(1).unwrap().as_str().to_string(),
                operations: ops,
            }));
        }

        // EXPLAIN POLICY
        if let Some(caps) = RE_EXPLAIN_POLICY.captures(sql) {
            return Some(CustomStatement::ExplainPolicy(ExplainPolicyStmt {
                table: caps.get(1).unwrap().as_str().to_string(),
                user: caps.get(2).unwrap().as_str().to_string(),
            }));
        }

        None
    }
}

// ============================================================================
// Rewriter Module
// ============================================================================

mod rewriter {
    use super::*;

    /// Escape a string for use in SQLite string literals
    fn escape_sql_string(s: &str) -> String {
        s.replace('\'', "''")
    }

    /// Convert a policy expression to a sqlsec label expression.
    /// This handles common patterns like function calls.
    fn policy_expr_to_label(expr: &str) -> String {
        // The policy USING clause uses function-style syntax like:
        //   has_role('finance') AND has_project_membership(project_id)
        //
        // We need to convert this to sqlsec label syntax:
        //   role=finance&project_member=true
        //
        // For now, we store the raw expression and let sqlsec handle it,
        // or we do a basic transformation.

        // Simple case: just store as-is for complex expressions
        // The sqlsec extension will need to evaluate these
        expr.to_string()
    }

    pub fn rewrite(stmt: CustomStatement) -> String {
        match stmt {
            // ================================================================
            // sqlsec: Fully Implemented
            // ================================================================
            CustomStatement::CreatePolicy(p) => rewrite_create_policy(p),
            CustomStatement::DropPolicy(p) => rewrite_drop_policy(p),
            CustomStatement::SetContext(s) => rewrite_set_context(s),
            CustomStatement::ClearContext => "SELECT sec_clear_context();".to_string(),
            CustomStatement::PushContext => "SELECT sec_push_context();".to_string(),
            CustomStatement::PopContext => "SELECT sec_pop_context();".to_string(),
            CustomStatement::RefreshSecurityViews => "SELECT sec_refresh_views();".to_string(),
            CustomStatement::RegisterSecureTable(r) => rewrite_register_secure_table(r),
            CustomStatement::DefineLabel(d) => rewrite_define_label(d),
            CustomStatement::DefineLevelStmt(d) => rewrite_define_level(d),
            CustomStatement::SetColumnSecurity(s) => rewrite_set_column_security(s),
            CustomStatement::CreateSecureView(v) => rewrite_create_secure_view(v),

            // ================================================================
            // Multi-Tenancy: Stubs
            // ================================================================
            CustomStatement::CreateTenantTable(t) => stub_create_tenant_table(t),
            CustomStatement::SetTenant(t) => stub_set_tenant(t),
            CustomStatement::ExportTenant(e) => stub_export_tenant(e),
            CustomStatement::ImportTenant(i) => stub_import_tenant(i),

            // ================================================================
            // Temporal: Stubs
            // ================================================================
            CustomStatement::CreateTemporalTable(t) => stub_create_temporal_table(t),
            CustomStatement::AsOfQuery(q) => stub_as_of_query(q),
            CustomStatement::HistoryQuery(q) => stub_history_query(q),
            CustomStatement::RestoreTable(r) => stub_restore_table(r),

            // ================================================================
            // CDC: Stubs
            // ================================================================
            CustomStatement::CreateChangefeed(c) => stub_create_changefeed(c),
            CustomStatement::DropChangefeed(d) => stub_drop_changefeed(d),

            // ================================================================
            // Encryption: Stubs
            // ================================================================
            CustomStatement::EncryptColumn(e) => stub_encrypt_column(e),
            CustomStatement::RotateEncryptionKey(r) => stub_rotate_key(r),

            // ================================================================
            // Auditing: Stubs
            // ================================================================
            CustomStatement::EnableAudit(a) => stub_enable_audit(a),
            CustomStatement::ExplainPolicy(e) => stub_explain_policy(e),
        }
    }

    // ========================================================================
    // sqlsec Implementations
    // ========================================================================

    fn rewrite_create_policy(p: CreatePolicyStmt) -> String {
        // CREATE POLICY maps to:
        // 1. Define a label with the policy expression
        // 2. Store the policy in a metadata table
        // 3. The policy name is stored for later reference
        //
        // For sqlsec integration, policies become row labels on tables.

        let label_expr = policy_expr_to_label(&p.using_expr);
        let escaped_expr = escape_sql_string(&label_expr);
        let escaped_name = escape_sql_string(&p.name);
        let escaped_table = escape_sql_string(&p.table);

        let op_str = match p.operation {
            Some(PolicyOperation::Select) => "SELECT",
            Some(PolicyOperation::Insert) => "INSERT",
            Some(PolicyOperation::Update) => "UPDATE",
            Some(PolicyOperation::Delete) => "DELETE",
            Some(PolicyOperation::All) | None => "ALL",
        };

        // Create policy metadata table if needed, define label, store policy
        format!(
            r#"
CREATE TABLE IF NOT EXISTS __lazysql_policies (
    name TEXT NOT NULL,
    table_name TEXT NOT NULL,
    operation TEXT NOT NULL,
    label_id INTEGER NOT NULL,
    expr TEXT NOT NULL,
    PRIMARY KEY (name, table_name)
);
INSERT OR REPLACE INTO __lazysql_policies (name, table_name, operation, label_id, expr)
VALUES (
    '{escaped_name}',
    '{escaped_table}',
    '{op_str}',
    sec_define_label('{escaped_expr}'),
    '{escaped_expr}'
);
"#
        )
    }

    fn rewrite_drop_policy(p: DropPolicyStmt) -> String {
        let escaped_name = escape_sql_string(&p.name);
        let escaped_table = escape_sql_string(&p.table);

        format!(
            "DELETE FROM __lazysql_policies WHERE name = '{escaped_name}' AND table_name = '{escaped_table}';"
        )
    }

    fn rewrite_set_context(s: SetContextStmt) -> String {
        let escaped_key = escape_sql_string(&s.key);
        let escaped_value = escape_sql_string(&s.value);

        // Set attribute and refresh views
        format!(
            "SELECT sec_set_attr('{escaped_key}', '{escaped_value}'); SELECT sec_refresh_views();"
        )
    }

    fn rewrite_register_secure_table(r: RegisterSecureTableStmt) -> String {
        let escaped_logical = escape_sql_string(&r.logical_name);
        let escaped_physical = escape_sql_string(&r.physical_name);
        let escaped_row_col = escape_sql_string(&r.row_label_column);

        let table_label = r
            .table_label
            .map(|l| format!("sec_define_label('{}')", escape_sql_string(&l)))
            .unwrap_or_else(|| "NULL".to_string());

        let insert_label = r
            .insert_label
            .map(|l| format!("sec_define_label('{}')", escape_sql_string(&l)))
            .unwrap_or_else(|| "NULL".to_string());

        format!(
            "SELECT sec_register_table('{escaped_logical}', '{escaped_physical}', '{escaped_row_col}', {table_label}, {insert_label});"
        )
    }

    fn rewrite_define_label(d: DefineLabelStmt) -> String {
        let escaped = escape_sql_string(&d.expr);
        format!("SELECT sec_define_label('{escaped}');")
    }

    fn rewrite_define_level(d: DefineLevelStmt) -> String {
        let escaped_attr = escape_sql_string(&d.attribute);
        let escaped_name = escape_sql_string(&d.name);
        format!(
            "SELECT sec_define_level('{escaped_attr}', '{escaped_name}', {});",
            d.value
        )
    }

    fn rewrite_set_column_security(s: SetColumnSecurityStmt) -> String {
        let escaped_table = escape_sql_string(&s.table);
        let escaped_column = escape_sql_string(&s.column);

        let mut stmts = Vec::new();

        if let Some(read_label) = s.read_label {
            let escaped = escape_sql_string(&read_label);
            stmts.push(format!(
                r#"UPDATE sec_columns SET read_label_id = sec_define_label('{escaped}')
WHERE logical_table = '{escaped_table}' AND column_name = '{escaped_column}';"#
            ));
        }

        if let Some(update_label) = s.update_label {
            let escaped = escape_sql_string(&update_label);
            stmts.push(format!(
                r#"UPDATE sec_columns SET update_label_id = sec_define_label('{escaped}')
WHERE logical_table = '{escaped_table}' AND column_name = '{escaped_column}';"#
            ));
        }

        if stmts.is_empty() {
            "SELECT 1;".to_string()
        } else {
            stmts.join("\n")
        }
    }

    fn rewrite_create_secure_view(v: CreateSecureViewStmt) -> String {
        // For secure views, we wrap the query with policy checks
        // This is a simplified version - full implementation would parse
        // the query and inject WHERE clauses
        let escaped_name = escape_sql_string(&v.name);
        let escaped_query = escape_sql_string(&v.query);

        format!(
            r#"CREATE VIEW {escaped_name} AS
SELECT * FROM ({escaped_query})
WHERE sec_assert_fresh();"#
        )
    }

    // ========================================================================
    // Multi-Tenancy Stubs
    // ========================================================================

    /// CREATE TENANT TABLE name (columns)
    ///
    /// Expected implementation:
    /// 1. Add tenant_id column automatically
    /// 2. Add tenant_id to all unique constraints
    /// 3. Register table for automatic tenant filtering
    /// 4. Create INSTEAD OF triggers for tenant isolation
    ///
    /// Required functions to implement:
    /// - `tenant_register_table(name)` - Register table for tenant filtering
    /// - `tenant_get_current()` - Get current tenant context
    fn stub_create_tenant_table(t: CreateTenantTableStmt) -> String {
        // TODO: Implement tenant table creation
        // This should:
        // 1. Parse columns and inject tenant_id
        // 2. Modify unique constraints to include tenant_id
        // 3. Create the table
        // 4. Register for tenant filtering
        eprintln!("STUB: CREATE TENANT TABLE {} - not yet implemented", t.name);
        format!(
            "SELECT 'TODO: CREATE TENANT TABLE {} not implemented' AS stub;",
            escape_sql_string(&t.name)
        )
    }

    /// SET TENANT = 'value'
    ///
    /// Expected implementation:
    /// 1. Store tenant ID in connection context
    /// 2. Refresh all tenant-filtered views
    ///
    /// Required functions to implement:
    /// - `tenant_set(tenant_id)` - Set current tenant
    /// - `tenant_refresh_views()` - Rebuild views with tenant filter
    fn stub_set_tenant(t: SetTenantStmt) -> String {
        // TODO: Implement tenant context setting
        eprintln!("STUB: SET TENANT = '{}' - not yet implemented", t.tenant_id);
        format!(
            "SELECT 'TODO: SET TENANT not implemented' AS stub, '{}' AS tenant;",
            escape_sql_string(&t.tenant_id)
        )
    }

    /// EXPORT TENANT 'name' [TO 'path']
    ///
    /// Expected implementation:
    /// 1. Generate INSERT statements for all tenant data
    /// 2. Include schema if needed
    /// 3. Write to file or return as result set
    ///
    /// Required functions to implement:
    /// - `tenant_export(tenant_id, path)` - Export tenant data
    fn stub_export_tenant(e: ExportTenantStmt) -> String {
        eprintln!(
            "STUB: EXPORT TENANT '{}' - not yet implemented",
            e.tenant_id
        );
        format!("SELECT 'TODO: EXPORT TENANT not implemented' AS stub;",)
    }

    /// IMPORT TENANT 'name' [FROM 'path']
    ///
    /// Expected implementation:
    /// 1. Read tenant data from file
    /// 2. Handle conflicts (rename, merge, reject)
    /// 3. Import with transaction safety
    ///
    /// Required functions to implement:
    /// - `tenant_import(tenant_id, path)` - Import tenant data
    fn stub_import_tenant(i: ImportTenantStmt) -> String {
        eprintln!(
            "STUB: IMPORT TENANT '{}' - not yet implemented",
            i.tenant_id
        );
        format!("SELECT 'TODO: IMPORT TENANT not implemented' AS stub;",)
    }

    // ========================================================================
    // Temporal Table Stubs
    // ========================================================================

    /// CREATE TEMPORAL TABLE name (columns)
    ///
    /// Expected implementation:
    /// 1. Create main table with valid_from, valid_to columns
    /// 2. Create history table: {name}_history
    /// 3. Create triggers for versioning:
    ///    - BEFORE UPDATE: copy to history, update valid_to
    ///    - BEFORE DELETE: copy to history, update valid_to
    ///    - AFTER INSERT: set valid_from to now, valid_to to infinity
    ///
    /// Required functions to implement:
    /// - `temporal_register_table(name)` - Register for temporal queries
    /// - `temporal_now()` - Get current timestamp for versioning
    fn stub_create_temporal_table(t: CreateTemporalTableStmt) -> String {
        eprintln!(
            "STUB: CREATE TEMPORAL TABLE {} - not yet implemented",
            t.name
        );
        format!(
            "SELECT 'TODO: CREATE TEMPORAL TABLE {} not implemented' AS stub;",
            escape_sql_string(&t.name)
        )
    }

    /// SELECT ... FROM table AS OF 'timestamp'
    ///
    /// Expected implementation:
    /// Rewrite to:
    /// ```sql
    /// SELECT * FROM (
    ///   SELECT * FROM table WHERE valid_from <= 'ts' AND valid_to > 'ts'
    ///   UNION ALL
    ///   SELECT * FROM table_history WHERE valid_from <= 'ts' AND valid_to > 'ts'
    /// )
    /// ```
    fn stub_as_of_query(q: AsOfQueryStmt) -> String {
        eprintln!(
            "STUB: AS OF query on {} at {} - not yet implemented",
            q.table, q.timestamp
        );
        format!("SELECT 'TODO: AS OF query not implemented' AS stub;",)
    }

    /// SELECT ... FROM table HISTORY
    ///
    /// Expected implementation:
    /// Rewrite to query {table}_history directly
    fn stub_history_query(q: HistoryQueryStmt) -> String {
        eprintln!("STUB: HISTORY query on {} - not yet implemented", q.table);
        format!("SELECT 'TODO: HISTORY query not implemented' AS stub;",)
    }

    /// RESTORE table TO 'timestamp'
    ///
    /// Expected implementation:
    /// 1. Find rows as they existed at timestamp
    /// 2. Insert/update them in main table
    /// 3. Create new history entries for the restore operation
    ///
    /// Required functions to implement:
    /// - `temporal_restore(table, timestamp)` - Restore table state
    fn stub_restore_table(r: RestoreTableStmt) -> String {
        eprintln!(
            "STUB: RESTORE {} TO '{}' - not yet implemented",
            r.table, r.timestamp
        );
        format!("SELECT 'TODO: RESTORE TABLE not implemented' AS stub;",)
    }

    // ========================================================================
    // CDC Stubs
    // ========================================================================

    /// CREATE CHANGEFEED name ON table [WHERE filter]
    ///
    /// Expected implementation:
    /// 1. Create changes table: {name}_changes with columns:
    ///    - seq (autoincrement)
    ///    - operation (INSERT/UPDATE/DELETE)
    ///    - timestamp
    ///    - old_data (JSON)
    ///    - new_data (JSON)
    /// 2. Create AFTER triggers on table for INSERT/UPDATE/DELETE
    ///
    /// Required functions to implement:
    /// - `cdc_register_feed(name, table)` - Register changefeed
    /// - `cdc_get_changes(name, since_seq)` - Get changes since sequence
    fn stub_create_changefeed(c: CreateChangefeedStmt) -> String {
        eprintln!(
            "STUB: CREATE CHANGEFEED {} ON {} - not yet implemented",
            c.name, c.table
        );
        format!("SELECT 'TODO: CREATE CHANGEFEED not implemented' AS stub;",)
    }

    /// DROP CHANGEFEED name
    ///
    /// Expected implementation:
    /// 1. Drop the changes table
    /// 2. Drop the triggers
    /// 3. Remove from metadata
    fn stub_drop_changefeed(d: DropChangefeedStmt) -> String {
        eprintln!("STUB: DROP CHANGEFEED {} - not yet implemented", d.name);
        format!("SELECT 'TODO: DROP CHANGEFEED not implemented' AS stub;",)
    }

    // ========================================================================
    // Encryption Stubs
    // ========================================================================

    /// ENCRYPT COLUMN table.column WITH KEY('keyname')
    ///
    /// Expected implementation (requires VFS layer):
    /// 1. Mark column in metadata as encrypted
    /// 2. Rewrite INSERT/UPDATE to encrypt values
    /// 3. Rewrite SELECT to decrypt values
    /// 4. Store key reference (actual key in secure storage)
    ///
    /// Required functions to implement:
    /// - `crypto_encrypt(value, key_name)` - Encrypt a value
    /// - `crypto_decrypt(value, key_name)` - Decrypt a value
    /// - `crypto_register_column(table, column, key)` - Register encrypted column
    fn stub_encrypt_column(e: EncryptColumnStmt) -> String {
        eprintln!(
            "STUB: ENCRYPT COLUMN {}.{} WITH KEY('{}') - not yet implemented",
            e.table, e.column, e.key_name
        );
        format!("SELECT 'TODO: ENCRYPT COLUMN not implemented (requires VFS layer)' AS stub;",)
    }

    /// ROTATE ENCRYPTION KEY [FOR table]
    ///
    /// Expected implementation:
    /// 1. Generate new key version
    /// 2. Re-encrypt all affected columns
    /// 3. Update key references
    /// 4. (Optionally) keep old key for decryption during rotation
    ///
    /// Required functions to implement:
    /// - `crypto_rotate_key(table)` - Rotate encryption key
    fn stub_rotate_key(r: RotateKeyStmt) -> String {
        let table_msg = r.table.as_deref().unwrap_or("all tables");
        eprintln!(
            "STUB: ROTATE ENCRYPTION KEY for {} - not yet implemented",
            table_msg
        );
        format!(
            "SELECT 'TODO: ROTATE ENCRYPTION KEY not implemented (requires VFS layer)' AS stub;",
        )
    }

    // ========================================================================
    // Auditing Stubs
    // ========================================================================

    /// ENABLE AUDIT ON table [FOR operations]
    ///
    /// Expected implementation:
    /// 1. Create audit_log table if not exists
    /// 2. Create triggers for specified operations
    /// 3. Log: timestamp, user, operation, table, old/new values
    ///
    /// Required functions to implement:
    /// - `audit_get_user()` - Get current user for audit
    /// - `audit_log(table, operation, old, new)` - Write audit entry
    fn stub_enable_audit(a: EnableAuditStmt) -> String {
        let ops: Vec<&str> = a
            .operations
            .iter()
            .map(|o| match o {
                PolicyOperation::Select => "SELECT",
                PolicyOperation::Insert => "INSERT",
                PolicyOperation::Update => "UPDATE",
                PolicyOperation::Delete => "DELETE",
                PolicyOperation::All => "ALL",
            })
            .collect();
        eprintln!(
            "STUB: ENABLE AUDIT ON {} FOR {:?} - not yet implemented",
            a.table, ops
        );
        format!("SELECT 'TODO: ENABLE AUDIT not implemented' AS stub;",)
    }

    /// EXPLAIN POLICY ON table FOR USER = 'name'
    ///
    /// Expected implementation:
    /// 1. Simulate user's security context
    /// 2. Evaluate which rows would be visible
    /// 3. Evaluate which columns would be visible
    /// 4. Return explanatory result set
    ///
    /// Required functions to implement:
    /// - `policy_explain(table, user)` - Explain policy effects
    fn stub_explain_policy(e: ExplainPolicyStmt) -> String {
        eprintln!(
            "STUB: EXPLAIN POLICY ON {} FOR USER='{}' - not yet implemented",
            e.table, e.user
        );
        format!("SELECT 'TODO: EXPLAIN POLICY not implemented' AS stub;",)
    }
}

// ============================================================================
// Main Rewrite Function
// ============================================================================

fn rewrite(sql: &str) -> Option<String> {
    if disabled() {
        return None;
    }

    parser::parse(sql).map(|stmt| {
        if debug() {
            eprintln!("sqlshim: parsed statement: {:?}", stmt);
        }
        rewriter::rewrite(stmt)
    })
}

// ============================================================================
// FFI Exports
// ============================================================================

unsafe fn resolve_prepare_v2() -> PrepareV2 {
    let cname = CString::new("sqlite3_prepare_v2").unwrap();
    let addr = libc::dlsym(RTLD_NEXT, cname.as_ptr());
    if addr.is_null() {
        panic!("sqlshim: could not resolve sqlite3_prepare_v2");
    }
    std::mem::transmute::<*mut c_void, PrepareV2>(addr)
}

unsafe fn resolve_prepare_v3() -> PrepareV3 {
    let cname = CString::new("sqlite3_prepare_v3").unwrap();
    let addr = libc::dlsym(RTLD_NEXT, cname.as_ptr());
    if addr.is_null() {
        panic!("sqlshim: could not resolve sqlite3_prepare_v3");
    }
    std::mem::transmute::<*mut c_void, PrepareV3>(addr)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sqlite3_prepare_v2(
    db: *mut Sqlite3,
    z_sql: *const c_char,
    n_byte: c_int,
    pp_stmt: *mut *mut SqliteStmt,
    pz_tail: *mut *const c_char,
) -> c_int {
    let real = resolve_prepare_v2();

    let sql = CStr::from_ptr(z_sql).to_string_lossy().to_string();

    if let Some(new_sql) = rewrite(&sql) {
        if debug() {
            eprintln!("sqlshim: prepare_v2 rewrite!");
            eprintln!("  original: {}", sql.trim());
            eprintln!("  rewritten: {}", new_sql.trim());
        }

        let csql = CString::new(new_sql).unwrap();
        return real(db, csql.as_ptr(), -1, pp_stmt, pz_tail);
    }

    real(db, z_sql, n_byte, pp_stmt, pz_tail)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sqlite3_prepare_v3(
    db: *mut Sqlite3,
    z_sql: *const c_char,
    n_byte: c_int,
    prep_flags: u32,
    pp_stmt: *mut *mut SqliteStmt,
    pz_tail: *mut *const c_char,
) -> c_int {
    let real = resolve_prepare_v3();

    let sql = CStr::from_ptr(z_sql).to_string_lossy().to_string();

    if let Some(new_sql) = rewrite(&sql) {
        if debug() {
            eprintln!("sqlshim: prepare_v3 rewrite!");
            eprintln!("  original: {}", sql.trim());
            eprintln!("  rewritten: {}", new_sql.trim());
        }

        let csql = CString::new(new_sql).unwrap();
        return real(db, csql.as_ptr(), -1, prep_flags, pp_stmt, pz_tail);
    }

    real(db, z_sql, n_byte, prep_flags, pp_stmt, pz_tail)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_create_policy() {
        let sql = "CREATE POLICY test_pol ON users FOR SELECT USING (role='admin');";
        let stmt = parser::parse(sql).unwrap();
        match stmt {
            CustomStatement::CreatePolicy(p) => {
                assert_eq!(p.name, "test_pol");
                assert_eq!(p.table, "users");
                assert_eq!(p.operation, Some(PolicyOperation::Select));
                assert_eq!(p.using_expr, "role='admin'");
            }
            _ => panic!("Expected CreatePolicy"),
        }
    }

    #[test]
    fn test_parse_set_context() {
        let sql = "SET CONTEXT role = 'admin';";
        let stmt = parser::parse(sql).unwrap();
        match stmt {
            CustomStatement::SetContext(s) => {
                assert_eq!(s.key, "role");
                assert_eq!(s.value, "admin");
            }
            _ => panic!("Expected SetContext"),
        }
    }

    #[test]
    fn test_parse_define_label() {
        let sql = "DEFINE LABEL 'role=admin&team=finance';";
        let stmt = parser::parse(sql).unwrap();
        match stmt {
            CustomStatement::DefineLabel(d) => {
                assert_eq!(d.expr, "role=admin&team=finance");
            }
            _ => panic!("Expected DefineLabel"),
        }
    }

    #[test]
    fn test_parse_create_tenant_table() {
        let sql = "CREATE TENANT TABLE invoices (id INTEGER PRIMARY KEY, amount REAL);";
        let stmt = parser::parse(sql).unwrap();
        match stmt {
            CustomStatement::CreateTenantTable(t) => {
                assert_eq!(t.name, "invoices");
                assert!(t.columns.contains("id INTEGER PRIMARY KEY"));
            }
            _ => panic!("Expected CreateTenantTable"),
        }
    }

    #[test]
    fn test_rewrite_create_policy() {
        let sql = "CREATE POLICY inv_pol ON invoices USING (has_role('finance'));";
        let rewritten = rewrite(sql).unwrap();
        assert!(rewritten.contains("__lazysql_policies"));
        assert!(rewritten.contains("sec_define_label"));
    }

    #[test]
    fn test_passthrough_normal_sql() {
        let sql = "SELECT * FROM users WHERE id = 1;";
        assert!(rewrite(sql).is_none());
    }
}
