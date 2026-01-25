use std::mem::forget;

use rusqlite::{Connection, Error, Result};

use crate::{
    context::sec_ctx::SecurityContext,
    label::{LABEL_CACHE, Label, parse::parse},
};

impl Label {
    pub fn evaluate(&self, ctx: &SecurityContext) -> bool {
        if self.always_true {
            return true;
        }

        // All clauses must pass (AND)
        self.clauses.iter().all(|clause| {
            // At least one requirement in clause must match (OR)
            clause.iter().any(|req| ctx.has(&req.key, &req.value))
        })
    }
}

pub fn evaluate_label_expr(expr: &str, ctx: &SecurityContext) -> Option<i64> {
    match parse(expr) {
        Ok(label) => {
            if label.evaluate(ctx) {
                // For triggers, we just return a dummy id (or 1 if needed)
                Some(1) // placeholder, you can adjust based on your label table
            } else {
                None
            }
        }
        Err(_) => None,
    }
}

/// Evaluate label by ID against context (using Connection)
pub fn evaluate_by_id_conn(
    conn: &Connection,
    label_id: i64,
    ctx: &SecurityContext,
) -> Result<bool> {
    // Check cache first
    if let Some(label) = LABEL_CACHE.lock().get(&label_id) {
        return Ok(label.evaluate(ctx));
    }
    // Load from DB
    let expr: String = conn.query_row(
        "SELECT expr FROM sec_labels WHERE id = ?1",
        [label_id],
        |r| r.get(0),
    )?;

    let label = parse(&expr).map_err(|_| Error::InvalidQuery)?;

    LABEL_CACHE.lock().insert(label_id, label.clone());

    Ok(label.evaluate(ctx))
}

/// Evaluate label by ID from raw pointer (for FFI)
pub fn evaluate_by_id(db_ptr: usize, label_id: i64, ctx: &SecurityContext) -> Result<bool> {
    let conn = unsafe { Connection::from_handle(db_ptr as *mut _)? };
    let result = evaluate_by_id_conn(&conn, label_id, ctx);
    forget(conn);
    result
}

/// Check if a label allows access (using Connection)
pub fn is_visible_conn(conn: &Connection, label_id: Option<i64>, ctx: &SecurityContext) -> bool {
    match label_id {
        None => true,
        Some(id) => evaluate_by_id_conn(conn, id, ctx).unwrap_or(false),
    }
}

/// Check if a label allows access from raw pointer (for FFI)
pub fn is_visible(db_ptr: usize, label_id: Option<i64>, ctx: &SecurityContext) -> bool {
    match label_id {
        None => true,
        Some(id) => evaluate_by_id(db_ptr, id, ctx).unwrap_or(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evaluate_simple() {
        let label = parse("role=admin").unwrap();
        let mut ctx = SecurityContext::default();

        assert!(!label.evaluate(&ctx));

        ctx.set_attr("role", "admin");
        assert!(label.evaluate(&ctx));
    }

    #[test]
    fn evaluate_or() {
        let label = parse("(role=admin|role=auditor)").unwrap();
        let mut ctx = SecurityContext::default();

        ctx.set_attr("role", "auditor");
        assert!(label.evaluate(&ctx));
    }

    #[test]
    fn evaluate_and() {
        let label = parse("role=admin&team=finance").unwrap();
        let mut ctx = SecurityContext::default();

        ctx.set_attr("role", "admin");
        assert!(!label.evaluate(&ctx));

        ctx.set_attr("team", "finance");
        assert!(label.evaluate(&ctx));
    }
}
