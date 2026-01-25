pub mod define;
pub mod evaluate;
pub mod parse;

use std::collections::HashMap;

use once_cell::sync::Lazy;
use parking_lot::Mutex;

/// A single requirement: key=value
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttrReq {
    pub key: String,
    pub value: String,
}

/// OR-group: any of these requirements satisfies the clause
pub type Clause = Vec<AttrReq>;

/// AND of OR-groups (CNF)
#[derive(Debug, Clone, Default)]
pub struct Label {
    pub clauses: Vec<Clause>,
    pub always_true: bool,
}

pub static LABEL_CACHE: Lazy<Mutex<HashMap<i64, Label>>> = Lazy::new(|| Mutex::new(HashMap::new()));
