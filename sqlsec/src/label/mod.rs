use std::{collections::HashMap, sync::LazyLock};

use parking_lot::Mutex;

pub mod define;
pub mod evaluate;
pub mod parse;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompareOp {
    Eq, // =
    Ge, // >=
    Gt, // >
    Le, // <=
    Lt, // <
}

#[derive(Debug, Clone)]
pub struct AttrReq {
    pub key: String,
    pub op: CompareOp,
    pub value: String,
}

pub type Clause = Vec<AttrReq>;

#[derive(Debug, Clone)]
pub struct Label {
    pub clauses: Vec<Clause>,
    pub always_true: bool,
}

// Cache: label_id -> Label
pub static LABEL_CACHE: LazyLock<Mutex<HashMap<i64, Label>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

// Cache: attr_name -> (level_name -> level_value)
pub static LEVELS_CACHE: LazyLock<Mutex<HashMap<String, HashMap<String, i64>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
