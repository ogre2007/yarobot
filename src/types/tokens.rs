use std::collections::HashSet;

use pyo3::prelude::*;

#[pyclass]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TokenType {
    #[default]
    ASCII,
    UTF16LE,
    BINARY,
}

#[pymethods]
impl TokenType {
    fn __eq__(&self, val: &TokenType) -> bool {
        self == val
    }
}

#[pyclass]
#[derive(Debug, Clone, Default)]
pub struct TokenInfo {
    #[pyo3(get, set)]
    pub reprz: String,
    #[pyo3(get, set)]
    pub count: usize,
    #[pyo3(get, set)]
    pub typ: TokenType,
    #[pyo3(get, set)]
    pub files: HashSet<String>,
    #[pyo3(get, set)]
    pub notes: String,
    #[pyo3(get, set)]
    pub score: i64,
}

#[pymethods]
impl TokenInfo {
    #[new]
    pub fn new(
        reprz: String,
        count: usize,
        typ: TokenType,
        files: HashSet<String>,
        notes: Option<String>,
    ) -> Self {
        if reprz.len() == 0 {
            panic!()
        }
        TokenInfo {
            reprz,
            count,
            typ,
            files,
            notes: notes.unwrap_or_default(),
            score: Default::default(),
        }
    }

    pub fn __str__(&self) -> String {
        format!(
            "TokenInfo: reprz={:?}, score={}, count={}, typ={:?}, files={:?}",
            self.reprz, self.score, self.count, self.typ, self.files
        )
    }

    pub fn merge(&mut self, value: &Self) {
        self.count += value.count;
        self.files.extend(value.files.clone());
        self.reprz = value.reprz.clone();
        self.notes += &value.notes;
        self.score += value.score;
    }

    pub fn add_file(&mut self, value: String) {
        self.files.insert(value);
    }

    pub fn add_note(&mut self, value: String) {
        self.notes += &format!(", {}", value);
    }
}
