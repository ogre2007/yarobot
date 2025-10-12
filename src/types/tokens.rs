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
    pub count: usize,
    #[pyo3(get, set)]
    pub typ: TokenType,
    #[pyo3(get, set)]
    pub files: HashSet<String>,
}

#[pymethods]
impl TokenInfo {
    #[new]
    pub fn new(count: usize, typ: TokenType, files: HashSet<String>) -> Self {
        TokenInfo { count, typ, files }
    }

    pub fn __str__(&self) -> String {
        format!(
            "TokenInfo: count={}, typ={:?}, files={:?}",
            self.count, self.typ, self.files
        )
    }

    pub fn add_file(&mut self, value: String) {
        self.files.insert(value);
    }
}