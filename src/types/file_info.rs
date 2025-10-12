use pyo3::prelude::*;
use sha2::{Digest, Sha256};

use crate::get_pe_info;

#[pyclass]
#[derive(Debug, Clone, Default)]
pub struct FileInfo {
    #[pyo3(get, set)]
    pub imphash: String,
    #[pyo3(get, set)]
    pub exports: Vec<String>,
    #[pyo3(get, set)]
    pub sha256: String,
    #[pyo3(get, set)]
    pub size: usize,
    #[pyo3(get, set)]
    pub magic: [u8; 4],
}

#[pymethods]
impl FileInfo {
    pub fn __str__(&self) -> String {
        format!(
            "FileInfo: imphash={}, exports={:?}, sha256={:?}",
            self.imphash, self.exports, self.sha256
        )
    }
}

#[pyfunction]
pub fn get_file_info(file_data: &[u8]) -> PyResult<FileInfo> {
    let mut hasher = Sha256::new();
    hasher.update(file_data);
    let mut fi = FileInfo {
        sha256: hex::encode(hasher.finalize()),
        imphash: Default::default(),
        exports: Default::default(),
        size: file_data.len(),
        magic: file_data[0..4].try_into().unwrap(),
    };
    if fi.magic[0..2] == *b"MZ" {
        get_pe_info(file_data, &mut fi);
    }
    Ok(fi)
}
