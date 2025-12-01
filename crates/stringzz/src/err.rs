use pyo3::{PyErr, PyResult};

#[derive(Debug, thiserror::Error)]
pub enum StringzzError {
    #[error("File too small: {0} bytes, minimum {1} bytes required")]
    FileTooSmall(usize, usize),

    #[error("Invalid format: {0}")]
    InvalidFormat(String),

    #[error("Parse error: {0}")]
    ParseError(#[from] Box<dyn std::error::Error>),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("PE parsing failed: {0}")]
    PeParseError(String),

    #[error("Unsupported file format")]
    UnsupportedFormat,

    #[error("Memory limit exceeded: {0}")]
    MemoryLimitExceeded(String),
}
impl From<StringzzError> for PyErr {
    fn from(err: StringzzError) -> Self {
        use pyo3::exceptions::*;
        match err {
            StringzzError::FileTooSmall(..) => PyValueError::new_err(err.to_string()),
            StringzzError::InvalidFormat(..) => PyValueError::new_err(err.to_string()),
            StringzzError::IoError(..) => PyIOError::new_err(err.to_string()),
            StringzzError::PeParseError(..) => PyRuntimeError::new_err(err.to_string()),
            _ => PyRuntimeError::new_err(err.to_string()),
        }
    }
}

// Helper trait for easy conversion
pub trait ToPyResult<T> {
    fn to_py_result(self) -> PyResult<T>;
}

impl<T> ToPyResult<T> for Result<T, StringzzError> {
    fn to_py_result(self) -> PyResult<T> {
        self.map_err(|e| e.into())
    }
}
