pub mod parsing;
pub use parsing::*;

pub mod types;
pub use types::*;

pub mod processing;
pub use processing::*;

use pyo3::{
    pymodule,
    types::{PyModule, PyModuleMethods},
    wrap_pyfunction, Bound, PyResult, Python,
};

#[pymodule]
#[pyo3(name = "stringzz")]
fn stringzz(_py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(extract_strings, m)?)?;
    m.add_function(wrap_pyfunction!(get_file_info, m)?)?;

    m.add_function(wrap_pyfunction!(get_pe_info, m)?)?;
    m.add_function(wrap_pyfunction!(remove_non_ascii_drop, m)?)?;
    m.add_function(wrap_pyfunction!(is_base_64, m)?)?;
    m.add_function(wrap_pyfunction!(is_hex_encoded, m)?)?;

    m.add_class::<types::TokenInfo>()?;
    m.add_class::<types::TokenType>()?;

    Ok(())
}
