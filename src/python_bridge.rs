use anyhow::Result;
use pyo3::prelude::*;

use crate::args::AppArgs;

pub fn update_databases(args: &AppArgs) -> Result<()> {
    Python::with_gil(|py| {
        let update_func = py.import("app.main")?.getattr("update_databases")?;
        update_func.call1((convert_args_to_py(py, args)?,))?;
        Ok(())
    })
}

fn convert_args_to_py(py: Python, args: &AppArgs) -> Result<PyObject> {
    // This would create a Python object that mimics the args structure
    // For simplicity, we're passing essential parameters
    let dict = pyo3::types::PyDict::new(py);

    if let Some(ref m) = args.m {
        dict.set_item("m", m)?;
    }
    dict.set_item("y", args.y)?;
    dict.set_item("z", args.z)?;
    // ... set all other arguments

    Ok(dict.into())
}
