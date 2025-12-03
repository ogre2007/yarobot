use std::{collections::HashMap, fs};

use pyo3::{Py, Python};
use stringzz::Config;
use yarobot_rs::{
    extract_and_count_ascii_strings, extract_dex_opcodes, init_analysis, process_malware,
};

// tests/integration_test.rs
#[test]
fn test_integr() {
    let malware_path = String::from("tests\\data\\");
    let excludegood = false;
    let min_score = 10;
    let superrule_overlap = 5;

    // Empty HashMaps for testing
    let good_strings_db: HashMap<String, usize> = HashMap::new();
    let good_opcodes_db: HashMap<String, usize> = HashMap::new();
    let good_imphashes_db: HashMap<String, usize> = HashMap::new();
    let good_exports_db: HashMap<String, usize> = HashMap::new();
    let pestudio_strings: HashMap<String, (i64, String)> = HashMap::new();
    let (fp, se) = init_analysis(
        Some(Config::default()),
        excludegood,
        min_score,
        superrule_overlap,
        Some(good_strings_db),
        Some(good_opcodes_db),
        Some(good_imphashes_db),
        Some(good_exports_db),
        Some(pestudio_strings),
    )
    .unwrap();
    pyo3::prepare_freethreaded_python();
    Python::with_gil(|py| {
        let _ = process_malware(
            malware_path,
            Py::new(py, fp).unwrap().borrow_mut(py),
            Py::new(py, se).unwrap().borrow_mut(py),
        );
    });
}

#[test]
fn test_dex() {
    let fdata = fs::read("tests\\data\\classes.dex").unwrap();
    let opcodes = extract_dex_opcodes(fdata.clone()).unwrap();
    let _strings = extract_and_count_ascii_strings(&fdata, 5, 128);
    //println!("{:?}", strings);
    assert!(opcodes.iter().len() > 0);
}
