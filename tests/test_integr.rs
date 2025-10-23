use std::collections::HashMap;

use yarobot_rs::process_malware;

// tests/integration_test.rs
#[test]
fn test_integr() {
    let malware_path = String::from("..\\quiling\\qiling\\examples\\rootfs\\x8664_windows\\");
    let recursive = true;
    let extensions = None;
    let minssize = 10;
    let maxssize = 100;
    let fsize: usize = 10;
    let get_opcodes = true;
    let debug: bool = true;
    let excludegood = false;
    let min_score = 10;
    let superrule_overlap = 5;

    // Empty HashMaps for testing
    let good_strings_db: HashMap<String, usize> = HashMap::new();
    let good_opcodes_db: HashMap<String, usize> = HashMap::new();
    let good_imphashes_db: HashMap<String, usize> = HashMap::new();
    let good_exports_db: HashMap<String, usize> = HashMap::new();
    let pestudio_strings: HashMap<String, (i64, String)> = HashMap::new();

    // Call the function with all requircaed arguments
    let result = process_malware(
        malware_path,
        recursive,
        extensions,
        minssize,
        maxssize,
        fsize,
        get_opcodes,
        debug,
        excludegood,
        min_score,
        superrule_overlap,
        good_strings_db,
        good_opcodes_db,
        good_imphashes_db,
        good_exports_db,
        pestudio_strings,
    );
}
