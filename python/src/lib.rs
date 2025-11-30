//use anyhow::Ok;
use log::info;
use pyo3::prelude::*;
use std::{cmp::min, collections::HashMap};

pub use stringzz::*; // re-exported from crates

pub mod scoring;
pub use scoring::*;

#[pyfunction]
pub fn init_analysis(
    recursive: bool,
    extensions: Option<Vec<String>>,
    minssize: usize,
    maxssize: usize,
    fsize: usize,
    get_opcodes: bool,
    debug: bool,
    excludegood: bool,
    min_score: i64,
    superrule_overlap: usize,
    good_strings_db: HashMap<String, usize>,
    good_opcodes_db: HashMap<String, usize>,
    good_imphashes_db: HashMap<String, usize>,
    good_exports_db: HashMap<String, usize>,
    pestudio_strings: HashMap<String, (i64, String)>,
) -> PyResult<(FileProcessor, ScoringEngine)> {
    let fp = FileProcessor::new(
        recursive,
        extensions,
        minssize,
        maxssize,
        fsize,
        get_opcodes,
        debug,
    );
    let scoring_engine = ScoringEngine {
        good_strings_db,
        good_opcodes_db,
        good_imphashes_db,
        good_exports_db,
        pestudio_strings,
        pestudio_marker: Default::default(),
        base64strings: Default::default(),
        hex_enc_strings: Default::default(),
        reversed_strings: Default::default(),
        excludegood,
        min_score,
        superrule_overlap,
        string_scores: Default::default(),
    };
    Ok((fp, scoring_engine))
}

#[pyfunction]
pub fn process_buffer(
    buffer: Vec<u8>,
    fp: PyRefMut<FileProcessor>,
    mut scoring_engine: PyRefMut<ScoringEngine>,
) -> PyResult<(
    HashMap<String, FileInfo>,
    HashMap<String, Vec<TokenInfo>>,
    HashMap<String, Vec<TokenInfo>>,
    HashMap<String, Vec<TokenInfo>>,
)> {
    let file_name = "data";
    let mut file_infos = HashMap::new();

    let (fi, string_stats, utf16strings, opcodes) = processing::process_buffer_u8(
        buffer[..min(fp.fsize * 1024 * 1024, buffer.len())].to_vec(),
        fp.minssize,
        fp.maxssize,
        fp.get_opcodes,
    )
    .unwrap();
    let mut file_strings = HashMap::new();
    file_strings.insert(
        file_name.to_string(),
        scoring_engine.filter_string_set(string_stats.into_values().collect())?,
    );

    let mut file_utf16strings = HashMap::new();
    file_utf16strings.insert(
        file_name.to_string(),
        scoring_engine.filter_string_set(utf16strings.into_values().collect())?,
    );
    let mut file_opcodes = HashMap::new();
    file_opcodes.insert(
        file_name.to_string(),
        scoring_engine.filter_string_set(opcodes.into_values().collect())?,
    );
    file_infos.insert(file_name.to_string(), fi);
    Ok((file_infos, file_strings, file_opcodes, file_utf16strings))
}

#[pyfunction]
pub fn process_file(
    malware_path: String,
    mut fp: FileProcessor,
    mut scoring_engine: ScoringEngine,
) -> PyResult<(
    Vec<tokens::TokenInfo>,
    Vec<tokens::TokenInfo>,
    Vec<tokens::TokenInfo>,
    HashMap<String, file_info::FileInfo>,
)> {
    info!("Processing malware file...");
    fp.process_file_with_checks(malware_path);
    let (string_stats, opcodes, utf16strings, file_infos) =
        (fp.strings, fp.opcodes, fp.utf16strings, fp.file_infos);
    let string_stats = scoring_engine.filter_string_set(string_stats.into_values().collect())?;
    let opcodes = scoring_engine.filter_opcode_set(opcodes.into_values().collect())?;
    let utf16strings = scoring_engine.filter_string_set(utf16strings.into_values().collect())?;
    Ok((string_stats, opcodes, utf16strings, file_infos))
}

#[pyfunction]
pub fn process_malware(
    malware_path: String,
    mut fp: PyRefMut<FileProcessor>,
    mut scoring_engine: PyRefMut<ScoringEngine>,
) -> PyResult<(
    HashMap<String, Combination>,
    Vec<Combination>,
    HashMap<String, Combination>,
    Vec<Combination>,
    HashMap<String, Combination>,
    Vec<Combination>,
    HashMap<String, Vec<TokenInfo>>,
    HashMap<String, Vec<TokenInfo>>,
    HashMap<String, Vec<TokenInfo>>,
    HashMap<String, FileInfo>,
)> {
    //env_logger::init();
    // Check if we should disable super rules for single files
    env_logger::init_from_env("RUST_LOG");

    info!("Processing malware files...");
    let (string_stats, opcodes, utf16strings, file_infos) =
        fp.parse_sample_dir(malware_path).unwrap();

    let (string_combis, string_superrules, file_strings) = scoring_engine
        .sample_string_evaluation(string_stats)
        .unwrap();
    let (utf16_combis, utf16_superrules, file_utf16strings) = scoring_engine
        .sample_string_evaluation(utf16strings)
        .unwrap();
    let mut file_opcodes = Default::default();
    let opcode_combis = Default::default();
    let opcode_superrules = Default::default();
    extract_stats_by_file(&opcodes, &mut file_opcodes, None, None);
    /*let (opcode_combis, opcode_superrules, file_opcodes) = scoring_engine
    .sample_string_evaluation(scoring_engine.opcodes.clone())
    .unwrap();*/
    Ok((
        string_combis,
        string_superrules,
        utf16_combis,
        utf16_superrules,
        opcode_combis,
        opcode_superrules,
        file_strings,
        file_opcodes,
        file_utf16strings,
        file_infos,
    ))
}


#[pymodule]
#[pyo3(name = "yarobot_rs")]
fn yarobot_rs(_py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(stringzz::extract_strings, m)?)?;
    m.add_function(wrap_pyfunction!(stringzz::get_file_info, m)?)?;
    m.add_function(wrap_pyfunction!(process_malware, m)?)?;
    m.add_function(wrap_pyfunction!(process_file, m)?)?;

    m.add_function(wrap_pyfunction!(stringzz::get_pe_info, m)?)?;
    m.add_function(wrap_pyfunction!(stringzz::remove_non_ascii_drop, m)?)?;
    m.add_function(wrap_pyfunction!(stringzz::is_base_64, m)?)?;
    m.add_function(wrap_pyfunction!(stringzz::is_hex_encoded, m)?)?;
    m.add_function(wrap_pyfunction!(init_analysis, m)?)?;
    m.add_function(wrap_pyfunction!(process_buffer, m)?)?;

    m.add_class::<stringzz::TokenInfo>()?;
    m.add_class::<stringzz::TokenType>()?;
    m.add_class::<stringzz::FileProcessor>()?;
    m.add_class::<ScoringEngine>()?;

    m.add_class::<Combination>()?;

    Ok(())
}
