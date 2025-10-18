use crate::{is_ascii_string, is_base_64, is_hex_encoded, score_with_regex, TokenInfo};
use base64;
use log::{debug, error, info, trace};
use pyo3::exceptions::PyValueError;
use pyo3::ffi::PyErr_BadArgument;
use pyo3::prelude::*;
use pyo3::{
    types::{PyAnyMethods, PyDict, PyList, PyTuple},
    Py, PyAny, Python,
};
use regex::Regex;
use std::{
    collections::{HashMap, HashSet},
    usize,
};

#[pyclass]
#[derive(Debug)]

pub struct ScoringEngine {
    #[pyo3(get, set)]
    pub good_strings_db: HashMap<String, usize>,
    #[pyo3(get, set)]
    pub good_opcodes_db: HashMap<String, usize>,
    #[pyo3(get, set)]
    pub utf16strings: HashMap<String, TokenInfo>,
    #[pyo3(get, set)]
    pub pestudio_strings: HashMap<String, (i64, String)>,
    #[pyo3(get, set)]
    pub pestudio_marker: HashMap<String, String>,
    #[pyo3(get, set)]
    pub base64strings: HashMap<String, String>,
    #[pyo3(get, set)]
    pub hex_enc_strings: HashMap<String, String>,
    #[pyo3(get, set)]
    pub reversed_strings: HashMap<String, String>,
    #[pyo3(get, set)]
    pub string_scores: HashMap<String, TokenInfo>,
    #[pyo3(get, set)]
    pub opcodes: HashMap<String, TokenInfo>,
    #[pyo3(get, set)]
    pub excludegood: bool,
    #[pyo3(get, set)]
    pub min_score: i64,
    #[pyo3(get, set)]
    pub superrule_overlap: usize,
}

#[pyclass]
#[derive(Debug, Clone)]
pub struct Combination {
    #[pyo3(get, set)]
    pub count: usize,
    #[pyo3(get, set)]
    pub strings: Vec<TokenInfo>,
    #[pyo3(get, set)]
    pub files: HashSet<String>,
}

// External functions that would be implemented elsewhere
pub fn get_pestudio_score(
    string: &str,
    pestudio_strings: &HashMap<String, (i64, String)>,
) -> (i64, String) {
    // Implementation would go here
    pestudio_strings
        .get(string)
        .cloned()
        .unwrap_or((0, String::new()))
}

pub fn get_opcode_string(opcode: &str) -> String {
    let reprz = opcode; // Assuming opcode is already the reprz
    (0..reprz.len())
        .step_by(2)
        .map(|i| {
            if i + 2 <= reprz.len() {
                &reprz[i..i + 2]
            } else {
                &reprz[i..]
            }
        })
        .collect::<Vec<&str>>()
        .join(" ")
}
pub fn find_combinations(
    stats: &HashMap<String, TokenInfo>,
) -> PyResult<(HashMap<String, Combination>, usize)> {
    let mut combinations = HashMap::new();
    let mut max_combi_count = 0;

    for (token, info) in stats {
        if info.files.len() > 1 {
            debug!(
                "OVERLAP Count: {}\nString: \"{}\"\nFILE: {}",
                info.count,
                token,
                info.files
                    .clone()
                    .into_iter()
                    .collect::<Vec<String>>()
                    .join(", ")
            );

            let mut sorted_files: Vec<String> = info.files.clone().into_iter().collect();
            sorted_files.sort();
            let combi = sorted_files.join(":");

            debug!("COMBI: {}", combi);

            let combo_entry = combinations
                .entry(combi.clone())
                .or_insert_with(|| Combination {
                    count: 0,
                    strings: Vec::new(),
                    files: info.files.clone(),
                });

            combo_entry.count += 1;
            combo_entry.strings.push(info.clone());

            if combo_entry.count > max_combi_count {
                max_combi_count = combo_entry.count;
            }
        }
    }

    Ok((combinations, max_combi_count))
}
pub fn extract_stats_by_file<'a>(
    stats: &HashMap<String, TokenInfo>,
    outer_dict: &'a mut HashMap<String, Vec<TokenInfo>>,
    min: Option<usize>,
    max: Option<usize>,
) {
    for (token, value) in stats {
        let count = value.count;
        if count >= min.unwrap_or(0) && count < max.unwrap_or(usize::MAX) {
            debug!(
                " [-] Adding {} ({:?}) to {} files.",
                token,
                value,
                value.files.len()
            );
            for file_path in &value.files {
                outer_dict
                    .entry(file_path.to_string())
                    .or_insert(Vec::new())
                    .push(value.clone());
            }
        }
    }
}

#[pymethods]
impl ScoringEngine {
    pub fn filter_opcode_set(&self, opcode_set: Vec<String>) -> PyResult<Vec<String>> {
        let pref_opcodes = vec![" 34 ", "ff ff ff "];
        let mut useful_set = Vec::new();
        let mut pref_set = Vec::new();

        for opcode in opcode_set {
            if self.good_opcodes_db.contains_key(&opcode) {
                debug!("skipping {}", opcode);

                continue;
            }

            let formatted_opcode = get_opcode_string(&opcode);
            let mut set_in_pref = false;

            for pref in &pref_opcodes {
                if formatted_opcode.contains(pref) {
                    pref_set.push(formatted_opcode.clone());
                    set_in_pref = true;
                    break;
                }
            }

            if !set_in_pref {
                useful_set.push(formatted_opcode);
            }
        }

        // Preferred opcodes first
        pref_set.append(&mut useful_set);
        Ok(pref_set)
    }
    pub fn filter_string_set(&mut self, tokens: Vec<TokenInfo>) -> PyResult<Vec<TokenInfo>> {
        if tokens.is_empty() {
            panic!();
        }

        let mut local_string_scores = Vec::new();

        for mut token in tokens {
            if token.reprz.is_empty() {
                println!("{:?}", token);
                panic!("empty token");
            }

            let mut goodstring = false;
            let mut goodcount = 0;

            // Goodware string marker
            if let Some(&count) = self.good_strings_db.get(&token.reprz) {
                goodstring = true;
                goodcount = count;
                if self.excludegood {
                    continue;
                }
            }

            let original_string = token.reprz.clone();

            // Good string evaluation
            if goodstring {
                token.score += (goodcount as i64 * -1) + 5;
            }

            // PEStudio String Blacklist Evaluation
            let (pescore, type_str) = get_pestudio_score(&token.reprz, &self.pestudio_strings);
            if !type_str.is_empty() {
                self.pestudio_marker.insert(token.reprz.clone(), type_str);
                if goodstring {
                    let adjusted_pescore = pescore - (goodcount as f64 / 1000.0) as i64;
                    token.score = adjusted_pescore;
                } else {
                    token.score = pescore;
                }
            }

            if !goodstring {
                info!("before heur: {}", token.score);

                score_with_regex(&mut token);
                // Encoding detections
                if token.reprz.len() > 8 {
                    // Base64 detection
                    debug!("Starting Base64 string analysis ...");
                    let test_strings = vec![
                        token.reprz.clone(),
                        token.reprz[1..].to_string(),
                        token.reprz[..token.reprz.len() - 1].to_string(),
                        format!("{}=", &token.reprz[1..]),
                        format!("{}=", &token.reprz),
                        format!("{}==", &token.reprz),
                    ];

                    for test_str in test_strings {
                        if is_base_64(test_str.clone()).unwrap() {
                            if let Ok(decoded_bytes) = base64::decode(test_str.clone().as_bytes()) {
                                if is_ascii_string(&decoded_bytes, true).unwrap() {
                                    token.score += 10;
                                    self.base64strings.insert(
                                        token.reprz.clone(),
                                        String::from_utf8_lossy(&decoded_bytes).to_string(),
                                    );
                                }
                            }
                        }
                    }

                    // Hex encoded string detection
                    debug!("Starting Hex encoded string analysis ...");
                    let cleaned_str = token
                        .reprz
                        .chars()
                        .filter(|c| c.is_ascii_alphanumeric())
                        .collect::<String>();
                    let hex_test_strings = vec![token.reprz.clone(), cleaned_str];

                    for test_str in hex_test_strings {
                        if is_hex_encoded(test_str.clone(), true).unwrap() {
                            if let Ok(decoded_bytes) = hex::decode(&test_str) {
                                if is_ascii_string(&decoded_bytes, true).unwrap() {
                                    // Not too many 00s
                                    if test_str.contains("00") {
                                        let zero_ratio = test_str.len() as f64
                                            / test_str.matches('0').count() as f64;
                                        if zero_ratio <= 1.2 {
                                            continue;
                                        }
                                    }
                                    token.score += 8;
                                    self.hex_enc_strings.insert(
                                        token.reprz.clone(),
                                        String::from_utf8_lossy(&decoded_bytes).to_string(),
                                    );
                                }
                            }
                        }
                    }
                }

                // Reversed String
                let reversed = token.reprz.chars().rev().collect::<String>();
                if self.good_strings_db.contains_key(&reversed) {
                    token.score += 10;
                    self.reversed_strings.insert(token.reprz.clone(), reversed);
                }

                // Certain string reduce
                let reduce_regex = Regex::new(r"(?i)(rundll32\.exe$|kernel\.dll$)").unwrap();
                if reduce_regex.is_match(&token.reprz) {
                    token.score -= 4;
                }
            }

            self.string_scores
                .insert(original_string.clone(), token.clone());
            local_string_scores.push(token);
        }

        // Sort by score descending
        local_string_scores.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap());

        // Filter by threshold and collect results
        let threshold: i64 = self.min_score;
        let mut result_set = Vec::new();

        for token in local_string_scores {
            debug!("TOP STRINGS: {} {}", token.reprz, token.score);

            if token.score < threshold {
                continue;
            }

            result_set.push(token);
        }

        debug!("RESULT SET: {:?}", result_set);

        Ok(result_set)
    }

    pub fn sample_string_evaluation(
        &mut self,
    ) -> PyResult<(
        HashMap<String, Combination>,
        Vec<Combination>,
        HashMap<String, Vec<TokenInfo>>,
        HashMap<String, Vec<TokenInfo>>,
        HashMap<String, Vec<TokenInfo>>,
    )> {
        info!("[+] Generating statistical data ...");
        info!("\t[INPUT] Strings: {}", self.string_scores.len());
        let mut file_strings = HashMap::new();
        let mut file_utf16strings = HashMap::new();

        let mut file_opcodes = HashMap::new();

        extract_stats_by_file(&self.string_scores, &mut file_strings, Some(0), Some(10));

        //STRING EVALUATION -------------------------------------------------------
        extract_stats_by_file(&self.opcodes, &mut file_opcodes, None, None);

        extract_stats_by_file(&self.utf16strings, &mut file_utf16strings, None, None);
        let (mut combinations, max_combi_count) = find_combinations(&self.string_scores).unwrap();

        info!("[+] Generating Super Rules ... (a lot of magic)");
        let mut super_rules = Vec::new();
        let min_strings: usize = self.superrule_overlap;

        for combi_count in (2..=max_combi_count).rev() {
            for (combi_key, combo) in combinations.iter_mut() {
                if combo.count == combi_count {
                    // Convert FileStats to Tokens for filtering
                    let tokens: Vec<TokenInfo> = combo.strings.clone();
                    debug!("calling filter with combo strings...");
                    let filtered_strings = self.filter_string_set(tokens)?;
                    combo.strings = filtered_strings;
                    if combo.strings.len() >= min_strings {
                        // Remove files from file_strings if provided
                        for file in &combo.files {
                            file_strings.remove(&file.clone());
                        }
                    }

                    info!(
                        "[-] Adding Super Rule with {} strings.",
                        combo.strings.len()
                    );
                    let mut new_combo = combo.clone();
                    // Store the filtered strings - you might need to adjust this based on your data structure
                    super_rules.push(new_combo);
                }
            }
        }
        info!("OUTPUT: {} super rules", super_rules.len());

        Ok((
            combinations,
            super_rules,
            file_strings,
            file_opcodes,
            file_utf16strings,
        ))
    }
}
