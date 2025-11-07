use crate::{
    is_ascii_string, is_base_64, is_hex_encoded, remove_non_ascii_drop, score_with_regex,
    TokenInfo, TokenType,
};
use base64;
use log::{debug, info, warn};
use pyo3::prelude::*;
use std::{
    collections::{HashMap, HashSet},
    usize,
};

#[pyclass]
#[derive(Debug, Clone)]
pub struct ScoringEngine {
    #[pyo3(get, set)]
    pub good_strings_db: HashMap<String, usize>,
    #[pyo3(get, set)]
    pub good_imphashes_db: HashMap<String, usize>,
    #[pyo3(get, set)]
    pub good_exports_db: HashMap<String, usize>,
    #[pyo3(get, set)]
    pub string_scores: HashMap<String, TokenInfo>,

    #[pyo3(get, set)]
    pub good_opcodes_db: HashMap<String, usize>,
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
    let tuple = (&"".to_string(), &(0 as i64, "".to_string())); // Implementation would go here
    pestudio_strings
        .iter()
        .find(|(&ref x, &ref y)| x.to_lowercase() == string.to_lowercase())
        .unwrap_or(tuple)
        .1
        .clone()
}

pub fn get_opcode_string(opcode: &mut TokenInfo) {
    let reprz = opcode.reprz.clone(); // Assuming opcode is already the reprz
    opcode.reprz = (0..reprz.len())
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
            /*debug!(
                "OVERLAP Count: {}\nString: \"{}\"\nFILE: {}",
                info.count,
                token,
                info.files
                    .clone()
                    .into_iter()
                    .collect::<Vec<String>>()
                    .join(", ")
            );*/

            let mut sorted_files: Vec<String> = info.files.clone().into_iter().collect();
            sorted_files.sort();
            let combi = sorted_files.join(":");

            //debug!("COMBI: {}", combi);

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
            /*debug!(
                " [-] Adding {} ({:?}) to {} files.",
                token,
                value,
                value.files.len()
            );*/
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
    pub fn generate_rule_strings(
        &self,
        score: bool,
        high_scoring: f64,
        strings_per_rule: usize,
        mut string_elements: Vec<TokenInfo>,
    ) -> PyResult<(Vec<String>, usize)> {
        let mut rule_strings = Vec::new();
        string_elements.sort_by(|a, b| b.score.cmp(&a.score));

        let mut high_scoring_strings = 0;
        let mut i = 0;
        for stringe in string_elements.iter_mut() {
            let string = stringe.reprz.clone();
            if self.good_strings_db.contains_key(&string) {
                stringe.add_note(format!(
                    "goodware string - occured {} times",
                    self.good_strings_db[&string]
                ));
            }
            if score {
                stringe.add_note(format!(" / score: {} /", stringe.score));
            } else {
                //logging.getLogger("yarobot").debug("NO SCORE: %s", string)
            }

            if stringe.b64 {
                stringe.add_note(format!(
                    " / base64 encoded string '{}' /",
                    self.base64strings[&string]
                ));
            }
            if stringe.hexed {
                stringe.add_note(format!(
                    " / hex encoded string '{}' /",
                    remove_non_ascii_drop(self.hex_enc_strings[&string].as_bytes()).unwrap()
                ));
            }
            if stringe.from_pestudio && score {
                stringe.add_note(format!(
                    " / PEStudio Blacklist: {} /",
                    self.pestudio_marker[&string]
                ));
            }
            if stringe.reversed {
                stringe.add_note(format!(
                    " / reversed goodware string '{}' /",
                    self.reversed_strings[&string]
                ));
            }

            let is_super_string = stringe.score as f64 > high_scoring;
            if is_super_string {
                high_scoring_strings += 1;
            }
            rule_strings.push(stringe.generate_string_repr(i, is_super_string));

            if i + 1 >= strings_per_rule.try_into().unwrap() {
                break;
            }
            i += 1;
        }
        /*




        */
        Ok((rule_strings, high_scoring_strings))
    }

    pub fn filter_opcode_set(&self, mut opcode_set: Vec<TokenInfo>) -> PyResult<Vec<TokenInfo>> {
        let pref_opcodes = vec![" 34 ", "ff ff ff "];
        let mut useful_set = Vec::new();
        let mut pref_set = Vec::new();

        for opcode in opcode_set.iter_mut() {
            if self.good_opcodes_db.contains_key(&opcode.reprz) {
                //debug!("skipping {}", opcode.reprz);

                continue;
            }

            get_opcode_string(opcode);
            let mut set_in_pref = false;

            for pref in &pref_opcodes {
                if opcode.reprz.contains(pref) {
                    pref_set.push(opcode.clone());
                    set_in_pref = true;
                    break;
                }
            }

            if !set_in_pref {
                useful_set.push(opcode.clone());
            }
        }

        // Preferred opcodes first
        pref_set.append(&mut useful_set);
        Ok(pref_set)
    }

    pub fn clear_context(&mut self) {
        (
            self.string_scores,
            self.base64strings,
            self.hex_enc_strings,
            self.base64strings,
            self.reversed_strings,
        ) = Default::default();
    }

    pub fn filter_string_set(&mut self, tokens: Vec<TokenInfo>) -> PyResult<Vec<TokenInfo>> {
        if tokens.is_empty() {
            //panic!();
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
                warn!("PESTUDIO_STR: {}-{}-{}", &token.reprz, pescore, type_str);
                self.pestudio_marker.insert(token.reprz.clone(), type_str);
                token.from_pestudio = true;
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
                    //debug!("Starting Base64 string analysis ...");
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
                                    token.b64 = true;
                                }
                            }
                        }
                    }

                    // Hex encoded string detection
                    //debug!("Starting Hex encoded string analysis ...");
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
                                    token.hexed = true;
                                    token.fullword = false;
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
                    token.reversed = true;
                }

                // Certain string reduce
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
            //debug!("TOP STRINGS: {} {}", token.reprz, token.score);

            if token.score < threshold {
                continue;
            }

            result_set.push(token);
        }

        //debug!("RESULT SET: {:?}", result_set);

        Ok(result_set)
    }

    pub fn sample_string_evaluation(
        &mut self,
        token_stats: HashMap<String, TokenInfo>,
    ) -> PyResult<(
        HashMap<String, Combination>,
        Vec<Combination>,
        HashMap<String, Vec<TokenInfo>>,
    )> {
        println!("[+] Generating statistical data ...");
        println!("\t[INPUT] Strings: {}", token_stats.len());
        let mut file_tokens = HashMap::new();
        let min = Some(0);
        let max = Some(20);
        extract_stats_by_file(&token_stats, &mut file_tokens, min, max);

        let (mut combinations, max_combi_count) = find_combinations(&token_stats).unwrap();

        info!("[+] Generating Super Rules ... (a lot of magic)");
        let mut super_rules = Vec::new();
        let min_strings: usize = self.superrule_overlap;

        for combi_count in (2..=max_combi_count).rev() {
            for (combi_key, combo) in combinations.iter_mut() {
                if combo.count == combi_count {
                    // Convert FileStats to Tokens for filtering
                    let tokens: Vec<TokenInfo> = combo.strings.clone();
                    //debug!("calling filter with combo strings...");

                    let filtered_strings = match tokens[0].typ {
                        TokenType::ASCII => self.filter_string_set(tokens)?,
                        TokenType::UTF16LE => self.filter_string_set(tokens)?,
                        TokenType::BINARY => self.filter_opcode_set(tokens)?,
                    };

                    combo.strings = filtered_strings;
                    if combo.strings.len() >= min_strings {
                        // Remove files from file_strings if provided
                        for file in &combo.files {
                            file_tokens.remove(&file.clone());
                        }
                        info!(
                            "[-] Adding Super Rule with {} strings.",
                            combo.strings.len()
                        );
                        let new_combo = combo.clone();
                        // Store the filtered strings - you might need to adjust this based on your data structure
                        super_rules.push(new_combo);
                    }
                }
            }
        }
        info!("OUTPUT: {} super rules", super_rules.len());

        Ok((combinations, super_rules, file_tokens))
    }
}
