use std::collections::HashMap;

use crate::args::AppArgs;

pub struct AppState {
    pub base64strings: HashMap<String, String>,
    pub reversed_strings: HashMap<String, String>,
    pub hex_enc_strings: HashMap<String, String>,
    pub pestudio_marker: HashMap<String, String>,
    pub string_scores: HashMap<String, f64>,
    pub good_strings_db: HashMap<String, u32>,
    pub good_opcodes_db: HashMap<String, u32>,
    pub good_imphashes_db: HashMap<String, u32>,
    pub good_exports_db: HashMap<String, u32>,
    pub pestudio_available: bool,
    pub pestudio_strings: HashMap<String, Vec<String>>,
    pub args: AppArgs,
    pub string_to_comms: HashMap<String, String>,
}

impl AppState {
    pub fn new(args: AppArgs) -> Self {
        Self {
            base64strings: HashMap::new(),
            reversed_strings: HashMap::new(),
            hex_enc_strings: HashMap::new(),
            pestudio_marker: HashMap::new(),
            string_scores: HashMap::new(),
            good_strings_db: HashMap::new(),
            good_opcodes_db: HashMap::new(),
            good_imphashes_db: HashMap::new(),
            good_exports_db: HashMap::new(),
            pestudio_available: false,
            pestudio_strings: HashMap::new(),
            args,
            string_to_comms: HashMap::new(),
        }
    }
}
