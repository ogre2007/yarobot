use anyhow::Result;
use std::env;

pub struct Config {
    pub db_path: String,
    pub pe_strings_file: String,
    pub relevant_extensions: Vec<String>,
}

impl Config {
    pub fn new() -> Result<Self> {
        let current_dir = env::current_dir()?;

        Ok(Self {
            db_path: current_dir.join("dbs").to_string_lossy().to_string(),
            pe_strings_file: current_dir
                .join("pestudio_strings.xml")
                .to_string_lossy()
                .to_string(),
            relevant_extensions: vec!["exe", "dll", "asp", "jsp", "php", "bin", "infected"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        })
    }
}

lazy_static::lazy_static! { pub static ref RELEVANT_EXTENSIONS: Vec<String> = vec![
    "asp", "vbs", "ps", "ps1", "tmp", "bas", "bat", "cmd", "com", "cpl", "crt", "dll", "exe",
    "msc", "scr", "sys", "vb", "vbe", "vbs", "wsc", "wsf", "wsh", "input", "war", "jsp", "php",
    "asp", "aspx", "psd1", "psm1", "py",
].iter().map(|&x| x.to_owned()).collect();
}
