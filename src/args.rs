use clap::{arg, command, ArgGroup, Parser, ValueHint};
use std::path::PathBuf;

#[derive(Parser, Debug, Clone)]
#[command(
    name = "yarobot",
    about = "YARA rule generator",
    version,
    group(
        ArgGroup::new("mode")
            .args(["m", "g", "update"])
            .required(true)
            .multiple(false)
    )
)]
pub struct AppArgs {
    /// Path to scan for malware
    #[arg(short = 'm', value_hint = ValueHint::DirPath)]
    pub m: Option<PathBuf>,

    /// Minimum string length to consider (default=8)
    #[arg(short = 'y', default_value = "8")]
    pub y: usize,

    /// Minimum score to consider (default=5)
    #[arg(short = 'z', default_value = "5")]
    pub z: i32,

    /// Score required to set string as 'highly specific string' (default: 30)
    #[arg(short = 'x', default_value = "30")]
    pub x: i32,

    /// Minimum number of strings that overlap to create a super rule (default: 5)
    #[arg(short = 'w', default_value = "5")]
    pub w: usize,

    /// Maximum length to consider (default=128)
    #[arg(short = 's', default_value = "128")]
    pub s: usize,

    /// Maximum number of strings per rule (default=20, intelligent filtering will be applied)
    #[arg(long = "rc", default_value = "20")]
    pub rc: usize,

    /// Force the exclude all goodware strings
    #[arg(long = "excludegood")]
    pub excludegood: bool,

    /// Output rule file
    #[arg(short = 'o', default_value = "yarobot_rules.yar")]
    pub o: PathBuf,

    /// Output directory for string exports
    #[arg(short = 'e', value_hint = ValueHint::DirPath)]
    pub e: Option<PathBuf>,

    /// Author Name
    #[arg(short = 'a', default_value = "yarobot Rule Generator")]
    pub a: String,

    /// Reference (can be string or text file)
    #[arg(long = "ref", default_value = "https://github.com/oogre2007/yarobot")]
    pub ref_: String,

    /// License
    #[arg(short = 'l')]
    pub l: Option<String>,

    /// Prefix for the rule description
    #[arg(short = 'p', default_value = "Auto-generated rule")]
    pub p: String,

    /// Text file from which the identifier is read
    #[arg(short = 'b', default_value = "not set")]
    pub b: String,

    /// Show the string scores as comments in the rules
    #[arg(long = "score")]
    pub score: bool,

    /// Show the string scores as comments in the rules
    #[arg(long = "strings")]
    pub strings: bool,

    /// Skip simple rule creation for files included in super rules
    #[arg(long = "nosimple")]
    pub nosimple: bool,

    /// Don't include the magic header condition statement
    #[arg(long = "nomagic")]
    pub nomagic: bool,

    /// Don't include the filesize condition statement
    #[arg(long = "nofilesize")]
    pub nofilesize: bool,

    /// Multiplier for the maximum 'filesize' condition value (default: 3)
    #[arg(long = "fm", default_value = "3")]
    pub fm: i32,

    /// Create global rules (improved rule set speed)
    #[arg(long = "globalrule")]
    pub globalrule: bool,

    /// Don't try to create super rules that match against various files
    #[arg(long = "nosuper")]
    pub nosuper: bool,

    /// Update the local strings and opcodes dbs from the online repository
    #[arg(long = "update")]
    pub update: bool,

    /// Path to scan for goodware (dont use the database shipped with yaraGen)
    #[arg(short = 'g', value_hint = ValueHint::DirPath)]
    pub g: Option<PathBuf>,

    /// Update local standard goodware database with a new analysis result (used with -g)
    #[arg(short = 'u')]
    pub u: bool,

    /// Create new local goodware database (use with -g and optionally -i "identifier")
    #[arg(short = 'c')]
    pub c: bool,

    /// Specify an identifier for the newly created databases
    #[arg(short = 'i')]
    pub i: Option<String>,

    /// Dropzone mode - monitors a directory [-m] for new samples to process. WARNING: Processed files will be deleted!
    #[arg(long = "dropzone")]
    pub dropzone: bool,

    /// Recursively scan directories
    #[arg(short = 'R')]
    pub R: bool,

    /// Only scan executable extensions EXE, DLL, ASP, JSP, PHP, BIN, INFECTED
    #[arg(long = "oe")]
    pub oe: bool,

    /// Max file size in MB to analyze (default=10)
    #[arg(long = "fs", default_value = "10")]
    pub fs: usize,

    /// Don't use extras like Imphash or PE header specifics
    #[arg(long = "noextras")]
    pub noextras: bool,

    /// Debug output
    #[arg(long = "debug")]
    pub debug: bool,

    /// Trace output
    #[arg(long = "trace")]
    pub trace: bool,

    /// Do use the OpCode feature (use this if not enough high scoring strings can be found)
    #[arg(long = "opcodes")]
    pub opcodes: bool,

    /// Number of opcodes to add if not enough high scoring string could be found (default=3)
    #[arg(short = 'n', default_value = "3")]
    pub n: i32,
}

impl AppArgs {
    /// Get identifier based on path or file content
    pub fn get_identifier(&self, path: &PathBuf) -> String {
        if self.b == "not set" || !PathBuf::from(&self.b).exists() {
            path.file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("unknown")
                .to_string()
        } else {
            std::fs::read_to_string(&self.b)
                .unwrap_or_else(|_| "unknown".to_string())
                .trim()
                .to_string()
        }
    }

    /// Get reference, reading from file if path exists
    pub fn get_reference(&self) -> String {
        let ref_path = PathBuf::from(&self.ref_);
        if ref_path.exists() {
            std::fs::read_to_string(&ref_path)
                .unwrap_or_else(|_| self.ref_.clone())
                .trim()
                .to_string()
        } else {
            self.ref_.clone()
        }
    }

    /// Get prefix for rule description
    pub fn get_prefix(&self, identifier: &str) -> String {
        if self.p == "Auto-generated rule" {
            identifier.to_string()
        } else {
            self.p.clone()
        }
    }
}
