use anyhow::{Context, Result};
use clap::Parser;
use flate2::read::GzDecoder;
use log::{debug, info, warn};
use log::{logger, LevelFilter};
use pyo3::{Py, PyAny, PyResult, Python};
use std::collections::HashMap;
use std::collections::HashSet;
use std::fmt::Debug;
use std::fs;
use std::fs::read_dir;
use std::io::Read;
use std::path::Path;
use std::process;
use yarobot_rs::FileProcessor;
use yarobot_rs::TokenInfo;

mod args;
mod config;
mod python_bridge;
mod state;

use args::AppArgs;
use config::Config;
use config::RELEVANT_EXTENSIONS;
use python_bridge::*;
use state::AppState;

use pyo3::types::{PyAnyMethods, PyList, PyListMethods, PyModule};
use pyo3_ffi::c_str;
use std::ffi::CString;

fn main() -> Result<()> {
    env_logger::builder().filter_level(LevelFilter::Info).init();
    let args = AppArgs::parse();

    if let Err(e) = run_app(args) {
        eprintln!("Error: {}", e);
        process::exit(1);
    }

    Ok(())
}
fn run_python() {
    let path = Path::new(".");
    let py_app =
        CString::new(fs::read_to_string(path.join("app").join("main.py")).unwrap()).unwrap();
    let from_python = Python::with_gil(|py| -> PyResult<Py<PyAny>> {
        let syspath = py
            .import("sys")?
            .getattr("path")?
            .downcast_into::<PyList>()?;
        syspath.insert(0, path)?;
        let app: Py<PyAny> =
            PyModule::from_code(py, py_app.as_c_str(), c_str!("app.py"), c_str!(""))?
                .getattr("run")?
                .into();
        app.call0(py)
    });
    println!("py: {}", from_python.unwrap());
}

fn run_app(args: AppArgs) -> Result<()> {
    let config = Config::new()?;

    // Handle database update
    if args.update {
        todo!();
        info!("Updated databases - you can now start creating YARA rules");
        return Ok(());
    }

    let (good_strings, good_opcodes, good_exports, good_imphashes) = load_databases("dbs").unwrap();
    // Validate input
    if let Some(ref malware_path) = args.m {
        if malware_path.is_file() {
            anyhow::bail!("Input is a file, please use a directory instead (-m path)");
        }
    }

    // Process goodware if specified
    if let Some(ref goodware_path) = args.g {
        process_goodware(&args, goodware_path)?;
    }

    // Process malware if specified
    if let Some(ref malware_path) = args.m {
        process_malware(&args, malware_path)?;
    }

    Ok(())
}

fn process_goodware(args: &AppArgs, goodware_path: &Path) -> Result<()> {
    info!("Processing goodware files...");
    let mut fp = yarobot_rs::FileProcessor::new(
        args.R,
        args.oe,
        RELEVANT_EXTENSIONS.to_vec(),
        args.y,
        args.s,
        args.fs,
        args.opcodes,
        args.debug,
    );
    let (good_strings_db, good_opcodes_db, good_imphashes_db, good_exports_db) =
        fp.parse_sample_dir(goodware_path.to_str().unwrap().to_owned())?;

    // Handle database operations
    if args.u {
        update_databases(args, &good_strings_db, &good_opcodes_db, &good_imphashes_db);
        //, &good_exports_db)?;
    }

    if args.c {
        create_databases(args, &good_strings_db, &good_opcodes_db, &good_imphashes_db);
        //, &good_exports_db)?;
    }

    Ok(())
}

fn process_malware(args: &AppArgs, malware_path: &Path) -> Result<()> {
    // Check if we should disable super rules for single files
    let mut final_args = args.clone();
    if let Ok(entries) = fs::read_dir(malware_path) {
        if entries.count() < 2 {
            final_args.nosuper = true;
        }
    }
    let mut fp = yarobot_rs::FileProcessor::new(
        args.R,
        args.oe,
        RELEVANT_EXTENSIONS.to_vec(),
        args.y,
        args.s,
        args.fs,
        args.opcodes,
        args.debug,
    );
    if final_args.dropzone {
        run_dropzone_mode(&mut fp, &final_args, malware_path)?;
    } else {
        info!("Processing malware files...");
        let obj_result = fp.parse_sample_dir(malware_path.to_str().unwrap().to_owned())?;
    }

    Ok(())
}

fn run_dropzone_mode(fp: &mut FileProcessor, args: &AppArgs, malware_path: &Path) -> Result<()> {
    info!(
        "Monitoring {} for new sample files (processed samples will be removed)",
        malware_path.display()
    );

    loop {
        if let Ok(entries) = fs::read_dir(malware_path) {
            if entries.count() > 0 {
                let mut dropzone_args = args.clone();

                // Adjust super rule setting based on file count
                if let Ok(entries) = fs::read_dir(malware_path) {
                    dropzone_args.nosuper = entries.count() < 2;
                }

                fp.parse_sample_dir(malware_path.to_str().unwrap().to_owned())?;
                empty_folder(malware_path)?;
            }
        }

        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}

fn update_databases(
    args: &AppArgs,
    good_strings_db: &HashMap<String, TokenInfo>,
    good_opcodes_db: &HashMap<String, TokenInfo>,
    good_imphashes_db: &HashMap<String, TokenInfo>,
    //good_exports_db: &HashMap<String, TokenInfo>,
) -> Result<()> {
    info!("Updating databases...");

    let db_identifier = args
        .i
        .as_deref()
        .map_or(String::new(), |i| format!("-{}", i));

    let dbs = [
        ("good-strings", good_strings_db),
        ("good-opcodes", good_opcodes_db),
        ("good-imphashes", good_imphashes_db),
        //("good-exports", good_exports_db),
    ];

    for (prefix, db) in dbs {
        let filename = format!("./dbs/{}{}.db", prefix, db_identifier);
        todo!()
        //update_single_database(&filename, db)?;
    }

    Ok(())
}

fn load_db(filename: &str) -> Result<serde_json::Value> {
    let path = Path::new(filename);
    let data: Vec<u8> = fs::read(path)?;
    let mut decoder = GzDecoder::new(&*data); // Create a GzDecoder from your compressed data
    let mut decompressed_buffer = Vec::new(); // Create a new Vec to store the decompressed data

    decoder.read_to_end(&mut decompressed_buffer)?; // Read all decompressed data into the buffer

    Ok(serde_json::from_slice(&decompressed_buffer).unwrap())
}

fn save_db(filename: &str, val: HashMap<String, usize>) -> Result<()> {
    let path = Path::new(filename);
    let json_data = serde_json::to_vec(&val)?;
    fs::write(path, json_data)?;
    Ok(())
}

fn load_databases(
    folder: &str,
) -> Result<(
    HashMap<String, usize>,
    HashMap<String, usize>,
    HashMap<String, usize>,
    HashMap<String, usize>,
)> {
    let mut good_strings_db: HashMap<String, usize> = Default::default();
    let mut good_opcodes_db: HashMap<String, usize> = Default::default();
    let mut good_imphashes_db: HashMap<String, usize> = Default::default();
    let mut good_exports_db: HashMap<String, usize> = Default::default();
    for f in read_dir(folder)? {
        let entry = f?;
        let path = entry.path();

        if path.is_file() {
            let name = path.as_os_str().to_str().unwrap();
            if name.contains("good-exports") {
                let hashmap: HashMap<String, usize> =
                    serde_json::from_value(load_db(name).unwrap()).unwrap();
                good_exports_db.extend(hashmap);
                info!("loaded {}, sum: {}", name, good_exports_db.len());
            } else if name.contains("good-strings") {
                let hashmap: HashMap<String, usize> =
                    serde_json::from_value(load_db(name).unwrap()).unwrap();
                good_strings_db.extend(hashmap);
                info!("loaded {}, sum: {}", name, good_strings_db.len());
            } else if name.contains("good-opcodes") {
                let hashmap: HashMap<String, usize> =
                    serde_json::from_value(load_db(name).unwrap()).unwrap();
                good_opcodes_db.extend(hashmap);
                info!("loaded {}, sum: {}", name, good_opcodes_db.len())
            } else if name.contains("good-imphashes") {
                let hashmap: HashMap<String, usize> =
                    serde_json::from_value(load_db(name).unwrap()).unwrap();
                good_imphashes_db.extend(hashmap);
                info!("loaded {}, sum: {}", name, good_imphashes_db.len())
            }
        }
    }
    Ok((
        good_strings_db,
        good_opcodes_db,
        good_exports_db,
        good_imphashes_db,
    ))
}

fn create_databases(
    args: &AppArgs,
    good_strings_db: &HashMap<String, TokenInfo>,
    good_opcodes_db: &HashMap<String, TokenInfo>,
    good_imphashes_db: &HashMap<String, TokenInfo>,
    //good_exports_db: &HashMap<String, TokenInfo>,
) -> Result<()> {
    info!("Creating local database...");

    let db_identifier = args
        .i
        .as_deref()
        .map_or(String::new(), |i| format!("-{}", i));
    let databases = [
        (
            "good-strings",
            good_strings_db
                .into_iter()
                .into_iter()
                .map(|(x, y)| (x.clone(), y.count))
                .collect::<HashMap<String, usize>>(),
        ),
        (
            "good-opcodes",
            good_opcodes_db
                .into_iter()
                .into_iter()
                .map(|(x, y)| (x.clone(), y.count))
                .collect::<HashMap<String, usize>>(),
        ),
        (
            "good-imphashes",
            good_imphashes_db
                .into_iter()
                .into_iter()
                .map(|(x, y)| (x.clone(), y.count))
                .collect::<HashMap<String, usize>>(),
        ),
        //("good-exports", good_exports_db.into_iter().into_iter().map(|(x,y)| (x.clone(), y.count)).collect::< HashMap<String, usize >>()),
    ];

    for (name, data) in databases {
        let filename = format!("./dbs/{}{}.db", name, db_identifier);

        if Path::new(&filename).exists() {
            warn!("File {} already exists. Overwriting.", filename);
        }

        let json_data = serde_json::to_vec(&data)?;
        fs::write(&filename, json_data)?;
        info!("Created database: {}", filename);
    }

    info!(
        "New database with {} string, {} opcode, {} imphash, export entries created.",
        good_strings_db.len(),
        good_opcodes_db.len(),
        good_imphashes_db.len(),
        //good_exports_db.len()
    );

    Ok(())
}

fn empty_folder(dir: &Path) -> Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();

        if path.is_file() {
            info!("Removing {} ...", path.display());
            fs::remove_file(path)?;
        }
    }

    Ok(())
}
