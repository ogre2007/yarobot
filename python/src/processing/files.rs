use std::{
    collections::HashMap,
    ffi::OsStr,
    fs::{self, File},
    io::Read,
    path,
};

use crate::{
    extract_and_count_ascii_strings, extract_and_count_utf16_strings, extract_opcodes,
    get_file_info, FileInfo, TokenInfo, TokenType,
};

use anyhow::Result;
use log::debug;
use pyo3::prelude::*;
use walkdir::WalkDir;

pub fn merge_stats(new: HashMap<String, TokenInfo>, stats: &mut HashMap<String, TokenInfo>) {
    for (tok, info) in new.into_iter() {
        if info.typ == TokenType::BINARY {
            //println!("{:?}", info);
        }
        if stats.len() > 0 {
            //println!("{:?}", &info);
            //assert_eq!(stats.iter().nth(0).unwrap().1.typ, info.typ);
        }
        let inf = stats.entry(tok).or_insert(Default::default());
        inf.merge(&info);
    }
}

#[pyclass]
#[derive(Debug, Clone, Default)]
pub struct FileProcessor {
    recursive: bool,
    extensions: Option<Vec<String>>,
    pub minssize: usize,
    pub maxssize: usize,
    pub fsize: usize,
    pub  get_opcodes: bool,
    debug: bool,

    pub strings: HashMap<String, TokenInfo>,
    pub utf16strings: HashMap<String, TokenInfo>,
    pub opcodes: HashMap<String, TokenInfo>,
    pub file_infos: HashMap<String, FileInfo>,
}

#[pyfunction]
pub fn get_files(folder: String, recursive: bool) -> PyResult<Vec<String>> {
    let mut files = Vec::new();

    if !recursive {
        if let Ok(entries) = fs::read_dir(folder) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    if let Some(path_str) = path.to_str() {
                        files.push(path_str.to_string());
                    }
                }
            }
        }
    } else {
        for entry in WalkDir::new(&folder).into_iter().filter_map(|e| e.ok()) {
            if entry.file_type().is_file() {
                if let Some(path_str) = entry.path().to_str() {
                    files.push(path_str.to_string());
                }
            }
        }
    }

    Ok(files)
}

pub fn process_buffer_u8(
    buffer: Vec<u8>,
    minssize: usize,
    maxssize: usize,
    get_opcodes: bool,
) -> Result<(
    FileInfo,
    HashMap<String, TokenInfo>,
    HashMap<String, TokenInfo>,
    HashMap<String, TokenInfo>,
)> {
    let fi: FileInfo = get_file_info(&buffer).unwrap();
    let (mut strings, mut utf16strings) = (
        extract_and_count_ascii_strings(&buffer, minssize, maxssize),
        extract_and_count_utf16_strings(&buffer, minssize, maxssize),
    );
    let mut opcodes = Default::default();
    if get_opcodes {
        opcodes = extract_opcodes(buffer).unwrap();
    }

    Ok((fi, strings, utf16strings, opcodes))
}

#[pymethods]
impl FileProcessor {
    #[new]
    pub fn new(
        recursive: bool,
        extensions: Option<Vec<String>>,
        minssize: usize,
        maxssize: usize,
        fsize: usize,
        get_opcodes: bool,
        debug: bool,
    ) -> Self {
        Self {
            recursive,
            extensions,
            minssize,
            maxssize,
            fsize,
            get_opcodes,
            debug,
            ..Default::default()
        }
    }

    pub fn parse_sample_dir(
        &mut self,
        dir: String,
    ) -> PyResult<(
        HashMap<String, TokenInfo>,
        HashMap<String, TokenInfo>,
        HashMap<String, TokenInfo>,
        HashMap<String, FileInfo>,
    )> {
        for file_path in get_files(dir, self.recursive).unwrap().into_iter() {
            self.process_file_with_checks(file_path);
        }
        Ok((
            self.strings.clone(),
            self.opcodes.clone(),
            self.utf16strings.clone(),
            self.file_infos.clone(),
        ))
    }

    pub fn clear_context(&mut self) {
        (
            self.strings,
            self.opcodes,
            self.utf16strings,
            self.file_infos,
        ) = Default::default();
    }

    pub fn process_file_with_checks(&mut self, file_path: String) -> bool {
        let os_path = path::Path::new(&file_path);

        if let Some(extensions) = &self.extensions {
            match os_path.extension().and_then(OsStr::to_str) {
                Some(ext) => {
                    if !extensions
                        .iter()
                        .any(|x| x.eq(&ext.to_owned().to_lowercase()))
                    {
                        debug!("[-] EXTENSION {} - Skipping file {}", ext, file_path);

                        return false;
                    }
                }
                _ => {}
            }
        }
        let meta = fs::metadata(os_path).unwrap();
        if meta.len() < 15 {
            debug!("[-] File is empty - Skipping file {}", file_path);
            return false;
        }
        //let bytes = fs::read(os_path).unwrap().into_iter().take(fs*1024*1024).collect();
        let (fi, strings, utf16strings, opcodes) =
            self.process_single_file(file_path.to_string()).unwrap();

        if self.file_infos.iter().any(|x| x.1.sha256 == fi.sha256) {
            if self.debug {
                println!(
                    "[-] Skipping strings/opcodes from {} due to MD5 duplicate detection",
                    file_path
                );
            }
            return false;
        }
        self.file_infos.insert(file_path.to_string(), fi);
        merge_stats(strings, &mut self.strings);
        merge_stats(utf16strings, &mut self.utf16strings);
        merge_stats(opcodes, &mut self.opcodes);
        if self.debug {
            println!(
                "[+] Processed {} Size: {} Strings: {} Utf16Strings: {} OpCodes: {}",
                file_path,
                meta.len(),
                self.strings.len(),
                self.utf16strings.len(),
                self.opcodes.len()
            );
        }
        true
    }

    pub fn process_single_file(
        &self,
        file_path: String,
    ) -> PyResult<(
        FileInfo,
        HashMap<String, TokenInfo>,
        HashMap<String, TokenInfo>,
        HashMap<String, TokenInfo>,
    )> {
        let file = File::open(&file_path)?;
        let mut limited_reader = file.take((self.fsize * 1024 * 1024).try_into().unwrap());
        let mut buffer = Vec::new();
        let _ = limited_reader.read_to_end(&mut buffer);

        let (fi, mut strings, mut utf16strings, mut opcodes) =
            process_buffer_u8(buffer, self.minssize, self.maxssize, self.get_opcodes).unwrap();
        for (_, ti) in strings.iter_mut() {
            ti.files.insert(file_path.clone());
        }
        for (_, ti) in utf16strings.iter_mut() {
            ti.files.insert(file_path.clone());
        }
        for (_, ti) in opcodes.iter_mut() {
            ti.files.insert(file_path.clone());
        }

        Ok((fi, strings, utf16strings, opcodes))
    }
}
