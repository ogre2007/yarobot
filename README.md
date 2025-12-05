# yarobot

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Python Version](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/)
[![Rust](https://img.shields.io/badge/rust-powered-orange.svg)](https://www.rust-lang.org/)

**[yarobot](https://github.com/ogre2007/yarobot)** is a high-performance YARA rule generator inspired by yarGen project, designed to automatically create quality YARA rules from malware samples while minimizing false positives through intelligent goodware database comparison.
![screenshot](img/web.png)
## 🚀 Features

- **Automated YARA Rule Generation**: Create both simple and super rules from malware samples
- **Scoring System**: Advanced string scoring with goodware database comparison
- **Separated and reusable core engine**: High-performance file processing and string analysis library - check out [stringZZ](https://github.com/ogre2007/yarobot) project
- **Python Interface**: CLI management, database operations, and rule formatting
- **Web UI**: Fancy and useful web&http interface
 

## 🛠 Installation

### Install from PyPI

```bash
pip install yarobot
```

### Install from Source

```bash
git clone https://github.com/ogre2007/yarobot
cd yarobot
pip install .
```

## 📖 Quick Start

### Create Custom Goodware Database (if needed)

```bash
py -m yarobot.database create /path/to/goodware/files --recursive
```

### Generate Rules from Malware Samples (cli)

```bash
py -m yarobot.generate /path/to/malware/samples --output-rule-file my_rules.yar
```

### Start as web service
```bash
py -m yarobot.app [-g <goodware dbs path>]
```
then locate http://localhost:5000
or use api directly from anywhere:
```bash
curl -X POST -F "files=@tests\\data\\binary" http://localhost:5000/api/analyze -F "min_score=5" -F "get_opcodes=true"
```

### Advanced Configuration

```bash
py -m yarobot.generate /malware/samples -g <goodware dbs path> \
  --opcodes \
  --recursive \
  --author "My Security Team" \
  --ref "Internal Investigation 2024" \
  --superrule-overlap 5 \
  --strings-per-rule 15
```

### Database Management

```bash
# Update existing database with new goodware samples
(TODO) py -m yarobot.database update /path/to/new/goodware --identifier corporate 

# Create new database from scratch
py -m yarobot.database create /path/to/goodware --opcodes
```

## 🔧 Configuration Options

### Rule Generation Options

- `--min-size`, `--max-size`: String length boundaries
- `--min-score`: Minimum string score threshold
- `--opcodes`: Enable opcode feature for additional detection capabilities
- `--superrule-overlap`: Minimum overlapping strings for super rule creation
- `--recursive`: Scan directories recursively
- `--excludegood`: Force exclusion of all goodware strings
- `--oe`: only executable extensions


### Database Options

- `--identifier`: Database identifier for multi-environment support
- `--update`: Update existing databases with new samples
- `--only-executable`: Only process executable file extensions


## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## TODO's
- [x] global project refactoring & packaging
- [x] token extraction&processing code rewritten in Rust
- [x] tests & ci/cd
- [x] multiplatform pypi release
- [x] http-service
- [x] Web UI
- [ ] store regexps in config
- [x] wide/ascii token merging
- [x] token deduplication
- [ ] fix/drop imphash/exports
- [ ] default databases
- [ ] rule generation rewriting
- [x] token extraction&processing separated in different package

## 📄 License

This project is licensed under the GPLv3 License - see the [LICENSE](LICENSE) file for details.

## 🙏 Credits
- **yarGen** by Florian Roth (initial idea and implementation)
- **Pyo3** for Python-Rust integration
- **goblin** for binary parsing

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/ogre2007/yarobot/issues) 

