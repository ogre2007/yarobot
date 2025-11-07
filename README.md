# yarobot

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Python Version](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/)
[![Rust](https://img.shields.io/badge/rust-powered-orange.svg)](https://www.rust-lang.org/)

**yarobot** is a high-performance YARA rule generator inspired by [yarGen](https://github.com/Neo23x0/yarGen), designed to automatically create quality YARA rules from malware samples while minimizing false positives through intelligent goodware database comparison.

## 🚀 Features

- **Automated YARA Rule Generation**: Create both simple and super rules from malware samples
- **Intelligent Scoring System**: Advanced string scoring with goodware database comparison
- **High Performance**: Core engine written in Rust for maximum speed

## 🛠 Installation

### Install from PyPI

```bash
pip install yarobot
```

### Build Prerequisites

- Python 3.11 or higher
- Rust toolchain (for building the native extension)

### Install from Source

```bash
git clone https://github.com/ogre2007/yarobot
cd yarobot
pip install .
```

## 📖 Quick Start

### 1. Update Goodware Databases

```bash
yarobot update-remote # from yarGen project. Doenst work yet. Just go to ex. 3
```

### 2. Generate Rules from Malware Samples

```bash
py -m yarobot.generate /path/to/malware/samples --output-rule-file my_rules.yar
```

### 3. Create Custom Goodware Database

```bash
py -m yarobot.database create /path/to/goodware/files --recursive
```

## 🎯 Usage Examples

### Basic Rule Generation

```bash
py -m yarobot.generate /malware/samples \
  --min-size 8 \
  --max-size 128 \
  --min-score 5 \
  --output-rule-file detection_rules.yar
```

### Start as service
server-side:
```bash
py -m yarobot.service
```
client-side:
```bash
curl -X POST -F "files=@tests\\data\\binary" http://localhost:5000/api/analyze -F "min_score=5" -F "get_opcodes=true"
```
### Advanced Configuration

```bash
py -m yarobot.generate /malware/samples \
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

## 🏗 Architecture

yarobot combines the performance of Rust with the flexibility of Python:

### Core Components

- **Rust Engine** (`yarobot-rs`): High-performance file processing and string analysis
- **Python Interface**: CLI management, database operations, and rule formatting
- **Scoring Engine**: Intelligent string scoring with goodware comparison
- **Rule Generator**: YARA rule synthesis and optimization

### Database Structure

- `good-strings.db`: Common strings from goodware samples
- `good-opcodes.db`: Opcode frequency database
- `good-imphashes.db`: Import hash database
- `good-exports.db`: Export function database
 
## 🤝 Contributing

We welcome contributions! 

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## TODO
- [ ] dropzone mode
- [x] http-service
- [ ] fix/drop imphash/exports
- [ ] default databases
- [ ] rule generation rewriting
- [ ] tokenizer code separated in different package
- [ ] dex opcode extraction

## 📄 License

This project is licensed under the GPLv3 License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Based on **yarGen** by Florian Roth
- Built with **Pyo3** for Python-Rust integration
- Uses **goblin** for binary parsing

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/ogre2007/yarobot/issues) 

