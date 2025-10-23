import os

# Resolve DB path relative to project root (two levels up from this file)
_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
DB_PATH = os.path.normpath(os.path.join(_ROOT, "dbs"))


PE_STRINGS_FILE = os.path.normpath(os.path.join(_ROOT, "3rdparty", "strings.xml"))

"../3rdparty/strings.xml"

KNOWN_IMPHASHES = {
    "a04dd9f5ee88d7774203e0a0cfa1b941": "PsExec",
    "2b8c9d9ab6fefc247adaf927e83dcea6": "RAR SFX variant",
}

REPO_URLS = {
    "good-opcodes-part1.db": "https://www.bsk-consulting.de/yargen/good-opcodes-part1.db",
    "good-opcodes-part2.db": "https://www.bsk-consulting.de/yargen/good-opcodes-part2.db",
    "good-opcodes-part3.db": "https://www.bsk-consulting.de/yargen/good-opcodes-part3.db",
    "good-opcodes-part4.db": "https://www.bsk-consulting.de/yargen/good-opcodes-part4.db",
    "good-opcodes-part5.db": "https://www.bsk-consulting.de/yargen/good-opcodes-part5.db",
    "good-opcodes-part6.db": "https://www.bsk-consulting.de/yargen/good-opcodes-part6.db",
    "good-opcodes-part7.db": "https://www.bsk-consulting.de/yargen/good-opcodes-part7.db",
    "good-opcodes-part8.db": "https://www.bsk-consulting.de/yargen/good-opcodes-part8.db",
    "good-opcodes-part9.db": "https://www.bsk-consulting.de/yargen/good-opcodes-part9.db",
    "good-strings-part1.db": "https://www.bsk-consulting.de/yargen/good-strings-part1.db",
    "good-strings-part2.db": "https://www.bsk-consulting.de/yargen/good-strings-part2.db",
    "good-strings-part3.db": "https://www.bsk-consulting.de/yargen/good-strings-part3.db",
    "good-strings-part4.db": "https://www.bsk-consulting.de/yargen/good-strings-part4.db",
    "good-strings-part5.db": "https://www.bsk-consulting.de/yargen/good-strings-part5.db",
    "good-strings-part6.db": "https://www.bsk-consulting.de/yargen/good-strings-part6.db",
    "good-strings-part7.db": "https://www.bsk-consulting.de/yargen/good-strings-part7.db",
    "good-strings-part8.db": "https://www.bsk-consulting.de/yargen/good-strings-part8.db",
    "good-strings-part9.db": "https://www.bsk-consulting.de/yargen/good-strings-part9.db",
    "good-exports-part1.db": "https://www.bsk-consulting.de/yargen/good-exports-part1.db",
    "good-exports-part2.db": "https://www.bsk-consulting.de/yargen/good-exports-part2.db",
    "good-exports-part3.db": "https://www.bsk-consulting.de/yargen/good-exports-part3.db",
    "good-exports-part4.db": "https://www.bsk-consulting.de/yargen/good-exports-part4.db",
    "good-exports-part5.db": "https://www.bsk-consulting.de/yargen/good-exports-part5.db",
    "good-exports-part6.db": "https://www.bsk-consulting.de/yargen/good-exports-part6.db",
    "good-exports-part7.db": "https://www.bsk-consulting.de/yargen/good-exports-part7.db",
    "good-exports-part8.db": "https://www.bsk-consulting.de/yargen/good-exports-part8.db",
    "good-exports-part9.db": "https://www.bsk-consulting.de/yargen/good-exports-part9.db",
    "good-imphashes-part1.db": "https://www.bsk-consulting.de/yargen/good-imphashes-part1.db",
    "good-imphashes-part2.db": "https://www.bsk-consulting.de/yargen/good-imphashes-part2.db",
    "good-imphashes-part3.db": "https://www.bsk-consulting.de/yargen/good-imphashes-part3.db",
    "good-imphashes-part4.db": "https://www.bsk-consulting.de/yargen/good-imphashes-part4.db",
    "good-imphashes-part5.db": "https://www.bsk-consulting.de/yargen/good-imphashes-part5.db",
    "good-imphashes-part6.db": "https://www.bsk-consulting.de/yargen/good-imphashes-part6.db",
    "good-imphashes-part7.db": "https://www.bsk-consulting.de/yargen/good-imphashes-part7.db",
    "good-imphashes-part8.db": "https://www.bsk-consulting.de/yargen/good-imphashes-part8.db",
    "good-imphashes-part9.db": "https://www.bsk-consulting.de/yargen/good-imphashes-part9.db",
}

RELEVANT_EXTENSIONS = [
    "asp",
    "vbs",
    "ps",
    "ps1",
    "tmp",
    "bas",
    "bat",
    "cmd",
    "com",
    "cpl",
    "crt",
    "dll",
    "exe",
    "msc",
    "scr",
    "sys",
    "vb",
    "vbe",
    "vbs",
    "wsc",
    "wsf",
    "wsh",
    "input",
    "war",
    "jsp",
    "php",
    "asp",
    "aspx",
    "psd1",
    "psm1",
    "py",
]
