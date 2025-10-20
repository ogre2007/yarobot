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
