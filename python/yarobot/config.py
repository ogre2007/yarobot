import os

# Resolve DB path relative to project root (two levels up from this file)
_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__)))
# DB_PATH = os.path.normpath(os.path.join(_ROOT, "dbs"))


PE_STRINGS_FILE = os.path.normpath(os.path.join(_ROOT, "3rdparty", "strings.xml"))

"../3rdparty/strings.xml"

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
