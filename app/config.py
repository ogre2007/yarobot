import os

# Resolve DB path relative to project root (two levels up from this file)
_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
DB_PATH = os.path.normpath(os.path.join(_ROOT, "dbs"))

PE_STRINGS_FILE = "./3rdparty/strings.xml"
