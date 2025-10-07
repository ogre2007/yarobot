 
from typing import Tuple
import os
import re 
import traceback
import logging
import lief 


logger = logging.getLogger("yarobot")
 

def get_pe_info(fileData: bytes) -> tuple[str, list[str]]:
    """
    Get different PE attributes and hashes by lief
    :param fileData:
    :return:
    """
    imphash = ""
    exports = []
    # Quick reject: not PE
    if fileData[:2] != b"MZ":
        return imphash, exports
    try:
        # Cheap PE signature validation to avoid heavy parsing on false MZ files
        if len(fileData) < 0x40:
            return imphash, exports
        e_lfanew = int.from_bytes(fileData[0x3C:0x40], "little", signed=False)
        if e_lfanew + 4 > len(fileData):
            return imphash, exports
        if fileData[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
            return imphash, exports

        # Avoid noisy prints on every file; keep exceptions logged below
        binary = lief.parse(fileData)
        # Imphash
        try:
            imphash = lief.PE.get_imphash(binary, lief.PE.IMPHASH_MODE.PEFILE)
        except Exception:
            imphash = ""
        # Exports (names)
        try:
            exp_tbl = binary.get_export()
            if exp_tbl is not None and getattr(exp_tbl, "entries", None):
                for exp in exp_tbl.entries:
                    name = getattr(exp, "name", None)
                    if name:
                        exports.append(str(name))
        except Exception:
            pass
    except Exception as e:
        # Keep debug trace in debug builds, but don't spam stdout otherwise
        logger.debug("lief parse failed: %s", e, exc_info=True)

    return imphash, exports
 
def removeNonAsciiDrop(data: bytes) -> bytes:
    try:
        # Keep printable ASCII 0x20..0x7E and allow NUL padding
        return bytes(b for b in data if (31 < b < 127))
    except Exception:
        if __debug__:
            traceback.print_exc()
        return b""

def getFileContent(file):
    """
    Gets the contents of a file (limited to 1024 characters)
    :param file:
    :return:
    """
    try:
        with open(file) as f:
            return f.read(1024)
    except Exception as e:
        return "not found"




def is_ascii_string(data: bytes, padding_allowed: bool = False) -> int:
    for b in data:
        if padding_allowed:
            if not ((31 < b < 127) or b == 0):
                return 0
        else:
            if not (31 < b < 127):
                return 0
    return 1


def is_base_64(s):
    return (len(s) % 4 == 0) and re.match("^[A-Za-z0-9+/]+[=]{0,2}$", s)


def get_files(folder, notRecursive):
    # Not Recursive
    if notRecursive:
        for filename in os.listdir(folder):
            filePath = os.path.join(folder, filename)
            if os.path.isdir(filePath):
                continue
            yield filePath
    # Recursive
    else:
        for root, dirs, files in os.walk(folder, topdown=False):
            for name in files:
                filePath = os.path.join(root, name)
                yield filePath


def is_hex_encoded(s, check_length=True):
    if re.match("^[A-Fa-f0-9]+$", s):
        if check_length:
            if len(s) % 2 == 0:
                return True
        else:
            return True
    return False
