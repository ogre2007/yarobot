import binascii
import datetime
import gzip
from typing import Tuple
import orjson as json
import os
import re
import sys
import traceback
import logging
import lief
from lxml import etree

import yarobot_rs

PE_STRINGS_FILE = "./3rdparty/strings.xml"


logger = logging.getLogger("yarobot")


def extract_opcodes(fileData) -> list[str]:
    return yarobot_rs.extract_opcodes(fileData)


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


def get_abs_path(filename):
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), filename)


def initialize_pestudio_strings():
    if not os.path.isfile(get_abs_path(PE_STRINGS_FILE)):
        return None
    print("[+] Processing PEStudio strings ...")

    pestudio_strings = {}

    tree = etree.parse(get_abs_path(PE_STRINGS_FILE))

    pestudio_strings["strings"] = tree.findall(".//string")
    pestudio_strings["av"] = tree.findall(".//av")
    pestudio_strings["folder"] = tree.findall(".//folder")
    pestudio_strings["os"] = tree.findall(".//os")
    pestudio_strings["reg"] = tree.findall(".//reg")
    pestudio_strings["guid"] = tree.findall(".//guid")
    pestudio_strings["ssdl"] = tree.findall(".//ssdl")
    pestudio_strings["ext"] = tree.findall(".//ext")
    pestudio_strings["agent"] = tree.findall(".//agent")
    pestudio_strings["oid"] = tree.findall(".//oid")
    pestudio_strings["priv"] = tree.findall(".//priv")

    # Obsolete
    # for elem in string_elems:
    #    strings.append(elem.text)

    return pestudio_strings


def emptyFolder(dir):
    """
    Removes all files from a given folder
    :return:
    """
    for file in os.listdir(dir):
        filePath = os.path.join(dir, file)
        try:
            if os.path.isfile(filePath):
                print("[!] Removing %s ..." % filePath)
                os.unlink(filePath)
        except Exception as e:
            print(e)


def getReference(ref):
    """
    Get a reference string - if the provided string is the path to a text file, then read the contents and return it as
    reference
    :param ref:
    :return:
    """
    if os.path.exists(ref):
        reference = getFileContent(ref)
        print("[+] Read reference from file %s > %s" % (ref, reference))
        return reference
    else:
        return ref


def save(object, filename):
    file = gzip.GzipFile(filename, "wb")
    file.write(bytes(json.dumps(object), "utf-8"))
    file.close()


def removeNonAsciiDrop(data: bytes) -> bytes:
    try:
        # Keep printable ASCII 0x20..0x7E and allow NUL padding
        return bytes(b for b in data if (31 < b < 127))
    except Exception:
        if __debug__:
            traceback.print_exc()
        return b""


def load(filename):
    file = gzip.GzipFile(filename, "rb")
    object = json.loads(file.read())
    file.close()
    return object


def getIdentifier(id, path):
    """
    Get a identifier string - if the provided string is the path to a text file, then read the contents and return it as
    reference, otherwise use the last element of the full path
    :param ref:
    :return:
    """
    # Identifier
    if id == "not set" or not os.path.exists(id):
        # Identifier is the highest folder name
        return os.path.basename(path.rstrip("/"))
    else:
        # Read identifier from file
        identifier = getFileContent(id)
        print("[+] Read identifier from file %s > %s" % (id, identifier))
        return identifier


def get_pestudio_score(string, pestudio_strings):
    for type in pestudio_strings:
        for elem in pestudio_strings[type]:
            # Full match
            if elem.text.lower() == string.lower():
                # Exclude the "extension" black list for now
                if type != "ext":
                    return 5, type
    return 0, ""


def getPrefix(prefix, identifier):
    """
    Get a prefix string for the rule description based on the identifier
    :param prefix:
    :param identifier:
    :return:
    """
    if prefix == "Auto-generated rule":
        return identifier
    else:
        return prefix


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


def get_timestamp_basic(date_obj=None):
    if not date_obj:
        date_obj = datetime.datetime.now()
    date_str = date_obj.strftime("%Y-%m-%d")
    return date_str


def is_ascii_char(b: int, padding_allowed: bool = False) -> int:
    if padding_allowed:
        return 1 if (31 < b < 127) or b == 0 else 0
    return 1 if (31 < b < 127) else 0


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


def get_opcode_string(opcode):
    return " ".join(opcode[i : i + 2] for i in range(0, len(opcode), 2))


def get_uint_string(magic):
    if len(magic) == 2:
        return "uint8(0) == 0x{0}{1}".format(magic[0], magic[1])
    if len(magic) == 4:
        return "uint16(0) == 0x{2}{3}{0}{1}".format(
            magic[0], magic[1], magic[2], magic[3]
        )
    return ""


def sanitize_rule_name(path: str, file: str) -> str:
    """Generate a valid YARA rule name from path and filename.

    - Prefix with folder name if too short
    - Ensure it doesn't start with a number
    - Replace invalid chars with underscore
    - De-duplicate underscores
    """
    file_base = os.path.splitext(file)[0]
    cleaned = file_base
    if len(file_base) < 8:
        cleaned = path.split("\\")[-1:][0] + "_" + cleaned
    if re.search(r"^[0-9]", cleaned):
        cleaned = "sig_" + cleaned
    cleaned = re.sub(r"[^\w]", "_", cleaned)
    cleaned = re.sub(r"_+", "_", cleaned)
    return cleaned
