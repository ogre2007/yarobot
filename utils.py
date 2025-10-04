import binascii
import datetime
import gzip
import json
import os
import re
import sys
import traceback
import lief
from lxml import etree

PE_STRINGS_FILE = "./3rdparty/strings.xml"




# TODO: Still buggy after port to Python3
def extract_hex_strings(s):
    strings = []
    hex_strings = re.findall(b"([a-fA-F0-9]{10,})", s)
    for string in list(hex_strings):
        hex_strings += string.split(b"0000")
        hex_strings += string.split(b"0d0a")
        hex_strings += re.findall(
            b"((?:0000|002[a-f0-9]|00[3-9a-f][0-9a-f]){6,})", string, re.IGNORECASE
        )
    hex_strings = list(set(hex_strings))
    # ASCII Encoded Strings
    for string in hex_strings:
        for x in string.split(b"00"):
            if len(x) > 10:
                strings.append(x)
    # WIDE Encoded Strings
    for string in hex_strings:
        try:
            if len(string) % 2 != 0 or len(string) < 8:
                continue
            # Skip
            if b"0000" in string:
                continue
            dec = string.replace(b"00", b"")
            if is_ascii_string(dec, padding_allowed=False):
                strings.append(string)
        except Exception as e:
            traceback.print_exc()
    return strings


def extract_strings(maxlen, fileData) -> list[str]:
    # String list
    cleaned_strings = []
    # Read file data
    try:
        # Read strings
        strings_full = re.findall(b"[\x1f-\x7e]{6,}", fileData)
        strings_limited = re.findall(b"[\x1f-\x7e]{6,%d}" % maxlen, fileData)
        strings_hex = extract_hex_strings(fileData)
        strings = list(set(strings_full) | set(strings_limited) | set(strings_hex))
        wide_strings = [ws for ws in re.findall(b"(?:[\x1f-\x7e][\x00]){6,}", fileData)]

        # Post-process
        # WIDE
        for ws in wide_strings:
            # Decode UTF16 and prepend a marker (facilitates handling)
            wide_string = ("UTF16LE:%s" % ws.decode("utf-16")).encode("utf-8")
            if wide_string not in strings:
                strings.append(wide_string)
        for string in strings:
            # Escape strings
            if len(string) > 0:
                string = string.replace(b"\\", b"\\\\")
                string = string.replace(b'"', b'\\"')
            try:
                if isinstance(string, str):
                    cleaned_strings.append(string)
                else:
                    cleaned_strings.append(string.decode("utf-8"))
            except AttributeError as e:
                print(string)
                traceback.print_exc()

    except Exception as e:
        print(string)
        traceback.print_exc()
        pass

    return cleaned_strings


def extract_opcodes(fileData) -> list[str]:
    # Opcode list
    opcodes = []

    try:
        # Read file data
        binary = lief.parse(fileData)
        ep = binary.entrypoint

        # Locate .text section
        text = None
        if isinstance(binary, lief.PE.Binary):
            for sec in binary.sections:
                if (
                    sec.virtual_address + binary.imagebase
                    <= ep
                    < sec.virtual_address + binary.imagebase + sec.virtual_size
                ):
                    print(f"EP is located at {sec.name} section")
                    text = sec.content.tobytes()
                    break
        elif isinstance(binary, lief.ELF.Binary):
            for sec in binary.sections:
                if sec.virtual_address <= ep < sec.virtual_address + sec.size:
                    print(f"EP is located at {sec.name} section")
                    text = sec.content.tobytes()
                    break

        if text is not None:
            # Split text into subs
            text_parts = re.split(b"[\x00]{3,}", text)
            # Now truncate and encode opcodes
            for text_part in text_parts:
                if text_part == "" or len(text_part) < 8:
                    continue
                opcodes.append(
                    binascii.hexlify(text_part[:16]).decode(encoding="ascii")
                )
    except Exception as e:
        traceback.print_exc()
        pass

    return opcodes


def get_pe_info(fileData: bytes) -> tuple[str, list[str]]:
    """
    Get different PE attributes and hashes by lief
    :param fileData:
    :return:
    """
    imphash = ""
    exports = []
    # Check for MZ header (speed improvement)
    if fileData[:2] != b"MZ":
        return imphash, exports
    try:

        print("Extracting PE information")
        binary: lief.PE.Binary = lief.parse(fileData)
        # Imphash
        imphash = lief.PE.get_imphash(binary, lief.PE.IMPHASH_MODE.PEFILE)
        # Exports (names)
        for exp in binary.get_export().entries:
            exp: lief.PE.ExportEntry
            exports.append(str(exp.name))
    except Exception as e:
        traceback.print_exc()
        pass

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


def removeNonAsciiDrop(string):
    nonascii = "error"
    try:
        byte_list = [i.to_bytes(1, sys.byteorder) for i in string]
        # Generate a new string without disturbing characters
        nonascii = b"".join(i for i in byte_list if ord(i) < 127 and ord(i) > 31)
    except Exception as e:
        traceback.print_exc()
        pass
    return nonascii


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


def is_ascii_char(b, padding_allowed=False):
    if padding_allowed:
        if (ord(b) < 127 and ord(b) > 31) or ord(b) == 0:
            return 1
    else:
        if ord(b) < 127 and ord(b) > 31:
            return 1
    return 0


def is_ascii_string(string, padding_allowed=False):
    for b in [i.to_bytes(1, sys.byteorder) for i in string]:
        if padding_allowed:
            if not ((ord(b) < 127 and ord(b) > 31) or ord(b) == 0):
                return 0
        else:
            if not (ord(b) < 127 and ord(b) > 31):
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
