import datetime
import gzip
import json
import os
import re
import sys
import traceback
from lxml import etree

PE_STRINGS_FILE = "./3rdparty/strings.xml"


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
