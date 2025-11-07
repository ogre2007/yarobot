from collections import Counter
import functools
import gzip
import logging
import os

import click
import orjson as json

from .config import DB_PATH, PE_STRINGS_FILE

from lxml import etree


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
        identifier = open(id).read()
        print("[+] Read identifier from file %s > %s" % (id, identifier))
        return identifier


def getReference(ref):
    """
    Get a reference string - if the provided string is the path to a text file, then read the contents and return it as
    reference
    :param ref:
    :return:
    """
    if os.path.exists(ref):
        reference = open(ref).read()
        print("[+] Read reference from file %s > %s" % (ref, reference))
        return reference
    else:
        return ref


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


def initialize_pestudio_strings():
    # if not os.path.isfile(get_abs_path(PE_STRINGS_FILE)):
    #    return None
    print("[+] Processing PEStudio strings ...")

    pestudio_strings = {}

    tree = etree.parse(get_abs_path(PE_STRINGS_FILE))
    processed_strings = {}
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
    for category, elements in pestudio_strings.items():
        for elem in elements:
            processed_strings[elem.text] = (5, category)
    return processed_strings


def load_databases():
    if not os.path.isdir(get_abs_path(DB_PATH)):
        logging.getLogger("yarobot").error("Database directory not found")
        return ({}, {}, {}, {})
    good_strings_db = Counter()
    good_opcodes_db = Counter()
    good_imphashes_db = Counter()
    good_exports_db = Counter()

    # Initialize all databases
    for file in os.listdir(get_abs_path(DB_PATH)):
        if file.endswith(".db") or file.endswith(".json"):
            if file.startswith("good-strings"):
                load_db(file, good_strings_db, True if file.endswith(".json") else False)
            if file.startswith("good-opcodes"):
                load_db(file, good_opcodes_db, True if file.endswith(".json") else False)
            if file.startswith("good-imphashes"):
                pass  # load_db(file, good_imphashes_db, True if file.endswith(".json") else False) TODO
            if file.startswith("good-exports"):
                pass  # load_db(file, good_exports_db, True if file.endswith(".json") else False) TODO
    return good_strings_db, good_opcodes_db, good_imphashes_db, good_exports_db


def common_single_analysis_options(f):
    @click.option(
        "-y",
        "--min-size",
        help="Minimum string length to consider (default=8)",
        type=int,
        default=8,
    )
    @click.option(
        "-z",
        "--min-score",
        help="Minimum score to consider (default=5)",
        type=int,
        default=5,
    )
    @click.option(
        "-x",
        "--high-scoring",
        help='Score required to set string as "highly specific string" (default: 30)',
        type=int,
        default=30,
    )
    @click.option(
        "-s",
        "--max-size",
        help="Maximum length to consider (default=128)",
        type=int,
        default=128,
    )
    @click.option(
        "-rc",
        "--strings-per-rule",
        help="Maximum number of strings per rule (default=15, intelligent filtering will be applied)",
        type=int,
        default=15,
    )
    @click.option(
        "--excludegood",
        help="Force the exclude all goodware strings",
        is_flag=True,
        default=False,
    )
    @click.option("-o", "--output-rule-file", help="Output rule file", default="yarobot_rules.yar")
    @click.option("-e", "--output-dir-strings", help="Output directory for string exports", default="")
    @click.option("-a", "--author", help="Author Name", default="yarobot Rule Generator")
    @click.option(
        "--ref",
        help="Reference (can be string or text file)",
        default="https://github.com/ogre2007/yarobot",
    )
    @click.option("-l", "--license", help="License", default="")
    @click.option(
        "-p",
        "--prefix",
        help="Prefix for the rule description",
        default="Auto-generated rule",
    )
    @click.option(
        "-b",
        "--identifier",
        help="Text file from which the identifier is read (default: last folder name in the full path)",
        default="not set",
    )
    @click.option(
        "--score",
        help="Show the string scores as comments in the rules",
        is_flag=True,
        default=False,
    )
    @click.option(
        "--nomagic",
        help="Don't include the magic header condition statement",
        is_flag=True,
        default=False,
    )
    @click.option(
        "--nofilesize",
        help="Don't include the filesize condition statement",
        is_flag=True,
        default=False,
    )
    @click.option(
        "-fm",
        "--filesize-multiplier",
        help="Multiplier for the maximum 'filesize' condition value (default: 2)",
        type=int,
        default=2,
    )
    @click.option(
        "--oe",
        "--only-executable",
        help="Only scan executable extensions EXE, DLL, ASP, JSP, PHP, BIN, INFECTED",
        is_flag=True,
        default=False,
    )
    @click.option(
        "-fs",
        "--max-file-size",
        help="Max file size in MB to analyze (default=2)",
        type=int,
        default=2,
    )
    @click.option(
        "--noextras",
        help="Don't use extras like Imphash or PE header specifics",
        is_flag=True,
        default=False,
    )
    @click.option("--debug", help="Debug output", is_flag=True, default=False)
    @click.option("--trace", help="Trace output", is_flag=True, default=False)
    @click.option(
        "--opcodes",
        help="Do use the OpCode feature (use this if not enough high scoring strings can be found)",
        is_flag=True,
        default=False,
    )
    @click.option(
        "-n",
        "--opcode-num",
        help="Number of opcodes to add if not enough high scoring string could be found (default=3)",
        type=int,
        default=3,
    )
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        return f(*args, **kwargs)

    return wrapper


def common_multi_analysis_options(f):
    @click.option(
        "-w",
        "--superrule-overlap",
        help="Minimum number of strings that overlap to create a super rule (default: 5)",
        type=int,
        default=5,
    )
    @click.option(
        "--nosimple",
        help="Skip simple rule creation for files included in super rules",
        is_flag=True,
        default=False,
    )
    @click.option(
        "--globalrule",
        help="Create global rules (improved rule set speed)",
        is_flag=True,
        default=False,
    )
    @click.option(
        "--nosuper",
        help="Don't try to create super rules that match against various files",
        is_flag=True,
        default=False,
    )
    @click.option(
        "-R",
        "--recursive",
        help="Recursively scan directories",
        is_flag=True,
        default=False,
    )
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        return f(*args, **kwargs)

    return wrapper


def load(filename, just_json=False):
    if just_json:
        with open(filename, "rb") as file:
            return json.loads(file.read())
    else:
        file = gzip.GzipFile(filename, "rb")
        object = json.loads(file.read())
        file.close()
        return object


def get_abs_path(filename):
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), filename)


def save(object, filename):
    path = os.path.join(DB_PATH, filename)
    with open(path, "wb") as file:
        file.write(bytes(json.dumps(object)))


def load_db(file, local_counter, just_json=False):
    filePath = os.path.join(DB_PATH, file)
    print("[+] Loading %s ..." % filePath)
    before = len(local_counter)
    js = load(get_abs_path(filePath), just_json)
    local_counter.update(js)
    added = len(local_counter) - before
    print("[+] Total: %s / Added %d entries" % (len(local_counter), added))

    return len(local_counter)
