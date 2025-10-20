#!/usr/bin/env python


"""
yarGen - Yara Rule Generator, Copyright (c) 2015, Florian Roth
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
    * Neither the name of the copyright owner nor the
      names of its contributors may be used to endorse or promote products
      derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL Florian Roth BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""

import gzip
import os
import sys
import logging

import traceback
import time
from collections import Counter
import signal as signal_module
import orjson as json
from lxml import etree

from app.config import DB_PATH, PE_STRINGS_FILE


from app.rule_generator import generate_rules

# from app.scoring import extract_stats_by_file, sample_string_evaluation
from app.config import RELEVANT_EXTENSIONS

import yarobot_rs

import click
import os
import sys

from app import dbs


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


def load(filename):
    file = gzip.GzipFile(filename, "rb")
    object = json.loads(file.read())
    file.close()
    return object


def get_abs_path(filename):
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), filename)


def save(object, filename):
    file = gzip.GzipFile(filename, "wb")
    file.write(bytes(json.dumps(object), "utf-8"))
    file.close()


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
    #if not os.path.isfile(get_abs_path(PE_STRINGS_FILE)):
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


def load_db(file, local_counter ):
 
    filePath = os.path.join(DB_PATH, file)
    print("[+] Loading %s ..." % filePath)
    before = len(local_counter)
    js = load(get_abs_path(filePath))
    local_counter.update(js)
    added = len(local_counter) - before
    print("[+] Total: %s / Added %d entries" % (len(local_counter), added))
 
    return len(local_counter)

def load_databases():
    good_strings_db = Counter()
    good_opcodes_db = Counter()
    good_imphashes_db = Counter()
    good_exports_db = Counter() 

    # Initialize all databases
    for file in os.listdir(get_abs_path(DB_PATH)):

        if not file.endswith(".db"):
            continue  # String databases
        match '-'.join(file.split("-")[:2]):
            case "good-strings":
                load_db(file, good_strings_db)
            case "good-opcodes":
                load_db(file, good_opcodes_db)
            case "good-imphashes":
                load_db(file, good_imphashes_db)
            case "good-exports":
                load_db(file, good_exports_db)
    return good_strings_db, good_opcodes_db, good_imphashes_db, good_exports_db


def process_folder(args, folder, good_strings_db, good_opcodes_db, good_imphashes_db, good_exports_db, pestudio_strings):
    if args.opcodes and len(good_opcodes_db) < 1:
        logging.getLogger("yarobot").warning("[E] Missing goodware opcode databases.    Please run 'yarobot update' to retrieve the newest database set.")
        args.opcodes = False

    if len(good_exports_db) < 1 and len(good_imphashes_db) < 1:
        logging.getLogger("yarobot").info("[E] Missing goodware imphash/export databases.     Please run 'yarobot update' to retrieve the newest database set.")

    if len(good_strings_db) < 1 and not args.c:
        logging.getLogger("yarobot").error("[E] Error - no goodware databases found.     Please run 'yarobot update' to retrieve the newest database set.")
        sys.exit(1)
    # Deactivate super rule generation if there's only a single file in the folder
    if len(os.listdir(args.malware_path)) < 2:
        args.nosuper = True
    
    # Scan malware files
    logging.getLogger("yarobot").info(f"[+] Generating YARA rules from {args.malware_path}")
    (combinations, super_rules, file_strings, file_opcodes, file_utf16strings, file_info, scoring_engine) = yarobot_rs.process_malware(
        args.malware_path,
        args.recursive,
        RELEVANT_EXTENSIONS,
        args.min_size,
        args.max_size,
        args.max_file_size,
        args.opcodes,
        args.debug,
        args.excludegood,
        args.min_score,
        args.superrule_overlap,
        good_strings_db,
        good_opcodes_db,
        good_imphashes_db,
        good_exports_db,
        pestudio_strings
    )
    # Apply intelligent filters
    logging.getLogger("yarobot").info("[-] Applying intelligent filters to string findings ...")
    file_strings = {fpath: scoring_engine.filter_string_set(strings) for fpath, strings in file_strings.items()}
    file_opcodes = {fpath: scoring_engine.filter_opcode_set(opcodes) for fpath, opcodes in file_opcodes.items()}

    # Create Rule Files
    (rule_count, super_rule_count) = generate_rules(
        scoring_engine, 
        args,
        file_strings,
        file_opcodes,
        super_rules,
        file_info,
    )

    print("[=] Generated %s SIMPLE rules." % str(rule_count))
    if not args.nosuper:
        print("[=] Generated %s SUPER rules." % str(super_rule_count))
    print("[=] All rules written to %s" % args.output_rule_file)

@click.group()
def cli():
    """yarobot - YARA rule generator"""
    pass


@cli.command()
@click.option("-m", "--malware-path", required=True, help="Path to scan for malware")
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
    "-w",
    "--superrule-overlap",
    help="Minimum number of strings that overlap to create a super rule (default: 5)",
    type=int,
    default=5,
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
    help="Maximum number of strings per rule (default=20, intelligent filtering will be applied)",
    type=int,
    default=20,
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
    "--nosimple",
    help="Skip simple rule creation for files included in super rules",
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
    help="Multiplier for the maximum 'filesize' condition value (default: 3)",
    type=int,
    default=3,
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
    help="Max file size in MB to analyze (default=10)",
    type=int,
    default=10,
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
def generate(**kwargs):
    """Generate YARA rules from malware samples"""
    args = type("Args", (), kwargs)()

    # Validate input
    if args.malware_path and os.path.isfile(args.malware_path):
        click.echo("[E] Input is a file, please use a directory instead (-m path)")
        sys.exit(0)
    sourcepath = args.malware_path
    args.identifier = getIdentifier(args.identifier, sourcepath)
    print("[+] Using identifier '%s'" % args.identifier)

    # Reference
    args.ref = getReference(args.ref)
    print("[+] Using reference '%s'" % args.ref)

    # Prefix
    args.prefix = getPrefix(args.prefix, args.identifier)
    print("[+] Using prefix '%s'" % args.prefix)

    pestudio_strings = initialize_pestudio_strings()
    print("[+] Reading goodware strings from database 'good-strings.db' ...")
    print("    (This could take some time and uses several Gigabytes of RAM depending on your db size)")

    good_strings_db, good_opcodes_db, good_imphashes_db, good_exports_db = load_databases()
    process_folder(args, args.malware_path, good_strings_db, good_opcodes_db, good_imphashes_db, good_exports_db, pestudio_strings)


@cli.command()
@click.option("-g", "--goodware-path", required=True, help="Path to scan for goodware")
@click.option("-i", "--identifier", help="Identifier for the database files", required=True)
@click.option(
    "--update",
    help="Update existing database with new goodware samples",
    is_flag=True,
    default=False,
)
@click.option("--debug", help="Debug output", is_flag=True, default=False)
def database(**kwargs):
    """Manage goodware databases"""
    args = type("Args", (), kwargs)()
    print("[+] Processing goodware files ...") 
    good_strings_db, good_opcodes_db, good_imphashes_db, good_exports_db = parse_good_dir(args.g)

    # Update existing databases
    if args.update:
        print("[+] Updating databases ...")

        # Evaluate the database identifiers
        db_identifier = ""
        if args.i != "":
            db_identifier = "-%s" % args.i
        strings_db = "./dbs/good-strings%s.db" % db_identifier
        opcodes_db = "./dbs/good-opcodes%s.db" % db_identifier
        imphashes_db = "./dbs/good-imphashes%s.db" % db_identifier
        exports_db = "./dbs/good-exports%s.db" % db_identifier

        # Strings -----------------------------------------------------
        print("[+] Updating %s ..." % strings_db)
        good_pickle = load(get_abs_path(strings_db))
        print("Old string database entries: %s" % len(good_pickle))
        good_pickle.update(good_strings_db)
        print("New string database entries: %s" % len(good_pickle))
        save(good_pickle, strings_db)

        # Opcodes -----------------------------------------------------
        print("[+] Updating %s ..." % opcodes_db)
        good_opcode_pickle = load(get_abs_path(opcodes_db))
        print("Old opcode database entries: %s" % len(good_opcode_pickle))
        good_opcode_pickle.update(good_opcodes_db)
        print("New opcode database entries: %s" % len(good_opcode_pickle))
        save(good_opcode_pickle, opcodes_db)

        # Imphashes ---------------------------------------------------
        print("[+] Updating %s ..." % imphashes_db)
        good_imphashes_pickle = load(get_abs_path(imphashes_db))
        print("Old opcode database entries: %s" % len(good_imphashes_pickle))
        good_imphashes_pickle.update(good_imphashes_db)
        print("New opcode database entries: %s" % len(good_imphashes_pickle))
        save(good_imphashes_pickle, imphashes_db)

        # Exports -----------------------------------------------------
        print("[+] Updating %s ..." % exports_db)
        good_exports_pickle = load(get_abs_path(exports_db))
        print("Old opcode database entries: %s" % len(good_exports_pickle))
        good_exports_pickle.update(good_exports_db)
        print("New opcode database entries: %s" % len(good_exports_pickle))
        save(good_exports_pickle, exports_db)

    if args.update:
        click.echo(f"[+] Updating goodware database with samples from {args.goodware_path}")
        # from app.dbs import update_goodware_db
        # update_goodware_db(args)
    else:
        click.echo("[+] Creating local database ...")
        # Evaluate the database identifiers
        db_identifier = ""
        if args.i != "":
            db_identifier = "-%s" % args.i
        strings_db = "./dbs/good-strings%s.db" % db_identifier
        opcodes_db = "./dbs/good-opcodes%s.db" % db_identifier
        imphashes_db = "./dbs/good-imphashes%s.db" % db_identifier
        exports_db = "./dbs/good-exports%s.db" % db_identifier

        # Creating the databases
        click.echo("[+] Using '%s' as filename for newly created strings database" % strings_db)
        click.echo("[+] Using '%s' as filename for newly created opcodes database" % opcodes_db)
        click.echo("[+] Using '%s' as filename for newly created opcodes database" % imphashes_db)
        click.echo("[+] Using '%s' as filename for newly created opcodes database" % exports_db)

        for file in [strings_db, opcodes_db, imphashes_db, exports_db]:
            if os.path.isfile(file):
                input("File %s alread exists. Press enter to proceed or CTRL+C to exit." % file)
                os.remove(file)

        # Strings
        good_json = good_strings_db
        # Opcodes
        good_op_json = good_opcodes_db
        # Imphashes
        good_imphashes_json = good_imphashes_db
        # Exports
        good_exports_json = good_exports_db

        # Save
        save(good_json, strings_db)
        save(good_op_json, opcodes_db)
        save(good_imphashes_json, imphashes_db)
        save(good_exports_json, exports_db)

        click.echo(
            "New database with %d string, %d opcode, %d imphash, %d export entries created. "
            "(remember to use --opcodes to extract opcodes from the samples and create the opcode databases)"
            % (
                len(good_strings_db),
                len(good_opcodes_db),
                len(good_imphashes_db),
                len(good_exports_db),
            )
        )


@cli.command()
def update():
    """Update the local strings and opcodes databases from the online repository"""
    args = type("Args", (), {})()
    dbs.update_databases(args)
    click.echo("[+] Updated databases - you can now start creating YARA rules")


@cli.command()
@click.option("-m", "--malware-path", required=True, help="Path to monitor for malware samples")
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
@click.option("-o", "--output-rule-file", help="Output rule file", default="yarobot_rules.yar")
@click.option("-a", "--author", help="Author Name", default="yarobot Rule Generator")
@click.option("--opcodes", help="Use the OpCode feature", is_flag=True, default=False)
@click.option("--debug", help="Debug output", is_flag=True, default=False)
def dropzone(**kwargs):
    """Dropzone mode - monitor directory for new samples and generate rules automatically"""
    args = type("Args", (), kwargs)()

    click.echo(f"[+] Starting dropzone mode, monitoring {args.malware_path}")
    click.echo("[!] WARNING: Processed files will be deleted!")

    while True:
        if len(os.listdir(args.m)) > 0:
            # Deactivate super rule generation if there's only a single file in the folder
            if len(os.listdir(args.m)) < 2:
                args.nosuper = True
            else:
                args.nosuper = False
            # Read a new identifier
            identifier = getIdentifier(args.b, args.m)
            # Read a new reference
            reference = getReference(args.ref)
            # Generate a new description prefix
            prefix = getPrefix(args.p, identifier)
            # Process the samples
            processSampleDir(args.m)
            # Delete all samples from the dropzone folder
            emptyFolder(args.m)
        time.sleep(1)


# MAIN ################################################################
if __name__ == "__main__":
    logging.basicConfig(level=os.environ.get("YAROBOT_LOG_LEVEL", "INFO"))
    logging.getLogger().setLevel(logging.DEBUG)
    cli()
    # Identifier
