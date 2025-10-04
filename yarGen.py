#!/usr/bin/env python
# -*- coding: iso-8859-1 -*-
# -*- coding: utf-8 -*-
#
# yarGen
# A Rule Generator for YARA Rules
#
# Florian Roth

__version__ = "0.24.0"

from json import load
import os
import sys

import argparse
import traceback
import time
from collections import Counter
import signal as signal_module

import dbs
from parse_files import parse_good_dir, processSampleDir
from utils import (
    emptyFolder,
    get_abs_path,
    getIdentifier,
    getPrefix,
    getReference,
    initialize_pestudio_strings,
    save,
)


class State:
    def __init__(
        self,
        args,
        good_strings_db,
        good_opcodes_db,
        good_imphashes_db,
        good_exports_db,
        pestudio_available,
        pestudio_strings,
    ):
        self.base64strings = {}
        self.reversedStrings = {}
        self.hexEncStrings = {}
        self.pestudioMarker = {}
        self.stringScores = {}
        self.good_strings_db = (good_strings_db,)
        self.good_opcodes_db = (good_opcodes_db,)
        self.good_imphashes_db = (good_imphashes_db,)
        good_exports_db = (good_exports_db,)
        self.pestudio_available = (pestudio_available,)
        self.pestudio_strings = (pestudio_strings,)
        self.args = (args,)


# CTRL+C Handler --------------------------------------------------------------
def signal_handler(signal_name, frame):
    print("> yarGen's work has been interrupted")
    sys.exit(0)


def print_welcome():
    print("------------------------------------------------------------------------")
    print("                   _____            ")
    print("    __ _____ _____/ ___/__ ___      ")
    print("   / // / _ `/ __/ (_ / -_) _ \\     ")
    print("   \\_, /\\_,_/_/  \\___/\\__/_//_/     ")
    print("  /___/  Yara Rule Generator        ")
    print("         Florian Roth, August 2023, Version %s" % __version__)
    print("   ")
    print("  Note: Rules have to be post-processed")
    print("  See this post for details: https://medium.com/@cyb3rops/121d29322282")
    print("------------------------------------------------------------------------")


# MAIN ################################################################
if __name__ == "__main__":

    # Signal handler for CTRL+C
    signal_module.signal(signal_module.SIGINT, signal_handler)

    # Parse Arguments
    parser = argparse.ArgumentParser(description="yarGen")

    group_creation = parser.add_argument_group("Rule Creation")
    group_creation.add_argument("-m", help="Path to scan for malware")
    group_creation.add_argument(
        "-y",
        help="Minimum string length to consider (default=8)",
        metavar="min-size",
        default=8,
    )
    group_creation.add_argument(
        "-z",
        help="Minimum score to consider (default=0)",
        metavar="min-score",
        default=0,
    )
    group_creation.add_argument(
        "-x",
        help="Score required to set string as 'highly specific string' (default: 30)",
        metavar="high-scoring",
        default=30,
    )
    group_creation.add_argument(
        "-w",
        help="Minimum number of strings that overlap to create a super rule (default: 5)",
        metavar="superrule-overlap",
        default=5,
    )
    group_creation.add_argument(
        "-s",
        help="Maximum length to consider (default=128)",
        metavar="max-size",
        default=128,
        type=int,
    )
    group_creation.add_argument(
        "-rc",
        help="Maximum number of strings per rule (default=20, intelligent filtering "
        "will be applied)",
        metavar="maxstrings",
        default=20,
    )
    group_creation.add_argument(
        "--excludegood",
        help="Force the exclude all goodware strings",
        action="store_true",
        default=False,
    )

    group_output = parser.add_argument_group("Rule Output")
    group_output.add_argument(
        "-o",
        help="Output rule file",
        metavar="output_rule_file",
        default="yargen_rules.yar",
    )
    group_output.add_argument(
        "-e",
        help="Output directory for string exports",
        metavar="output_dir_strings",
        default="",
    )
    group_output.add_argument(
        "-a", help="Author Name", metavar="author", default="yarGen Rule Generator"
    )
    group_output.add_argument(
        "-r",
        help="Reference (can be string or text file)",
        metavar="ref",
        default="https://github.com/Neo23x0/yarGen",
    )
    group_output.add_argument("-l", help="License", metavar="lic", default="")
    group_output.add_argument(
        "-p",
        help="Prefix for the rule description",
        metavar="prefix",
        default="Auto-generated rule",
    )
    group_output.add_argument(
        "-b",
        help="Text file from which the identifier is read (default: last folder name in "
        'the full path, e.g. "myRAT" if -m points to /mnt/mal/myRAT)',
        metavar="identifier",
        default="not set",
    )
    group_output.add_argument(
        "--score",
        help="Show the string scores as comments in the rules",
        action="store_true",
        default=False,
    )
    group_output.add_argument(
        "--strings",
        help="Show the string scores as comments in the rules",
        action="store_true",
        default=False,
    )
    group_output.add_argument(
        "--nosimple",
        help="Skip simple rule creation for files included in super rules",
        action="store_true",
        default=False,
    )
    group_output.add_argument(
        "--nomagic",
        help="Don't include the magic header condition statement",
        action="store_true",
        default=False,
    )
    group_output.add_argument(
        "--nofilesize",
        help="Don't include the filesize condition statement",
        action="store_true",
        default=False,
    )
    group_output.add_argument(
        "-fm",
        help="Multiplier for the maximum 'filesize' condition value (default: 3)",
        default=3,
    )
    group_output.add_argument(
        "--globalrule",
        help="Create global rules (improved rule set speed)",
        action="store_true",
        default=False,
    )
    group_output.add_argument(
        "--nosuper",
        action="store_true",
        default=False,
        help="Don't try to create super rules " "that match against various files",
    )

    group_db = parser.add_argument_group("Database Operations")
    group_db.add_argument(
        "--update",
        action="store_true",
        default=False,
        help="Update the local strings and opcodes " "dbs from the online repository",
    )
    group_db.add_argument(
        "-g",
        help="Path to scan for goodware (dont use the database shipped with yaraGen)",
    )
    group_db.add_argument(
        "-u",
        action="store_true",
        default=False,
        help="Update local standard goodware database with "
        "a new analysis result (used with -g)",
    )
    group_db.add_argument(
        "-c",
        action="store_true",
        default=False,
        help="Create new local goodware database "
        '(use with -g and optionally -i "identifier")',
    )
    group_db.add_argument(
        "-i",
        default="",
        help="Specify an identifier for the newly created databases "
        "(good-strings-identifier.db, good-opcodes-identifier.db)",
    )

    group_general = parser.add_argument_group("General Options")
    group_general.add_argument(
        "--dropzone",
        action="store_true",
        default=False,
        help="Dropzone mode - monitors a directory [-m] for new samples to process. "
        "WARNING: Processed files will be deleted!",
    )
    group_general.add_argument(
        "--nr",
        action="store_true",
        default=False,
        help="Do not recursively scan directories",
    )
    group_general.add_argument(
        "--oe",
        action="store_true",
        default=False,
        help="Only scan executable extensions EXE, "
        "DLL, ASP, JSP, PHP, BIN, INFECTED",
    )
    group_general.add_argument(
        "-fs",
        help="Max file size in MB to analyze (default=10)",
        metavar="size-in-MB",
        default=10,
    )
    group_general.add_argument(
        "--noextras",
        action="store_true",
        default=False,
        help="Don't use extras like Imphash or PE header specifics",
    )
    group_general.add_argument(
        "--ai",
        action="store_true",
        default=False,
        help="Create output to be used as ChatGPT4 input",
    )
    group_general.add_argument(
        "--debug", action="store_true", default=False, help="Debug output"
    )
    group_general.add_argument(
        "--trace", action="store_true", default=False, help="Trace output"
    )

    group_opcode = parser.add_argument_group("Other Features")
    group_opcode.add_argument(
        "--opcodes",
        action="store_true",
        default=False,
        help="Do use the OpCode feature "
        "(use this if not enough high "
        "scoring strings can be found)",
    )
    group_opcode.add_argument(
        "-n",
        help="Number of opcodes to add if not enough high scoring string could be found "
        "(default=3)",
        metavar="opcode-num",
        default=3,
    )

    group_inverse = parser.add_argument_group("Inverse Mode (unstable)")
    group_inverse.add_argument(
        "--inverse", help=argparse.SUPPRESS, action="store_true", default=False
    )
    group_inverse.add_argument(
        "--nodirname", help=argparse.SUPPRESS, action="store_true", default=False
    )
    group_inverse.add_argument(
        "--noscorefilter", help=argparse.SUPPRESS, action="store_true", default=False
    )

    args = parser.parse_args()

    # Print Welcome
    print_welcome()

    if not args.update and not args.m and not args.g:
        parser.print_help()
        print("")
        print(
            """
[E] You have to select --update to update yarGens database or -m for signature generation or -g for the 
creation of goodware string collections 
(see https://github.com/Neo23x0/yarGen#examples for more details)

Recommended command line:
    python yarGen.py -a 'Your Name' --opcodes --dropzone -m ./dropzone"""
        )
        sys.exit(1)

    # Update
    if args.update:
        dbs.update_databases()
        print("[+] Updated databases - you can now start creating YARA rules")
        sys.exit(0)

    # Typical input erros
    if args.m:
        if os.path.isfile(args.m):
            print("[E] Input is a file, please use a directory instead (-m path)")
            sys.exit(0)

    # Opcodes evaluation or not
    args.opcodes = False
    if args.opcodes:
        args.opcodes = True

    # Read PEStudio string list
    pestudio_strings = {}
    pestudio_available = False

    # Identifier
    sourcepath = args.m
    if args.g:
        sourcepath = args.g
    args.identifier = getIdentifier(args.b, sourcepath)
    print("[+] Using identifier '%s'" % args.identifier)

    # Reference
    args.reference = getReference(args.r)
    print("[+] Using reference '%s'" % args.reference)

    # Prefix
    args.prefix = getPrefix(args.p, args.identifier)
    print("[+] Using prefix '%s'" % args.prefix)

    if strs := initialize_pestudio_strings():
        pestudio_available = True
        pestudio_strings = strs

    # Highly specific string score
    args.score_highly_specific = int(args.x)

    # Scan goodware files
    if args.g:
        print("[+] Processing goodware files ...")
        good_strings_db, good_opcodes_db, good_imphashes_db, good_exports_db = (
            parse_good_dir(args, args.g, args.nr, args.oe)
        )

        # Update existing databases
        if args.u:
            try:
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

            except Exception as e:
                traceback.print_exc()

        # Create new databases
        if args.c:
            print("[+] Creating local database ...")
            # Evaluate the database identifiers
            db_identifier = ""
            if args.i != "":
                db_identifier = "-%s" % args.i
            strings_db = "./dbs/good-strings%s.db" % db_identifier
            opcodes_db = "./dbs/good-opcodes%s.db" % db_identifier
            imphashes_db = "./dbs/good-imphashes%s.db" % db_identifier
            exports_db = "./dbs/good-exports%s.db" % db_identifier

            # Creating the databases
            print(
                "[+] Using '%s' as filename for newly created strings database"
                % strings_db
            )
            print(
                "[+] Using '%s' as filename for newly created opcodes database"
                % opcodes_db
            )
            print(
                "[+] Using '%s' as filename for newly created opcodes database"
                % imphashes_db
            )
            print(
                "[+] Using '%s' as filename for newly created opcodes database"
                % exports_db
            )

            try:

                if os.path.isfile(strings_db):
                    input(
                        "File %s alread exists. Press enter to proceed or CTRL+C to exit."
                        % strings_db
                    )
                    os.remove(strings_db)
                if os.path.isfile(opcodes_db):
                    input(
                        "File %s alread exists. Press enter to proceed or CTRL+C to exit."
                        % opcodes_db
                    )
                    os.remove(opcodes_db)
                if os.path.isfile(imphashes_db):
                    input(
                        "File %s alread exists. Press enter to proceed or CTRL+C to exit."
                        % imphashes_db
                    )
                    os.remove(imphashes_db)
                if os.path.isfile(exports_db):
                    input(
                        "File %s alread exists. Press enter to proceed or CTRL+C to exit."
                        % exports_db
                    )
                    os.remove(exports_db)

                # Strings
                good_json = Counter()
                good_json = good_strings_db
                # Opcodes
                good_op_json = Counter()
                good_op_json = good_opcodes_db
                # Imphashes
                good_imphashes_json = Counter()
                good_imphashes_json = good_imphashes_db
                # Exports
                good_exports_json = Counter()
                good_exports_json = good_exports_db

                # Save
                save(good_json, strings_db)
                save(good_op_json, opcodes_db)
                save(good_imphashes_json, imphashes_db)
                save(good_exports_json, exports_db)

                print(
                    "New database with %d string, %d opcode, %d imphash, %d export entries created. "
                    "(remember to use --opcodes to extract opcodes from the samples and create the opcode databases)"
                    % (
                        len(good_strings_db),
                        len(good_opcodes_db),
                        len(good_imphashes_db),
                        len(good_exports_db),
                    )
                )
            except Exception as e:
                traceback.print_exc()

    # Analyse malware samples and create rules
    else:
        print("[+] Reading goodware strings from database 'good-strings.db' ...")
        print(
            "    (This could take some time and uses several Gigabytes of RAM depending on your db size)"
        )

        good_strings_db = Counter()
        good_opcodes_db = Counter()
        good_imphashes_db = Counter()
        good_exports_db = Counter()

        opcodes_num = 0
        strings_num = 0
        imphash_num = 0
        exports_num = 0

        # Initialize all databases
        for file in os.listdir(get_abs_path("./dbs/")):
            if not file.endswith(".db"):
                continue
            filePath = os.path.join("./dbs/", file)
            # String databases
            if file.startswith("good-strings"):
                try:
                    print("[+] Loading %s ..." % filePath)
                    good_json = load(get_abs_path(filePath))
                    good_strings_db.update(good_json)
                    print(
                        "[+] Total: %s / Added %d entries"
                        % (len(good_strings_db), len(good_strings_db) - strings_num)
                    )
                    strings_num = len(good_strings_db)
                except Exception as e:
                    traceback.print_exc()
            # Opcode databases
            if file.startswith("good-opcodes"):
                try:
                    if args.opcodes:
                        print("[+] Loading %s ..." % filePath)
                        good_op_json = load(get_abs_path(filePath))
                        good_opcodes_db.update(good_op_json)
                        print(
                            "[+] Total: %s (removed duplicates) / Added %d entries"
                            % (len(good_opcodes_db), len(good_opcodes_db) - opcodes_num)
                        )
                        opcodes_num = len(good_opcodes_db)
                except Exception as e:
                    args.opcodes = False
                    traceback.print_exc()
            # Imphash databases
            if file.startswith("good-imphash"):
                try:
                    print("[+] Loading %s ..." % filePath)
                    good_imphashes_json = load(get_abs_path(filePath))
                    good_imphashes_db.update(good_imphashes_json)
                    print(
                        "[+] Total: %s / Added %d entries"
                        % (len(good_imphashes_db), len(good_imphashes_db) - imphash_num)
                    )
                    imphash_num = len(good_imphashes_db)
                except Exception as e:
                    traceback.print_exc()
            # Export databases
            if file.startswith("good-exports"):
                try:
                    print("[+] Loading %s ..." % filePath)
                    good_exports_json = load(get_abs_path(filePath))
                    good_exports_db.update(good_exports_json)
                    print(
                        "[+] Total: %s / Added %d entries"
                        % (len(good_exports_db), len(good_exports_db) - exports_num)
                    )
                    exports_num = len(good_exports_db)
                except Exception as e:
                    traceback.print_exc()

        if args.opcodes and len(good_opcodes_db) < 1:
            print(
                "[E] Missing goodware opcode databases."
                "    Please run 'yarGen.py --update' to retrieve the newest database set."
            )
            args.opcodes = False

        if len(good_exports_db) < 1 and len(good_imphashes_db) < 1:
            print(
                "[E] Missing goodware imphash/export databases. "
                "    Please run 'yarGen.py --update' to retrieve the newest database set."
            )

        if len(good_strings_db) < 1 and not args.c:
            print(
                "[E] Error - no goodware databases found. "
                "    Please run 'yarGen.py --update' to retrieve the newest database set."
            )
            sys.exit(1)

    # If malware directory given
    if args.m:
        # Deactivate super rule generation if there's only a single file in the folder
        if len(os.listdir(args.m)) < 2:
            args.nosuper = True

        # AI input generation
        args.strings_per_rule = int(args.rc)
        if args.ai:
            args.strings_per_rule = 200

        # Special strings
        state = State(
            args,
            good_strings_db,
            good_opcodes_db,
            good_imphashes_db,
            good_exports_db,
            pestudio_available,
            pestudio_strings,
        )
        # Dropzone mode
        if args.dropzone:
            # Monitoring folder for changes
            print(
                "Monitoring %s for new sample files (processed samples will be removed)"
                % args.m
            )
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
                    reference = getReference(args.r)
                    # Generate a new description prefix
                    prefix = getPrefix(args.p, identifier)
                    # Process the samples
                    processSampleDir(args.m, state)
                    # Delete all samples from the dropzone folder
                    emptyFolder(args.m)
                time.sleep(1)
        else:
            # Scan malware files
            print("[+] Processing malware files ...")
            processSampleDir(args.m, state)

        print("[+] yarGen run finished")
