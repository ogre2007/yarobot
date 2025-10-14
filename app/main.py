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

from app.args import get_args
from app.config import DB_PATH, PE_STRINGS_FILE


from app.rule_generator import generate_rules
from app.scoring import extract_stats_by_file, sample_string_evaluation
from app.config import RELEVANT_EXTENSIONS

import yarobot_rs


def parse_good_dir(state, dir):
    print(":: Parsing good samples ...")
    fp = yarobot_rs.FileProcessor(
        state.args.R,
        state.args.oe,
        RELEVANT_EXTENSIONS,
        state.args.y,
        state.args.s,
        state.args.fs,
        state.args.opcodes,
        state.args.debug,
    )
    return fp.parse_sample_dir(dir)


def processSampleDir(targetDir, state):
    """
    Processes samples in a given directory and creates a yara rule file
    :param directory:
    :return:
    """

    fp = yarobot_rs.FileProcessor(
        state.args.R,
        state.args.oe,
        RELEVANT_EXTENSIONS,
        state.args.y,
        state.args.s,
        state.args.fs,
        state.args.opcodes,
        state.args.debug,
    )
    # Extract all information
    (sample_string_stats, sample_opcode_stats, sample_utf16string_stats, file_info) = (
        fp.parse_sample_dir(targetDir)
    )
    """
    for k, v in sample_string_stats.items():
        #print(v.files)
        print(k, v)

    exit() 
    """
    file_strings = {}
    file_utf16strings = {}
    file_opcodes = {}
    # OPCODE EVALUATION -----------------------------------------------
    extract_stats_by_file(sample_string_stats, file_opcodes, lambda x: x < 10)

    # STRING EVALUATION -------------------------------------------------------
    extract_stats_by_file(sample_opcode_stats, file_strings)

    extract_stats_by_file(sample_utf16string_stats, file_utf16strings)
    # Evaluate Strings
    if not state.args.nosuper:
        (combinations, super_rules) = sample_string_evaluation(
            state,
            sample_string_stats,
            sample_opcode_stats,
            sample_utf16string_stats,
            file_strings if state.args.nosimple else None,
            file_utf16strings if state.args.nosimple else None,
            file_opcodes if state.args.nosimple else None,
        )

    # Create Rule Files
    (rule_count, super_rule_count) = generate_rules(
        state,
        file_strings,
        file_opcodes,
        super_rules,
        file_info,
    )

    print("[=] Generated %s SIMPLE rules." % str(rule_count))
    if not state.args.nosuper:
        print("[=] Generated %s SUPER rules." % str(super_rule_count))
    print("[=] All rules written to %s" % state.args.o)


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


def load_db(file, local_counter, prefix):
    if file.startswith(prefix):
        try:
            filePath = os.path.join(DB_PATH, file)
            print("[+] Loading %s ..." % filePath)
            before = len(local_counter)
            js = load(get_abs_path(filePath))
            local_counter.update(js)
            added = len(local_counter) - before
            print("[+] Total: %s / Added %d entries" % (len(local_counter), added))
        except Exception:
            traceback.print_exc()
    return len(local_counter)


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
        self.good_strings_db = good_strings_db
        self.good_opcodes_db = good_opcodes_db
        self.good_imphashes_db = good_imphashes_db
        self.good_exports_db = good_exports_db
        self.pestudio_available = pestudio_available
        self.pestudio_strings = pestudio_strings
        self.args = args
        self.string_to_comms = dict()


# CTRL+C Handler --------------------------------------------------------------
def signal_handler(signal_name, frame):
    print("> yarobot's work has been interrupted")
    sys.exit(0)


# MAIN ################################################################
if __name__ == "__main__":
    logging.basicConfig(level=os.environ.get("YAROBOT_LOG_LEVEL", "WARNING"))
    # Signal handler for CTRL+C
    signal_module.signal(signal_module.SIGINT, signal_handler)
    args = get_args()
    # Read PEStudio string list
    pestudio_strings = {}
    pestudio_available = False

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    # Identifier
    sourcepath = args.m
    if args.g:
        sourcepath = args.g
    args.identifier = getIdentifier(args.b, sourcepath)
    print("[+] Using identifier '%s'" % args.identifier)

    # Reference
    args.ref = getReference(args.ref)
    print("[+] Using reference '%s'" % args.ref)

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
        state = State(
            args, None, None, None, None, pestudio_available, pestudio_strings
        )
        good_strings_db, good_opcodes_db, good_imphashes_db, good_exports_db = (
            parse_good_dir(state, args.g)
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

            except Exception:
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
                for file in [strings_db, opcodes_db, imphashes_db, exports_db]:
                    if os.path.isfile(file):
                        input(
                            "File %s alread exists. Press enter to proceed or CTRL+C to exit."
                            % file
                        )
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
            except Exception:
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
        for file in os.listdir(get_abs_path(DB_PATH)):
            if not file.endswith(".db"):
                continue  # String databases
            strings_num = load_db(file, good_strings_db, "good-strings")
            opcodes_num = load_db(file, good_opcodes_db, "good-opcodes")
            imphash_num = load_db(file, good_imphashes_db, "good-imphash")
            exports_num = load_db(file, good_exports_db, "good-exports")

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
                    reference = getReference(args.ref)
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
