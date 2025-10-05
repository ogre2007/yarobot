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


import os
import sys

import traceback
import time
from collections import Counter
import signal as signal_module

from app.args import get_args
from app.utils import load
from app.parse_files import parse_good_dir, processSampleDir
from app.utils import (
    emptyFolder,
    get_abs_path,
    getIdentifier,
    getPrefix,
    getReference,
    initialize_pestudio_strings,
    save,
)
from app.config import DB_PATH


def load_db(file, local_counter, prefix):
    if file.startswith(prefix):
        try:
            filePath = os.path.join(DB_PATH, file)
            print("[+] Loading %s ..." % filePath)
            js = load(get_abs_path(filePath))
            local_counter.update(js)
            print(
                "[+] Total: %s / Added %d entries"
                % (len(local_counter), len(local_counter) - strings_num)
            )
        except Exception as e:
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
        self.good_strings_db = (good_strings_db,)
        self.good_opcodes_db = good_opcodes_db
        self.good_imphashes_db = good_imphashes_db
        self.good_exports_db = good_exports_db
        self.pestudio_available = pestudio_available
        self.pestudio_strings = pestudio_strings
        self.args = args
        self.string_to_comms = dict()


# CTRL+C Handler --------------------------------------------------------------
def signal_handler(signal_name, frame):
    print("> yarGen's work has been interrupted")
    sys.exit(0)


def print_welcome():
    print("------------------------------------------------------------------------") 
    print("------------------------------------------------------------------------")


# MAIN ################################################################
if __name__ == "__main__":
    print_welcome()

    # Signal handler for CTRL+C
    signal_module.signal(signal_module.SIGINT, signal_handler)
    args = get_args()
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
                for file in [strings_db, opcodes_db, imphashes_db, exports_db]:

                    if os.path.isfile(file):
                        input(
                            "File %s alread exists. Press enter to proceed or CTRL+C to exit."
                            % file
                        )
                        os.remove(file)

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

