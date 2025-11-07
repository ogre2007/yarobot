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
import logging

import time

from .common import (
    emptyFolder,
    getIdentifier,
    getPrefix,
    getReference,
    initialize_pestudio_strings,
    load,
    load_databases,
    load_db,
    common_multi_analysis_options,
    common_single_analysis_options,
)

import pstats

import cProfile
from .rule_generator import RuleGenerator

# from app.scoring import extract_stats_by_file, sample_string_evaluation
from .config import RELEVANT_EXTENSIONS

from yarobot import yarobot_rs

import click
import os


def process_bytes(
    fp: yarobot_rs.FileProcessor,
    se: yarobot_rs.ScoringEngine,
    args,
    data: bytes,
    good_strings_db={},
    good_opcodes_db={},
    good_imphashes_db={},
    good_exports_db={},
    pestudio_strings={},
):
    logging.getLogger("yarobot").info(f"[+] Generating YARA rules from buffer len {len(data)}")
    # print(fp, se)

    (
        file_infos,
        file_strings,
        file_opcodes,
        file_utf16strings,
    ) = yarobot_rs.process_buffer(data, fp, se)
    # print(file_strings)
    file_strings = {fpath: strings for fpath, strings in file_strings.items()}

    file_opcodes = {fpath: opcodes for fpath, opcodes in file_opcodes.items()}

    file_utf16strings = {fpath: utf16strings for fpath, utf16strings in file_utf16strings.items()}

    # Create Rule Files
    rg = RuleGenerator(args, se)
    (rule_count, super_rule_count, rules) = rg.generate_rules(
        file_strings,
        file_opcodes,
        file_utf16strings,
        [],
        [],
        [],
        file_infos,
    )

    print("[=] Generated %s SIMPLE rules." % str(rule_count))
    if not args.nosuper:
        print("[=] Generated %s SUPER rules." % str(super_rule_count))
    print("[=] All rules written to %s" % args.output_rule_file)
    return rules


def process_folder(
    args,
    folder,
    good_strings_db={},
    good_opcodes_db={},
    good_imphashes_db={},
    good_exports_db={},
    pestudio_strings={},
):
    if args.opcodes and len(good_opcodes_db) < 1:
        logging.getLogger("yarobot").warning(
            "Missing goodware opcode databases.    Please run 'yarobot update' to retrieve the newest database set."
        )
        args.opcodes = False

    if len(good_exports_db) < 1 and len(good_imphashes_db) < 1:
        logging.getLogger("yarobot").warning(
            "Missing goodware imphash/export databases.     Please run 'yarobot update' to retrieve the newest database set."
        )

    if len(good_strings_db) < 1:
        logging.getLogger("yarobot").warning(
            "no goodware databases found.     Please run 'yarobot update' to retrieve the newest database set."
        )
        # sys.exit(1)

    # Scan malware files
    fp, se = yarobot_rs.init_analysis(
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
        pestudio_strings,
    )

    logging.getLogger("yarobot").info(f"[+] Generating YARA rules from {folder}")
    (
        combinations,
        super_rules,
        utf16_combinations,
        utf16_super_rules,
        opcode_combinations,
        opcode_super_rules,
        file_strings,
        file_opcodes,
        file_utf16strings,
        file_info,
    ) = yarobot_rs.process_malware(folder, fp, se)
    # Apply intelligent filters
    logging.getLogger("yarobot").info("[-] Applying intelligent filters to string findings ...")
    file_strings = {fpath: se.filter_string_set(strings) for fpath, strings in file_strings.items()}

    file_opcodes = {fpath: se.filter_opcode_set(opcodes) for fpath, opcodes in file_opcodes.items()}

    file_utf16strings = {fpath: se.filter_string_set(utf16strings) for fpath, utf16strings in file_utf16strings.items()}

    # Create Rule Files
    rg = RuleGenerator(args, se)
    (rule_count, super_rule_count, rules) = rg.generate_rules(
        file_strings,
        file_opcodes,
        file_utf16strings,
        super_rules,
        opcode_super_rules,
        utf16_super_rules,
        file_info,
    )

    print("[=] Generated %s SIMPLE rules." % str(rule_count))
    if not args.nosuper:
        print("[=] Generated %s SUPER rules." % str(super_rule_count))
    print("[=] All rules written to %s" % args.output_rule_file)
    return rules


@click.group()
def cli():
    pass


@cli.command()
@click.argument("malware_path", type=click.Path(exists=True))
@common_single_analysis_options
@common_multi_analysis_options
def generate(malware_path, **kwargs):
    pr = cProfile.Profile()
    pr.enable()
    """Generate YARA rules from malware samples"""
    args = type("Args", (), kwargs)()

    args.identifier = getIdentifier(args.identifier, malware_path)
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
    # exit()
    process_folder(
        args,
        malware_path,
        good_strings_db,
        good_opcodes_db,
        good_imphashes_db,
        good_exports_db,
        pestudio_strings,
    )
    pr.disable()

    stats = pstats.Stats(pr)
    stats.sort_stats("cumulative").print_stats(10)  # Sort by cumulative time and print top 10


@cli.command()
@click.argument("malware_path", type=click.Path(exists=True))
@common_single_analysis_options
@common_multi_analysis_options
def dropzone(malware_path, **kwargs):
    """Dropzone mode - monitor directory for new samples and generate rules automatically"""
    args = type("Args", (), kwargs)()

    click.echo(f"[+] Starting dropzone mode, monitoring {malware_path}")
    click.echo("[!] WARNING: Processed files will be deleted!")

    while True:
        if len(os.listdir(malware_path)) > 0:
            # Deactivate super rule generation if there's only a single file in the folder
            if len(os.listdir(malware_path)) < 2:
                args.nosuper = True
            else:
                args.nosuper = False
            # Read a new identifier
            identifier = getIdentifier(args.b, malware_path)
            # Read a new reference
            reference = getReference(args.ref)
            # Generate a new description prefix
            prefix = getPrefix(args.p, identifier)
            # Process the samples
            processSampleDir(malware_path)
            # Delete all samples from the dropzone folder
            emptyFolder(malware_path)
        time.sleep(1)


# MAIN ################################################################
if __name__ == "__main__":
    logging.basicConfig(level=os.environ.get("YAROBOT_LOG_LEVEL", "INFO"))
    logging.getLogger().setLevel(logging.DEBUG)
    generate()
    # Identifier
