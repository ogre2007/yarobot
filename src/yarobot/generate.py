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

from .common import (
    getIdentifier,
    getPrefix,
    getReference,
    initialize_pestudio_strings,
    load_databases,
    common_multi_analysis_options,
    common_single_analysis_options,
)

import pstats

import cProfile
from .rule_generator import RuleGenerator

from .config import RELEVANT_EXTENSIONS

import stringzz

import click


def print_generated_stats(args, rule_count, super_rule_count):
    print("[=] Generated %s SIMPLE rules." % str(rule_count))
    if not args.nosuper:
        print("[=] Generated %s SUPER rules." % str(super_rule_count))
    if "output_rule_file" in args.__dict__.keys() and args.output_rule_file:
        print("[=] All rules written to %s" % args.output_rule_file)


def process_buffers(
    fp: stringzz.FileProcessor,
    se: stringzz.ScoringEngine,
    args,
    data: list[bytes],
    good_strings_db={},
    good_opcodes_db={},
    good_imphashes_db={},
    good_exports_db={},
    pestudio_strings={},
):
    logging.getLogger("yarobot").info(
        f"[+] Generating YARA rules from  {len(data)} buffers "
    )
    # print(fp, se)

    print("excludegood", args.excludegood)
    (
        string_combis,
        string_superrules,
        utf16_combis,
        utf16_superrules,
        opcode_combis,
        opcode_superrules,
        file_strings,
        file_opcodes,
        file_utf16strings,
        file_infos,
    ) = stringzz.analyze_buffers_comprehensive(data, fp, se)
    # print(file_strings)
    # Create Rule Files
    rg = RuleGenerator(args, se)
    print("fs", file_strings)
    (rule_count, super_rule_count, rules) = rg.generate_rules(
        file_strings,
        file_opcodes,
        file_utf16strings,
        string_superrules,
        opcode_superrules,
        utf16_superrules,
        file_infos,
    )

    print_generated_stats(args, rule_count, super_rule_count)

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
    if args.get_opcodes and len(good_opcodes_db) < 1:
        logging.getLogger("yarobot").warning("Missing goodware opcode databases.")
        args.get_opcodes = False

    if len(good_exports_db) < 1 and len(good_imphashes_db) < 1:
        logging.getLogger("yarobot").warning(
            "Missing goodware imphash/export databases."
        )

    if len(good_strings_db) < 1:
        logging.getLogger("yarobot").warning("no goodware databases found. ")

    # Scan malware files
    config = stringzz.Config(
        recursive=args.recursive,
        extensions=RELEVANT_EXTENSIONS,
        min_string_len=args.min_size,
        max_string_len=args.max_size,
        max_file_size_mb=args.max_file_size,
        extract_opcodes=args.get_opcodes,
        debug=args.debug,
        max_file_count=args.max_file_count if args.max_file_count else None,
    )
    fp, se = stringzz.init_analysis(
        config,
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
    ) = stringzz.process_malware(folder, fp, se)
    # Apply intelligent filters
    logging.getLogger("yarobot").info(
        "[-] Applying intelligent filters to string findings ..."
    )

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

    print_generated_stats(args, rule_count, super_rule_count)
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
    args.goodware_dbs
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
    print(
        "    (This could take some time and uses several Gigabytes of RAM depending on your db size)"
    )

    if args.goodware_dbs:
        good_strings_db, good_opcodes_db, good_imphashes_db, good_exports_db = (
            load_databases(args.goodware_dbs)
        )
    else:
        logging.getLogger("yarobot").warning(
            "No goodware databases found. Please create new databases."
        )
        good_strings_db, good_opcodes_db, good_imphashes_db, good_exports_db = (
            {},
            {},
            {},
            {},
        )
    # exit()
    rules = process_folder(
        args,
        malware_path,
        good_strings_db,
        good_opcodes_db,
        good_imphashes_db,
        good_exports_db,
        pestudio_strings,
    )
    with open(args.output_rule_file, "wt") as f:
        f.write(rules)
    pr.disable()

    stats = pstats.Stats(pr)
    stats.sort_stats("cumulative").print_stats(
        10
    )  # Sort by cumulative time and print top 10


# MAIN ################################################################
if __name__ == "__main__":
    logging.basicConfig(level=os.environ.get("YAROBOT_LOG_LEVEL", "INFO"))
    logging.getLogger().setLevel(logging.DEBUG)
    generate()
    # Identifier
