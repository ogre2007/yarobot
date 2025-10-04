import argparse
import os
import sys

import dbs


def get_args():
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

    return args
