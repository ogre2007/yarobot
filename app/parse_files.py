import binascii
from collections import Counter
import os
import traceback
from dataclasses import dataclass, field

from hashlib import sha256
from app.rule_generator import generate_rules
from app.scoring import sample_string_evaluation

import yarobot_rs


@dataclass
class StringInfo:
    def __init__(
        self,
        count: int,
        is_utf16: bool = False,
        files: list[str] | None = None,
    ):
        self.count = count
        self.is_utf16 = is_utf16
        self.files = [] if files is None else files

    def __str__(self):
        if self.is_utf16:
            return "UTF16: %s" % self.count
        else:
            return "%s" % self.count


def extract_strings(fileData, min_len: int = 5, max_len: int = 128): 
    strings = {
        s[0]: StringInfo(s[1])
        for s in yarobot_rs.extract_strings(fileData, min_len, max_len, False)
    }
    utf16_strings = {
        s[0]: StringInfo(s[1], True)
        for s in yarobot_rs.extract_strings(fileData, min_len, max_len, True)
    }
    return strings, utf16_strings


RELEVANT_EXTENSIONS = [
    ".asp",
    ".vbs",
    ".ps",
    ".ps1",
    ".tmp",
    ".bas",
    ".bat",
    ".cmd",
    ".com",
    ".cpl",
    ".crt",
    ".dll",
    ".exe",
    ".msc",
    ".scr",
    ".sys",
    ".vb",
    ".vbe",
    ".vbs",
    ".wsc",
    ".wsf",
    ".wsh",
    ".input",
    ".war",
    ".jsp",
    ".php",
    ".asp",
    ".aspx",
    ".psd1",
    ".psm1",
    ".py",
]


def parse_sample_dir(
    dir, state, notRecursive=False, generateInfo=False, onlyRelevantExtensions=False
):
    # Prepare dictionary
    string_stats = {}
    utf16string_stats = {}
    opcode_stats = {}
    file_info = {}
    known_sha1sums = []

    for filePath in yarobot_rs.get_files(dir, notRecursive):
        try:
            print("[+] Processing %s ..." % filePath)

            # Get Extension
            extension = os.path.splitext(filePath)[1].lower()
            if not extension in RELEVANT_EXTENSIONS and onlyRelevantExtensions:
                if state.args.debug:
                    print("[-] EXTENSION %s - Skipping file %s" % (extension, filePath))
                continue

            # Info file check
            if os.path.basename(filePath) == os.path.basename(
                state.args.b
            ) or os.path.basename(filePath) == os.path.basename(state.args.r):
                continue

            # Size Check
            size = 0
            try:
                size = os.stat(filePath).st_size
                if size > (state.args.fs * 1024 * 1024):
                    if state.args.debug:
                        print(
                            "[-] File is to big - Skipping file %s (use -fs to adjust this behaviour)"
                            % (filePath)
                        )
                    continue
            except Exception as e:
                pass

            # Check and read file
            try:
                with open(filePath, "rb") as f:
                    fileData = f.read()
            except Exception as e:
                print("[-] Cannot read file - skipping %s" % filePath)

            # Extract strings from file
            # Respect CLI min/max lengths
            min_len = int(getattr(state.args, "y", 8))
            max_len = int(getattr(state.args, "s", 128))
            strings, utf16strings = extract_strings(fileData, min_len, max_len)
            for s in strings:
                strings[s].files = set(set(strings[s].files) | {filePath})
            for s in utf16strings:
                utf16strings[s].files = set(set(utf16strings[s].files) | {filePath})
            # print(strings, utf16strings)
            # Extract opcodes from file
            opcodes = []
            if state.args.opcodes:
                print("[-] Extracting OpCodes: %s" % filePath)
                opcodes = yarobot_rs.extract_opcodes(fileData)

            # Add sha256 value
            if generateInfo:
                sha256sum = sha256(fileData).hexdigest()
                file_info[filePath] = {}
                file_info[filePath]["hash"] = sha256sum
                file_info[filePath]["imphash"], file_info[filePath]["exports"] = (
                    yarobot_rs.get_pe_info(fileData)
                )

            # Skip if hash already known - avoid duplicate files
            if sha256sum in known_sha1sums:
                # if state.args.debug:
                print(
                    "[-] Skipping strings/opcodes from %s due to MD5 duplicate detection"
                    % filePath
                )
                continue
            else:
                known_sha1sums.append(sha256sum)

            # Magic evaluation
            if not state.args.nomagic:
                file_info[filePath]["magic"] = binascii.hexlify(fileData[:2]).decode(
                    "ascii"
                )
            else:
                file_info[filePath]["magic"] = ""

            # File Size
            file_info[filePath]["size"] = os.stat(filePath).st_size


            def merge_stats(new_stats, old_stats):
                for string, info in new_stats.items():
                    if string not in old_stats:
                        old_stats[string] = info

                    elif info.is_utf16 == old_stats[string].is_utf16:
                        old_stats[string].count += new_stats[string].count
                        for f in new_stats[string].files:
                            if f not in old_stats[string].files:
                                old_stats[string].files.update(f)
                    else:
                        raise ValueError("String %s has different encoding" % string)

            merge_stats(strings, string_stats)
            merge_stats(utf16strings, utf16string_stats)

            # Add opcodes to statistics
            for opcode in opcodes:
                # Opcode is not already known
                if opcode not in opcode_stats:
                    opcode_stats[opcode] = {}
                    opcode_stats[opcode]["count"] = 0
                    opcode_stats[opcode]["files"] = [] 
                # Opcode count
                opcode_stats[opcode]["count"] += 1 
                if filePath not in opcode_stats[opcode]["files"]:
                    opcode_stats[opcode]["files"].append(filePath)

            if state.args.debug:
                print(
                    "[+] Processed "
                    + filePath
                    + " Size: "
                    + str(size)
                    + " Strings: "
                    + str(len(string_stats))
                    + " OpCodes: "
                    + str(len(opcode_stats))
                    + " ... "
                )

        except Exception as e:
            traceback.print_exc()
            print("[E] ERROR reading file: %s" % filePath)

    return string_stats, opcode_stats, file_info, utf16string_stats


def parse_good_dir(state, dir, notRecursive=False, onlyRelevantExtensions=True):
    # Prepare dictionary
    all_strings = Counter()
    all_opcodes = Counter()
    all_imphashes = Counter()
    all_exports = Counter()

    for filePath in yarobot_rs.get_files(dir, notRecursive):
        # Get Extension
        extension = os.path.splitext(filePath)[1].lower()
        if extension not in RELEVANT_EXTENSIONS and onlyRelevantExtensions:
            if state.args.debug:
                print("[-] EXTENSION %s - Skipping file %s" % (extension, filePath))
            continue

        # Size Check
        size = 0
        try:
            size = os.stat(filePath).st_size
            if size > (state.args.fs * 1024 * 1024):
                continue
        except Exception as e:
            pass

        # Check and read file
        try:
            with open(filePath, "rb") as f:
                fileData = f.read()
        except Exception as e:
            print("[-] Cannot read file - skipping %s" % filePath)

        # Extract strings from file
        min_len = int(getattr(state.args, "y", 8))
        max_len = int(getattr(state.args, "s", 128))
        strings_map, utf16_map = extract_strings(fileData, min_len, max_len)
        # Merge ASCII
        all_strings.update({s: info.count for s, info in strings_map.items()})
        # Merge UTF16 (store as plain for goodware DB usage)
        all_strings.update({s: info.count for s, info in utf16_map.items()})

        # Extract Opcodes from file
        opcodes = []
        if state.args.opcodes:
            print("[-] Extracting OpCodes: %s" % filePath)
            opcodes = yarobot_rs.extract_opcodes(fileData)
            # Append to all opcodes
            all_opcodes.update(opcodes)

        # Imphash and Exports
        (imphash, exports) = yarobot_rs.get_pe_info(fileData)
        if imphash != "":
            all_imphashes.update([imphash])
        all_exports.update(exports)
        if state.args.debug:
            print(
                "[+] Processed %s - %d strings %d opcodes %d exports and imphash %s"
                % (filePath, len(all_strings), len(opcodes), len(exports), imphash)
            )

    # return it as a set (unique strings)
    return all_strings, all_opcodes, all_imphashes, all_exports


def processSampleDir(targetDir, state):
    """
    Processes samples in a given directory and creates a yara rule file
    :param directory:
    :return:
    """

    # Extract all information
    (sample_string_stats, sample_opcode_stats, file_info, sample_utf16string_stats) = (
        parse_sample_dir(
            targetDir,
            state,
            state.args.nr,
            generateInfo=True,
            onlyRelevantExtensions=state.args.oe,
        )
    )

    # Evaluate Strings
    (file_strings, file_opcodes, combinations, super_rules) = (
        sample_string_evaluation(
            sample_string_stats,
            sample_opcode_stats,
            file_info,
            state,
            sample_utf16string_stats,
        )
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
