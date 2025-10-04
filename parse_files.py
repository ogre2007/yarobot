import binascii
from collections import Counter
import os
import traceback
from hashlib import sha256
from rule_generator import generate_rules
from scoring import sample_string_evaluation

from utils import extract_opcodes, extract_strings, get_files, get_pe_info


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
    opcode_stats = {}
    file_info = {}
    known_sha1sums = []

    for filePath in get_files(dir, notRecursive):
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
            strings = extract_strings(state.args.s, fileData)

            # Extract opcodes from file
            opcodes = []
            if state.args.opcodes:
                print("[-] Extracting OpCodes: %s" % filePath)
                opcodes = extract_opcodes(fileData)

            # Add sha256 value
            if generateInfo:
                sha256sum = sha256(fileData).hexdigest()
                file_info[filePath] = {}
                file_info[filePath]["hash"] = sha256sum
                file_info[filePath]["imphash"], file_info[filePath]["exports"] = (
                    get_pe_info(fileData)
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

            # Add stats for basename (needed for inverse rule generation)
            fileName = os.path.basename(filePath)
            folderName = os.path.basename(os.path.dirname(filePath))
            if fileName not in file_info:
                file_info[fileName] = {}
                file_info[fileName]["count"] = 0
                file_info[fileName]["hashes"] = []
                file_info[fileName]["folder_names"] = []
            file_info[fileName]["count"] += 1
            file_info[fileName]["hashes"].append(sha256sum)
            if folderName not in file_info[fileName]["folder_names"]:
                file_info[fileName]["folder_names"].append(folderName)

            # Add strings to statistics
            for string in strings:
                # String is not already known
                if string not in string_stats:
                    string_stats[string] = {}
                    string_stats[string]["count"] = 0
                    string_stats[string]["files"] = []
                    string_stats[string]["files_basename"] = {}
                # String count
                string_stats[string]["count"] += 1
                # Add file information
                if fileName not in string_stats[string]["files_basename"]:
                    string_stats[string]["files_basename"][fileName] = 0
                string_stats[string]["files_basename"][fileName] += 1
                if filePath not in string_stats[string]["files"]:
                    string_stats[string]["files"].append(filePath)

            # Add opcodes to statistics
            for opcode in opcodes:
                # Opcode is not already known
                if opcode not in opcode_stats:
                    opcode_stats[opcode] = {}
                    opcode_stats[opcode]["count"] = 0
                    opcode_stats[opcode]["files"] = []
                    opcode_stats[opcode]["files_basename"] = {}
                # Opcode count
                opcode_stats[opcode]["count"] += 1
                # Add file information
                if fileName not in opcode_stats[opcode]["files_basename"]:
                    opcode_stats[opcode]["files_basename"][fileName] = 0
                opcode_stats[opcode]["files_basename"][fileName] += 1
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

    return string_stats, opcode_stats, file_info


def parse_good_dir(state, dir, notRecursive=False, onlyRelevantExtensions=True):
    # Prepare dictionary
    all_strings = Counter()
    all_opcodes = Counter()
    all_imphashes = Counter()
    all_exports = Counter()

    for filePath in get_files(dir, notRecursive):
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
        strings = extract_strings(state.args.s, fileData)
        # Append to all strings
        all_strings.update(strings)

        # Extract Opcodes from file
        opcodes = []
        if state.args.opcodes:
            print("[-] Extracting OpCodes: %s" % filePath)
            opcodes = extract_opcodes(fileData)
            # Append to all opcodes
            all_opcodes.update(opcodes)

        # Imphash and Exports
        (imphash, exports) = get_pe_info(fileData)
        if imphash != "":
            all_imphashes.update([imphash])
        all_exports.update(exports)
        if state.args.debug:
            print(
                "[+] Processed %s - %d strings %d opcodes %d exports and imphash %s"
                % (filePath, len(strings), len(opcodes), len(exports), imphash)
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
    (sample_string_stats, sample_opcode_stats, file_info) = parse_sample_dir(
        targetDir,
        state,
        state.args.nr,
        generateInfo=True,
        onlyRelevantExtensions=state.args.oe,
    )

    # Evaluate Strings
    (file_strings, file_opcodes, combinations, super_rules, inverse_stats) = (
        sample_string_evaluation(
            sample_string_stats, sample_opcode_stats, file_info, state
        )
    )

    # Create Rule Files
    (rule_count, inverse_rule_count, super_rule_count) = generate_rules(
        state,
        file_strings,
        file_opcodes,
        super_rules,
        file_info,
        inverse_stats,
    )

    if state.args.inverse:
        print("[=] Generated %s INVERSE rules." % str(inverse_rule_count))
    else:
        print("[=] Generated %s SIMPLE rules." % str(rule_count))
        if not state.args.nosuper:
            print("[=] Generated %s SUPER rules." % str(super_rule_count))
        print("[=] All rules written to %s" % state.args.o)
