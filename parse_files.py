import binascii
from collections import Counter
import os
import lief
import re
import traceback
from hashlib import sha256

from utils import get_files, is_ascii_string


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


# TODO: Still buggy after port to Python3
def extract_hex_strings(s):
    strings = []
    hex_strings = re.findall(b"([a-fA-F0-9]{10,})", s)
    for string in list(hex_strings):
        hex_strings += string.split(b"0000")
        hex_strings += string.split(b"0d0a")
        hex_strings += re.findall(
            b"((?:0000|002[a-f0-9]|00[3-9a-f][0-9a-f]){6,})", string, re.IGNORECASE
        )
    hex_strings = list(set(hex_strings))
    # ASCII Encoded Strings
    for string in hex_strings:
        for x in string.split(b"00"):
            if len(x) > 10:
                strings.append(x)
    # WIDE Encoded Strings
    for string in hex_strings:
        try:
            if len(string) % 2 != 0 or len(string) < 8:
                continue
            # Skip
            if b"0000" in string:
                continue
            dec = string.replace(b"00", b"")
            if is_ascii_string(dec, padding_allowed=False):
                strings.append(string)
        except Exception as e:
            traceback.print_exc()
    return strings


def extract_strings(args, fileData) -> list[str]:
    # String list
    cleaned_strings = []
    # Read file data
    try:
        # Read strings
        strings_full = re.findall(b"[\x1f-\x7e]{6,}", fileData)
        strings_limited = re.findall(b"[\x1f-\x7e]{6,%d}" % args.s, fileData)
        strings_hex = extract_hex_strings(fileData)
        strings = list(set(strings_full) | set(strings_limited) | set(strings_hex))
        wide_strings = [ws for ws in re.findall(b"(?:[\x1f-\x7e][\x00]){6,}", fileData)]

        # Post-process
        # WIDE
        for ws in wide_strings:
            # Decode UTF16 and prepend a marker (facilitates handling)
            wide_string = ("UTF16LE:%s" % ws.decode("utf-16")).encode("utf-8")
            if wide_string not in strings:
                strings.append(wide_string)
        for string in strings:
            # Escape strings
            if len(string) > 0:
                string = string.replace(b"\\", b"\\\\")
                string = string.replace(b'"', b'\\"')
            try:
                if isinstance(string, str):
                    cleaned_strings.append(string)
                else:
                    cleaned_strings.append(string.decode("utf-8"))
            except AttributeError as e:
                print(string)
                traceback.print_exc()

    except Exception as e:
        if args.debug:
            print(string)
            traceback.print_exc()
        pass

    return cleaned_strings


def extract_opcodes(args, fileData) -> list[str]:
    # Opcode list
    opcodes = []

    try:
        # Read file data
        binary = lief.parse(fileData)
        ep = binary.entrypoint

        # Locate .text section
        text = None
        if isinstance(binary, lief.PE.Binary):
            for sec in binary.sections:
                if (
                    sec.virtual_address + binary.imagebase
                    <= ep
                    < sec.virtual_address + binary.imagebase + sec.virtual_size
                ):
                    if args.debug:
                        print(f"EP is located at {sec.name} section")
                    text = sec.content.tobytes()
                    break
        elif isinstance(binary, lief.ELF.Binary):
            for sec in binary.sections:
                if sec.virtual_address <= ep < sec.virtual_address + sec.size:
                    if args.debug:
                        print(f"EP is located at {sec.name} section")
                    text = sec.content.tobytes()
                    break

        if text is not None:
            # Split text into subs
            text_parts = re.split(b"[\x00]{3,}", text)
            # Now truncate and encode opcodes
            for text_part in text_parts:
                if text_part == "" or len(text_part) < 8:
                    continue
                opcodes.append(
                    binascii.hexlify(text_part[:16]).decode(encoding="ascii")
                )
    except Exception as e:
        if args.debug:
            traceback.print_exc()
        pass

    return opcodes


def get_pe_info(args, fileData: bytes) -> tuple[str, list[str]]:
    """
    Get different PE attributes and hashes by lief
    :param fileData:
    :return:
    """
    imphash = ""
    exports = []
    # Check for MZ header (speed improvement)
    if fileData[:2] != b"MZ":
        return imphash, exports
    try:
        if args.debug:
            print("Extracting PE information")
        binary: lief.PE.Binary = lief.parse(fileData)
        # Imphash
        imphash = lief.PE.get_imphash(binary, lief.PE.IMPHASH_MODE.PEFILE)
        # Exports (names)
        for exp in binary.get_export().entries:
            exp: lief.PE.ExportEntry
            exports.append(str(exp.name))
    except Exception as e:
        if args.debug:
            traceback.print_exc()
        pass

    return imphash, exports


def parse_sample_dir(
    args, dir, notRecursive=False, generateInfo=False, onlyRelevantExtensions=False
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
                if args.debug:
                    print("[-] EXTENSION %s - Skipping file %s" % (extension, filePath))
                continue

            # Info file check
            if os.path.basename(filePath) == os.path.basename(
                args.b
            ) or os.path.basename(filePath) == os.path.basename(args.r):
                continue

            # Size Check
            size = 0
            try:
                size = os.stat(filePath).st_size
                if size > (args.fs * 1024 * 1024):
                    if args.debug:
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
            strings = extract_strings(args, fileData)

            # Extract opcodes from file
            opcodes = []
            if args.opcodes:
                print("[-] Extracting OpCodes: %s" % filePath)
                opcodes = extract_opcodes(args, fileData)

            # Add sha256 value
            if generateInfo:
                sha256sum = sha256(fileData).hexdigest()
                file_info[filePath] = {}
                file_info[filePath]["hash"] = sha256sum
                file_info[filePath]["imphash"], file_info[filePath]["exports"] = (
                    get_pe_info(args, fileData)
                )

            # Skip if hash already known - avoid duplicate files
            if sha256sum in known_sha1sums:
                # if args.debug:
                print(
                    "[-] Skipping strings/opcodes from %s due to MD5 duplicate detection"
                    % filePath
                )
                continue
            else:
                known_sha1sums.append(sha256sum)

            # Magic evaluation
            if not args.nomagic:
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

            if args.debug:
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


def parse_good_dir(args, dir, notRecursive=False, onlyRelevantExtensions=True):
    # Prepare dictionary
    all_strings = Counter()
    all_opcodes = Counter()
    all_imphashes = Counter()
    all_exports = Counter()

    for filePath in get_files(dir, notRecursive):
        # Get Extension
        extension = os.path.splitext(filePath)[1].lower()
        if extension not in RELEVANT_EXTENSIONS and onlyRelevantExtensions:
            if args.debug:
                print("[-] EXTENSION %s - Skipping file %s" % (extension, filePath))
            continue

        # Size Check
        size = 0
        try:
            size = os.stat(filePath).st_size
            if size > (args.fs * 1024 * 1024):
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
        strings = extract_strings(args, fileData)
        # Append to all strings
        all_strings.update(strings)

        # Extract Opcodes from file
        opcodes = []
        if args.opcodes:
            print("[-] Extracting OpCodes: %s" % filePath)
            opcodes = extract_opcodes(args, fileData)
            # Append to all opcodes
            all_opcodes.update(opcodes)

        # Imphash and Exports
        (imphash, exports) = get_pe_info(args, fileData)
        if imphash != "":
            all_imphashes.update([imphash])
        all_exports.update(exports)
        if args.debug:
            print(
                "[+] Processed %s - %d strings %d opcodes %d exports and imphash %s"
                % (filePath, len(strings), len(opcodes), len(exports), imphash)
            )

    # return it as a set (unique strings)
    return all_strings, all_opcodes, all_imphashes, all_exports
