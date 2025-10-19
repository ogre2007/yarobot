from collections import Counter
import datetime
import traceback
from typing import Any, List

from app.config import KNOWN_IMPHASHES

# from app.scoring import filter_opcode_set, filter_string_set
import yarobot_rs
import os
import re
import logging


from yarobot_rs import ScoringEngine, TokenInfo

def get_uint_string(magic):
    print(magic)
    return f"uint16(0) == 0x{hex(magic[1])[2:]}{hex(magic[0])[2:]}"


def sanitize_rule_name(path: str, file: str) -> str:
    """Generate a valid YARA rule name from path and filename.

    - Prefix with folder name if too short
    - Ensure it doesn't start with a number
    - Replace invalid chars with underscore
    - De-duplicate underscores
    """
    file_base = os.path.splitext(file)[0]
    cleaned = file_base
    if len(file_base) < 8:
        cleaned = path.split("\\")[-1:][0] + "_" + cleaned
    if re.search(r"^[0-9]", cleaned):
        cleaned = "sig_" + cleaned
    cleaned = re.sub(r"[^\w]", "_", cleaned)
    cleaned = re.sub(r"_+", "_", cleaned)
    return cleaned


def get_timestamp_basic(date_obj=None):
    return date_obj.strftime("%Y-%m-%d") if date_obj else datetime.datetime.now().strftime("%Y-%m-%d")


def get_file_range(size, fm_size):
    size_string = ""
    try:
        # max sample size - args.filesize_multiplier times the original size
        max_size_b = size * fm_size
        # Minimum size
        if max_size_b < 1024:
            max_size_b = 1024
        # in KB
        max_size = int(max_size_b / 1024)
        max_size_kb = max_size
        # Round
        if len(str(max_size)) == 2:
            max_size = int(round(max_size, -1))
        elif len(str(max_size)) == 3:
            max_size = int(round(max_size, -2))
        elif len(str(max_size)) == 4:
            max_size = int(round(max_size, -3))
        elif len(str(max_size)) >= 5:
            max_size = int(round(max_size, -3))
        size_string = "filesize < {0}KB".format(max_size)
        logging.getLogger("yarobot").debug(
            "File Size Eval: SampleSize (b): %s SizeWithMultiplier (b/Kb): %s / %s RoundedSize: %s",
            str(size),
            str(max_size_b),
            str(max_size_kb),
            str(max_size),
        )
    except Exception:
        traceback.print_exc()
    finally:
        return size_string


def get_strings(state, string_elements):
    """
    Get a dictionary of all string types
    :param string_elements:
    :return:
    """
    strings = {
        "ascii": [],
        "wide": [],
        "base64 encoded": [],
        "hex encoded": [],
        "reversed": [],
    }

    # Adding the strings --------------------------------------
    if state.args.debug:
        print(
            state.base64strings,
            state.hexEncStrings,
            state.reversedStrings,
            state.utf16strings,
        )
    for i, string in enumerate(string_elements):
        if string in state.utf16strings:
            strings["wide"].append(string)
        elif string in state.base64strings:
            strings["base64 encoded"].append(string)
        elif string in state.hexEncStrings:
            strings["hex encoded"].append(string)
        elif string in state.reversedStrings:
            strings["reversed"].append(string)
        else:
            strings["ascii"].append(string)

    return strings


def write_strings(filePath, strings, output_dir, scores, stringScores):
    """
    Writes string information to an output file
    :param filePath:
    :param strings:
    :param output_dir:
    :param scores:
    :return:
    """
    SECTIONS = ["ascii", "wide", "base64 encoded", "hex encoded", "reversed"]
    # File
    filename = os.path.basename(filePath)
    strings_filename = os.path.join(output_dir, "%s_strings.txt" % filename)
    print("[+] Writing strings to file %s" % strings_filename)
    # Strings
    output_string = []
    for key in SECTIONS:
        # Skip empty
        if len(strings[key]) < 1:
            continue
        # Section
        output_string.append("%s Strings" % key.upper())
        output_string.append("------------------------------------------------------------------------")
        for string in strings[key]:
            if scores:
                score = "unknown"
                if key == "wide":
                    score = stringScores["UTF16LE:%s" % string]
                else:
                    score = stringScores[string]
                output_string.append("%d;%s" % (score, string))
            else:
                output_string.append(string)
        # Empty line between sections
        output_string.append("\n")
    with open(strings_filename, "w") as fh:
        fh.write("\n".join(output_string))


def generate_general_condition(file_info, nofilesize, filesize_multiplier):
    """
    Generates a general condition for a set of files
    :param file_info:
    :return:
    """
    conditions_string = ""
    conditions = []
    pe_module_neccessary = False

    # Different Magic Headers and File Sizes
    magic_headers = []
    file_sizes = []
    imphashes = []

    for filePath in file_info:
        if not file_info[filePath].magic:
            continue
        magic = file_info[filePath].magic
        size = file_info[filePath].size
        imphash = file_info[filePath].imphash

        # Add them to the lists
        if magic not in magic_headers and magic != "":
            magic_headers.append(magic)
        if size not in file_sizes:
            file_sizes.append(size)
        if imphash not in imphashes and imphash != "":
            imphashes.append(imphash)

    # If different magic headers are less than 5
    if len(magic_headers) <= 5:
        magic_string = " or ".join(get_uint_string(h) for h in magic_headers)
        if " or " in magic_string:
            conditions.append("( {0} )".format(magic_string))
        else:
            conditions.append("{0}".format(magic_string))

    # Biggest size multiplied with maxsize_multiplier
    if not nofilesize and len(file_sizes) > 0:
        conditions.append(get_file_range(max(file_sizes), filesize_multiplier))

    # If different magic headers are less than 5
    if len(imphashes) == 1:
        conditions.append('pe.imphash() == "{0}"'.format(imphashes[0]))
        pe_module_neccessary = True

    # If enough attributes were special
    condition_string = " and ".join(conditions)

    return condition_string, pe_module_neccessary



def generate_meta(file, prefix, author, ref, hashes):
    # Meta data -----------------------------------------------
    rule = "   meta:\n"
    rule += '      description = "%s - file %s"\n' % (
        prefix,
        file,
    )
    rule += '      author = "%s"\n' % author
    rule += '      reference = "%s"\n' % ref
    rule += '      date = "%s"\n' % get_timestamp_basic()
    for i, hash in enumerate(hashes):
        rule += '      hash%d = "%s"\n' % (i, hash)

    return rule

def add_conditions(conditions, subconditions, rule_strings, rule_opcodes, high_scoring_strings, pe_conditions_add):
    # String combinations
    cond_op = ""  # opcodes condition
    cond_hs = ""  # high scoring strings condition
    cond_ls = ""  # low scoring strings condition

    low_scoring_strings = len(rule_strings) - high_scoring_strings
    if high_scoring_strings > 0:
        cond_hs = "1 of ($x*)"
    if low_scoring_strings > 0:
        if low_scoring_strings > 10:
            if high_scoring_strings > 0:
                cond_ls = "4 of them"
            else:
                cond_ls = "8 of them"
        else:
            cond_ls = "all of them"

    # If low scoring and high scoring
    cond_combined = "all of them"
    needs_brackets = False
    if low_scoring_strings > 0 and high_scoring_strings > 0:
        # If PE conditions have been added, don't be so strict with the strings
        if pe_conditions_add:
            cond_combined = "{0} or {1}".format(cond_hs, cond_ls)
            needs_brackets = True
        else:
            cond_combined = "{0} and {1}".format(cond_hs, cond_ls)
    elif low_scoring_strings > 0 and not high_scoring_strings > 0:
        cond_combined = "{0}".format(cond_ls)
    elif not low_scoring_strings > 0 and high_scoring_strings > 0:
        cond_combined = "{0}".format(cond_hs)
    if rule_opcodes:
        cond_op = " and all of ($op*)"
        # Opcodes (if needed)
    if cond_op or needs_brackets:
        subconditions.append("( {0}{1} )".format(cond_combined, cond_op))
    else:
        subconditions.append(cond_combined)


def generate_simple_rule(printed_rules, scoring_engine: ScoringEngine, state, strings: List[TokenInfo], opcodes, info, fname) -> str:
    # Skip if there is nothing to do
    if not strings:
        logging.getLogger("yarobot").warning(
            "[W] Not enough high scoring strings to create a rule. (Try -z 0 to reduce the min score or --opcodes to include opcodes) FILE: %s",
            fname,
        )
        return False
    elif not opcodes:
        logging.getLogger("yarobot").warning(
            "[W] Not enough high scoring strings and opcodes to create a rule. (Try -z 0 to reduce the min score) FILE: %s",
            fname,
        )

    # Print rule title ----------------------------------------

    (path, file) = os.path.split(fname)
    # Prepare name via helper
    cleanedName = sanitize_rule_name(path, file)
    # Check if already printed
    if cleanedName in printed_rules:
        printed_rules[cleanedName] += 1
        cleanedName = cleanedName + "_" + str(printed_rules[cleanedName])
    else:
        printed_rules[cleanedName] = 1

    rule = "rule %s {\n" % cleanedName

    rule += generate_meta(file, state.args.prefix, state.args.author, state.args.ref, [info.sha256])

    rule += "   strings:\n"
    # Get the strings -----------------------------------------
    # Rule String generation
    (
        rule_strings,
        high_scoring_strings,
    ) = generate_rule_strings(
        scoring_engine,
        state,
        strings,
    )

    rule += "\n".join(rule_strings)
    rule_opcodes = generate_rule_opcodes(opcodes, state.args.opcode_num)

    rule += "\n".join(rule_opcodes)

    # Condition -----------------------------------------------
    # Conditions list (will later be joined with 'or')
    conditions = []  # AND connected
    subconditions = []  # OR connected

    # Condition PE
    # Imphash and Exports - applicable to PE files only
    condition_pe = []
    condition_pe_part1 = []
    condition_pe_part2 = []

    if not state.args.noextras and info.magic.startswith(b"MZ"):
        # Add imphash - if certain conditions are met
        if info.imphash not in state.good_imphashes_db and info.imphash != "":
            # Comment to imphash
            imphash = info.imphash
            comment = ""
            if imphash in KNOWN_IMPHASHES:
                comment = " /* {0} */".format(KNOWN_IMPHASHES[imphash])
            # Add imphash to condition
            condition_pe_part1.append('pe.imphash() == "{0}"{1}'.format(imphash, comment))
            pe_module_necessary = True
        if info.exports:
            e_count = 0
            for export in info.exports:
                if export not in state.good_exports_db:
                    condition_pe_part2.append('pe.exports("{0}")'.format(export))
                    e_count += 1
                    pe_module_necessary = True
                if e_count > 5:
                    break

    # 1st Part of Condition 1
    basic_conditions: List[Any] = []
    # Filesize
    if not state.args.nofilesize:
        basic_conditions.insert(0, get_file_range(info.size, state.args.filesize_multiplier))
    # Magic
    if info.magic != b"":
        uint_string = get_uint_string(info.magic)
        basic_conditions.insert(0, uint_string)
    # Basic Condition
    if len(basic_conditions):
        conditions.append(" and ".join(basic_conditions))

    # Add extra PE conditions to condition 1
    pe_conditions_add = False
    if condition_pe_part1 or condition_pe_part2:
        if len(condition_pe_part1) == 1:
            condition_pe.append(condition_pe_part1[0])
        elif len(condition_pe_part1) > 1:
            condition_pe.append("( %s )" % " or ".join(condition_pe_part1))
        if len(condition_pe_part2) == 1:
            condition_pe.append(condition_pe_part2[0])
        elif len(condition_pe_part2) > 1:
            condition_pe.append("( %s )" % " and ".join(condition_pe_part2))
        # Marker that PE conditions have been added
        pe_conditions_add = True
        # Add to sub condition
        subconditions.append(" and ".join(condition_pe))



    add_conditions(conditions, subconditions, rule_strings, rule_opcodes, high_scoring_strings, pe_conditions_add)



    # Now add string condition to the conditions
    if len(subconditions) == 1:
        conditions.append(subconditions[0])
    elif len(subconditions) > 1:
        conditions.append("( %s )" % " or ".join(subconditions))

    # Create condition string
    condition_string = " and\n      ".join(conditions)


    rule += "   condition:\n"
    rule += "      %s\n" % condition_string
    rule += "}\n\n"

    return rule


def generate_super_rule(super_rule, infos, state, scoring_engine, printed_rules, super_rule_names, printed_combi, super_rule_count, opcodes):
    rule = ""
    # Prepare Name
    rule_name = ""
    file_list = []
    hashes = []
    # Loop through files
    imphashes = Counter()
    for filePath in super_rule.files:
        (path, file) = os.path.split(filePath)
        file_list.append(file)
        # Prepare name via helper
        cleanedName = sanitize_rule_name(path, file)
        # Append it to the full name
        rule_name += "_" + cleanedName
        # Check if imphash of all files is equal
        imphash = infos[filePath].imphash
        hashes.append(infos[filePath].sha256)
        if imphash != "-" and imphash != "":
            imphashes.update([imphash])

    # Imphash usable
    if len(imphashes) == 1:
        unique_imphash = list(imphashes.items())[0][0]
        if unique_imphash in state.good_imphashes_db:
            unique_imphash = ""

    # Shorten rule name
    rule_name = rule_name[:124]
    # Add count if rule name already taken
    if rule_name not in super_rule_names:
        rule_name = "%s_%s" % (rule_name, super_rule_count)
    super_rule_names.append(rule_name)

    # File name starts with a number
    if re.search(r"^[0-9]", rule_name):
        rule_name = "sig_" + rule_name
    # clean name from all characters that would cause errors
    rule_name = re.sub(r"[^\w]", "_", rule_name)
    # Check if already printed
    if rule_name in printed_rules:
        printed_combi[rule_name] += 1
        rule_name = rule_name + "_" + str(printed_combi[rule_name])
    else:
        printed_combi[rule_name] = 1

    # Print rule title
    rule += "rule %s {\n" % rule_name
    rule += generate_meta(", ".join(file_list), state.args.prefix, state.args.author, state.args.ref, hashes)

    rule += "   strings:\n"

    tmp_file_opcodes = opcodes
    (
        rule_strings,
        high_scoring_strings,
    ) = generate_rule_strings(
        scoring_engine,
        state,
        super_rule.strings,
    )

    rule_opcodes = generate_rule_opcodes(tmp_file_opcodes, state.args.opcode_num)

    rule += "\n".join(rule_strings)
    rule += "\n".join(rule_opcodes)
    rule += "\n"
    # Condition -----------------------------------------------
    # Conditions list (will later be joined with 'or')
    conditions = []
    subbconditions = []
    # 1st condition
    # Evaluate the general characteristics
    file_info_super = {}
    for filePath in super_rule.files:
        file_info_super[filePath] = infos[filePath]
    condition_strings, pe_module_necessary_gen = generate_general_condition(infos, state.args.nofilesize, state.args.filesize_multiplier)
    if pe_module_necessary_gen:
        pe_module_necessary = True

    # 2nd condition
    # String combinations
    add_conditions(conditions, subbconditions, rule_strings, rule_opcodes, high_scoring_strings, pe_module_necessary)
 
    # Create condition string
    condition_string = "\n      ) or ( ".join(conditions)

    rule += "   condition:\n"
    rule += "      ( %s )\n" % condition_string
    rule += "}\n\n"

    # print rule
    # Add to rules string
    return rule


def generate_rules(
    scoring_engine,
    state,
    file_strings,
    file_opcodes,
    super_rules,
    file_info,
):
    try:
        fh = open(state.args.output_rule_file, "w")
    except Exception:
        traceback.print_exc()

    # General Info
    general_info = "/*\n"
    general_info += "   YARA Rule Set\n"
    general_info += "   Author: {0}\n".format(state.args.author)
    general_info += "   Date: {0}\n".format(get_timestamp_basic())
    general_info += "   Identifier: {0}\n".format(state.args.identifier)
    general_info += "   Reference: {0}\n".format(state.args.ref)
    if state.args.license != "":
        general_info += "   License: {0}\n".format(state.args.license)
    general_info += "*/\n\n"

    fh.write(general_info)

    # GLOBAL RULES ----------------------------------------------------
    if state.args.globalrule:
        condition, pe_module_necessary = generate_general_condition(file_info, state.args.nofilesize, state.args.filesize_multiplier)

        # Global Rule
        if condition != "":
            global_rule = "/* Global Rule -------------------------------------------------------------- */\n"
            global_rule += "/* Will be evaluated first, speeds up scanning process, remove at will */\n\n"
            global_rule += "global private rule gen_characteristics {\n"
            global_rule += "   condition:\n"
            global_rule += "      {0}\n".format(condition)
            global_rule += "}\n\n"

            fh.write(global_rule)

    # General vars
    rules = ""
    printed_rules = {}
    opcodes_to_add = []
    rule_count = 0
    super_rule_count = 0
    pe_module_necessary = False

    # PROCESS SIMPLE RULES ----------------------------------------------------
    logging.getLogger("yarobot").info("[+] Generating Simple Rules ...")
    # Apply intelligent filters
    logging.getLogger("yarobot").info("[-] Applying intelligent filters to string findings ...")
    # logging.getLogger("yarobot").info(file_strings)

    # GENERATE SIMPLE RULES -------------------------------------------
    fh.write("/* Rule Set ----------------------------------------------------------------- */\n\n")

    for filePath, strings in file_strings.items():
        if rule := generate_simple_rule(printed_rules, scoring_engine, state, strings, file_opcodes, file_info[filePath], filePath):
            rules += rule
            rule_count += 1

    # GENERATE SUPER RULES --------------------------------------------
    if not state.args.nosuper:
        rules += "/* Super Rules ------------------------------------------------------------- */\n\n"
        super_rule_names = []

        print("[+] Generating Super Rules ...")
        printed_combi = {}
        for super_rule in super_rules:
            rules += generate_super_rule(super_rule, file_info, state, scoring_engine, printed_rules, super_rule_names, printed_combi, super_rule_count, file_opcodes)
            super_rule_count += 1

    # WRITING RULES TO FILE
    # PE Module -------------------------------------------------------
    if not state.args.noextras:
        if pe_module_necessary:
            fh.write('import "pe"\n\n')
    # RULES ------------------------------
    fh.write(rules)

    fh.close()

    # Print rules to command line -------------------------------------
    if state.args.debug:
        print(rules)

    return (rule_count, super_rule_count)


from yarobot_rs import TokenType


def generate_string_repr(is_super_string, i, stringe):
    return f'\t${"x" if is_super_string else "s"}{i + 1} = "{stringe.reprz.replace('\\', '\\\\')}" {"wide" if stringe.typ == TokenType.UTF16LE else "ascii"}\
 {"fullword" if stringe.fullword else ""} /*{stringe.notes}*/'


def generate_opcode_repr(i, opcode):
    return f"\t$op{i} = {{{opcode}}}\n"


def generate_rule_opcodes(opcode_elements, opcodes_per_rule):
    # Adding the opcodes --------------------------------------
    rule_opcodes = []
    for i, opcode in enumerate(opcode_elements):
        rule_opcodes.append(generate_opcode_repr(i, opcode))
        if i >= opcodes_per_rule:
            break
    return rule_opcodes


def generate_rule_strings(scoring_engine, state, string_elements):
    rule_strings = []
    # Adding the strings --------------------------------------

    string_elements = list(set(string_elements))
    string_elements = sorted(string_elements, key=lambda x: x.score, reverse=True)
    high_scoring_strings = 0
    for i, stringe in enumerate(string_elements):
        # Collect the data
        string = stringe.reprz

        if string in scoring_engine.good_strings_db:
            stringe.add_note(f"goodware string - occured {scoring_engine.good_strings_db[string]} times")

        if state.args.score:
            stringe.add_note(f" / score: {scoring_engine.string_scores[string].score} /")
        else:
            logging.getLogger("yarobot").debug("NO SCORE: %s", string)

        if stringe.b64:
            stringe.add_note(f" / base64 encoded string '{scoring_engine.base64strings[string]}' /")
        if stringe.hexed:
            stringe.add_note(f" / hex encoded string '{yarobot_rs.remove_non_ascii_drop(scoring_engine.hex_enc_strings[string]).decode()}' /")
        if stringe.from_pestudio and state.args.score:
            stringe.add_note(f" / PEStudio Blacklist: {state.args.pestudio_marker[string]} /")
        if stringe.reversed:
            stringe.add_note(f" / reversed goodware string '{scoring_engine.reversed_strings[string]}' /")

        # Checking string length
        if len(string) >= state.args.max_size:
            # cut string
            stringe.reprz = string[: state.args.max_size].rstrip("\\")
            stringe.fullword = False
        # Now compose the rule line

        is_super_string = float(stringe.score) > state.args.high_scoring
        if is_super_string:
            high_scoring_strings += 1
        rule_strings.append(generate_string_repr(is_super_string, i, stringe))

        # If too many string definitions found - cut it at the
        # count defined via command line param -rc
        if (i + 1) >= state.args.strings_per_rule:  # state.args.strings_per_rule:
            break
 

    else:
        logging.getLogger("yarobot").info("[-] Not enough unique opcodes found to include them")

    return rule_strings, high_scoring_strings
