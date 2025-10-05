from collections import Counter
import traceback

from app.scoring import filter_opcode_set, filter_string_set
from app.utils import *

KNOWN_IMPHASHES = {
    "a04dd9f5ee88d7774203e0a0cfa1b941": "PsExec",
    "2b8c9d9ab6fefc247adaf927e83dcea6": "RAR SFX variant",
}


AI_COMMENT = """
The provided rule is a YARA rule, encompassing a wide range of suspicious strings. Kindly review the list and pinpoint the twenty strings that are most distinctive or appear most suited for a YARA rule focused on malware detection. Arrange them in descending order based on their level of suspicion. Then, swap out the current list of strings in the YARA rule with your chosen set and supply the revised rule.
---
"""


def get_file_range(size, fm_size):
    size_string = ""
    try:
        # max sample size - args.fm times the original size
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
        print(
            "File Size Eval: SampleSize (b): {0} SizeWithMultiplier (b/Kb): {1} / {2} RoundedSize: {3}".format(
                str(size), str(max_size_b), str(max_size_kb), str(max_size)
            )
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

        if string[:8] == "UTF16LE:":
            string = string[8:]
            strings["wide"].append(string)
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
        output_string.append(
            "------------------------------------------------------------------------"
        )
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


def generate_general_condition(state, file_info):
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

    try:
        for filePath in file_info:
            # Short file name info used for inverse generation has no magic/size fields
            if "magic" not in file_info[filePath]:
                continue
            magic = file_info[filePath]["magic"]
            size = file_info[filePath]["size"]
            imphash = file_info[filePath]["imphash"]

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
        if not state.args.nofilesize and len(file_sizes) > 0:
            conditions.append(get_file_range(max(file_sizes), state.args.fm))

        # If different magic headers are less than 5
        if len(imphashes) == 1:
            conditions.append('pe.imphash() == "{0}"'.format(imphashes[0]))
            pe_module_neccessary = True

        # If enough attributes were special
        condition_string = " and ".join(conditions)

    except Exception as e:
        if state.args.debug:
            traceback.print_exc()
            exit(1)
        print(
            "[E] ERROR while generating general condition - check the global rule and remove it if it's faulty"
        )

    return condition_string, pe_module_neccessary


def generate_rules(
    state,
    file_strings,
    file_opcodes,
    super_rules,
    file_info,
    inverse_stats,
):
    # Write to file ---------------------------------------------------
    if state.args.o:
        try:
            fh = open(state.args.o, "w")
        except Exception as e:
            traceback.print_exc()

    # General Info
    general_info = "/*\n"
    general_info += "   YARA Rule Set\n"
    general_info += "   Author: {0}\n".format(state.args.a)
    general_info += "   Date: {0}\n".format(get_timestamp_basic())
    general_info += "   Identifier: {0}\n".format(state.args.identifier)
    general_info += "   Reference: {0}\n".format(state.args.reference)
    if state.args.l != "":
        general_info += "   License: {0}\n".format(state.args.l)
    general_info += "*/\n\n"

    fh.write(general_info)

    # GLOBAL RULES ----------------------------------------------------
    if state.args.globalrule:

        condition, pe_module_necessary = generate_general_condition(file_info)

        # Global Rule
        if condition != "":
            global_rule = "/* Global Rule -------------------------------------------------------------- */\n"
            global_rule += "/* Will be evaluated first, speeds up scanning process, remove at will */\n\n"
            global_rule += "global private rule gen_characteristics {\n"
            global_rule += "   condition:\n"
            global_rule += "      {0}\n".format(condition)
            global_rule += "}\n\n"

            # Write rule
            if state.args.o:
                fh.write(global_rule)

    # General vars
    rules = ""
    printed_rules = {}
    opcodes_to_add = []
    rule_count = 0
    inverse_rule_count = 0
    super_rule_count = 0
    pe_module_necessary = False

    if not state.args.inverse:
        # PROCESS SIMPLE RULES ----------------------------------------------------
        print("[+] Generating Simple Rules ...")
        # Apply intelligent filters
        print("[-] Applying intelligent filters to string findings ...")
        for filePath in file_strings:

            print("[-] Filtering string set for %s ..." % filePath)

            # Replace the original string set with the filtered one
            file_strings[filePath] = filter_string_set(file_strings[filePath], state)

            print("[-] Filtering opcode set for %s ..." % filePath)

            # Replace the original opcode set with the filtered one
            file_opcodes[filePath] = (
                filter_opcode_set(state, file_opcodes[filePath], state.good_opcodes_db)
                if filePath in file_opcodes
                else []
            )

        # GENERATE SIMPLE RULES -------------------------------------------
        fh.write(
            "/* Rule Set ----------------------------------------------------------------- */\n\n"
        )

        for filePath in file_strings:

            # Skip if there is nothing to do
            if len(file_strings[filePath]) == 0:
                print(
                    "[W] Not enough high scoring strings to create a rule. "
                    "(Try -z 0 to reduce the min score or --opcodes to include opcodes) FILE: %s"
                    % filePath
                )
                continue
            elif len(file_strings[filePath]) == 0 and len(file_opcodes[filePath]) == 0:
                print(
                    "[W] Not enough high scoring strings and opcodes to create a rule. "
                    "(Try -z 0 to reduce the min score) FILE: %s" % filePath
                )
                continue

            # Create Rule
            try:
                rule = ""
                (path, file) = os.path.split(filePath)
                # Prepare name
                fileBase = os.path.splitext(file)[0]
                # Create a clean new name
                cleanedName = fileBase
                # Adapt length of rule name
                if len(fileBase) < 8:  # if name is too short add part from path
                    cleanedName = path.split("\\")[-1:][0] + "_" + cleanedName
                # File name starts with a number
                if re.search(r"^[0-9]", cleanedName):
                    cleanedName = "sig_" + cleanedName
                # clean name from all characters that would cause errors
                cleanedName = re.sub(r"[^\w]", "_", cleanedName)
                # Check if already printed
                if cleanedName in printed_rules:
                    printed_rules[cleanedName] += 1
                    cleanedName = cleanedName + "_" + str(printed_rules[cleanedName])
                else:
                    printed_rules[cleanedName] = 1

                # Print rule title ----------------------------------------
                rule += "rule %s {\n" % cleanedName

                # Meta data -----------------------------------------------
                rule += "   meta:\n"
                rule += '      description = "%s - file %s"\n' % (
                    state.args.prefix,
                    file,
                )
                rule += '      author = "%s"\n' % state.args.a
                rule += '      reference = "%s"\n' % state.args.reference
                rule += '      date = "%s"\n' % get_timestamp_basic()
                rule += '      hash1 = "%s"\n' % file_info[filePath]["hash"]
                rule += "   strings:\n"

                # Get the strings -----------------------------------------
                # Rule String generation
                (
                    rule_strings,
                    opcodes_included,
                    string_rule_count,
                    high_scoring_strings,
                ) = get_rule_strings(
                    state,
                    file_strings[filePath],
                    file_opcodes[filePath],
                )

                rule += rule_strings

                # Extract rul strings
                if state.args.strings:
                    strings = get_strings(
                        state,
                        file_strings[filePath],
                    )
                    write_strings(
                        filePath,
                        strings,
                        state.args.e,
                        state.args.score,
                        state.stringScores,
                    )

                # Condition -----------------------------------------------
                # Conditions list (will later be joined with 'or')
                conditions = []  # AND connected
                subconditions = []  # OR connected

                # Condition PE
                # Imphash and Exports - applicable to PE files only
                condition_pe = []
                condition_pe_part1 = []
                condition_pe_part2 = []
                if not state.args.noextras and file_info[filePath]["magic"] == "MZ":
                    # Add imphash - if certain conditions are met
                    if (
                        file_info[filePath]["imphash"] not in state.good_imphashes_db
                        and file_info[filePath]["imphash"] != ""
                    ):
                        # Comment to imphash
                        imphash = file_info[filePath]["imphash"]
                        comment = ""
                        if imphash in KNOWN_IMPHASHES:
                            comment = " /* {0} */".format(KNOWN_IMPHASHES[imphash])
                        # Add imphash to condition
                        condition_pe_part1.append(
                            'pe.imphash() == "{0}"{1}'.format(imphash, comment)
                        )
                        pe_module_necessary = True
                    if file_info[filePath]["exports"]:
                        e_count = 0
                        for export in file_info[filePath]["exports"]:
                            if export not in state.good_exports_db:
                                condition_pe_part2.append(
                                    'pe.exports("{0}")'.format(export)
                                )
                                e_count += 1
                                pe_module_necessary = True
                            if e_count > 5:
                                break

                # 1st Part of Condition 1
                basic_conditions = []
                # Filesize
                if not state.args.nofilesize:
                    basic_conditions.insert(
                        0, get_file_range(file_info[filePath]["size"], state.args.fm)
                    )
                # Magic
                if file_info[filePath]["magic"] != "":
                    uint_string = get_uint_string(file_info[filePath]["magic"])
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

                # String combinations
                cond_op = ""  # opcodes condition
                cond_hs = ""  # high scoring strings condition
                cond_ls = ""  # low scoring strings condition

                low_scoring_strings = string_rule_count - high_scoring_strings
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
                if opcodes_included:
                    cond_op = " and all of ($op*)"

                # Opcodes (if needed)
                if cond_op or needs_brackets:
                    subconditions.append("( {0}{1} )".format(cond_combined, cond_op))
                else:
                    subconditions.append(cond_combined)

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

                # Add to rules string
                rules += rule

                rule_count += 1
            except Exception as e:
                traceback.print_exc()

    # GENERATE SUPER RULES --------------------------------------------
    if not state.args.nosuper and not state.args.inverse:

        rules += "/* Super Rules ------------------------------------------------------------- */\n\n"
        super_rule_names = []

        print("[+] Generating Super Rules ...")
        printed_combi = {}
        for super_rule in super_rules:
            try:
                rule = ""
                # Prepare Name
                rule_name = ""
                file_list = []

                # Loop through files
                imphashes = Counter()
                for filePath in super_rule["files"]:
                    (path, file) = os.path.split(filePath)
                    file_list.append(file)
                    # Prepare name
                    fileBase = os.path.splitext(file)[0]
                    # Create a clean new name
                    cleanedName = fileBase
                    # Append it to the full name
                    rule_name += "_" + cleanedName
                    # Check if imphash of all files is equal
                    imphash = file_info[filePath]["imphash"]
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

                # Create a list of files
                file_listing = ", ".join(file_list)

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
                rule += "   meta:\n"
                rule += '      description = "%s - from files %s"\n' % (
                    state.args.prefix,
                    file_listing,
                )
                rule += '      author = "%s"\n' % state.args.a
                rule += '      reference = "%s"\n' % state.args.reference
                rule += '      date = "%s"\n' % get_timestamp_basic()
                for i, filePath in enumerate(super_rule["files"]):
                    rule += '      hash%s = "%s"\n' % (
                        str(i + 1),
                        file_info[filePath]["hash"],
                    )

                rule += "   strings:\n"

                # Adding the opcodes
                if file_opcodes.get(filePath) is None:
                    tmp_file_opcodes = {}
                else:
                    tmp_file_opcodes = file_opcodes.get(filePath)
                (
                    rule_strings,
                    opcodes_included,
                    string_rule_count,
                    high_scoring_strings,
                ) = get_rule_strings(
                    state,
                    super_rule["strings"],
                    tmp_file_opcodes,
                )
                rule += rule_strings

                # Condition -----------------------------------------------
                # Conditions list (will later be joined with 'or')
                conditions = []

                # 1st condition
                # Evaluate the general characteristics
                file_info_super = {}
                for filePath in super_rule["files"]:
                    file_info_super[filePath] = file_info[filePath]
                condition_strings, pe_module_necessary_gen = generate_general_condition(
                    state, file_info_super
                )
                if pe_module_necessary_gen:
                    pe_module_necessary = True

                # 2nd condition
                # String combinations
                cond_op = ""  # opcodes condition
                cond_hs = ""  # high scoring strings condition
                cond_ls = ""  # low scoring strings condition

                low_scoring_strings = string_rule_count - high_scoring_strings
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
                if low_scoring_strings > 0 and high_scoring_strings > 0:
                    cond_combined = "{0} and {1}".format(cond_hs, cond_ls)
                elif low_scoring_strings > 0 and not high_scoring_strings > 0:
                    cond_combined = "{0}".format(cond_ls)
                elif not low_scoring_strings > 0 and high_scoring_strings > 0:
                    cond_combined = "{0}".format(cond_hs)
                if opcodes_included:
                    cond_op = " and all of ($op*)"

                condition2 = "( {0} ){1}".format(cond_combined, cond_op)
                conditions.append(" and ".join([condition_strings, condition2]))

                # 3nd condition
                # In memory detection base condition (no magic, no filesize)
                condition_pe = "all of them"
                conditions.append(condition_pe)

                # Create condition string
                condition_string = "\n      ) or ( ".join(conditions)

                rule += "   condition:\n"
                rule += "      ( %s )\n" % condition_string
                rule += "}\n\n"

                # print rule
                # Add to rules string
                rules += rule

                super_rule_count += 1
            except Exception as e:
                traceback.print_exc()

    try:
        # WRITING RULES TO FILE
        # PE Module -------------------------------------------------------
        if not state.args.noextras:
            if pe_module_necessary:
                fh.write('import "pe"\n\n')
        # RULES -----------------------------------------------------------
        if state.args.o:
            fh.write(rules)
    except Exception as e:
        traceback.print_exc()

    # PROCESS INVERSE RULES ---------------------------------------------------
    # print inverse_stats.keys()
    if state.args.inverse:
        print("[+] Generating inverse rules ...")
        inverse_rules = ""
        # Apply intelligent filters -------------------------------------------
        print("[+] Applying intelligent filters to string findings ...")
        for fileName in inverse_stats:

            print("[-] Filtering string set for %s ..." % fileName)

            # Replace the original string set with the filtered one
            string_set = inverse_stats[fileName]
            inverse_stats[fileName] = []
            inverse_stats[fileName] = filter_string_set(string_set, state)

            # Preset if empty
            if fileName not in file_opcodes:
                file_opcodes[fileName] = {}

        # GENERATE INVERSE RULES -------------------------------------------
        fh.write(
            "/* Inverse Rules ------------------------------------------------------------- */\n\n"
        )

        for fileName in inverse_stats:
            try:
                rule = ""
                # Create a clean new name
                cleanedName = fileName.replace(".", "_")
                # Add ANOMALY
                cleanedName += "_ANOMALY"
                # File name starts with a number
                if re.search(r"^[0-9]", cleanedName):
                    cleanedName = "sig_" + cleanedName
                # clean name from all characters that would cause errors
                cleanedName = re.sub(r"[^\w]", "_", cleanedName)
                # Check if already printed
                if cleanedName in printed_rules:
                    printed_rules[cleanedName] += 1
                    cleanedName = cleanedName + "_" + str(printed_rules[cleanedName])
                else:
                    printed_rules[cleanedName] = 1

                # Print rule title ----------------------------------------
                rule += "rule %s {\n" % cleanedName

                # Meta data -----------------------------------------------
                rule += "   meta:\n"
                rule += '      description = "%s for anomaly detection - file %s"\n' % (
                    state.args.prefix,
                    fileName,
                )
                rule += '      author = "%s"\n' % state.args.a
                rule += '      reference = "%s"\n' % state.args.reference
                rule += '      date = "%s"\n' % get_timestamp_basic()
                for i, hash in enumerate(file_info[fileName]["hashes"]):
                    rule += '      hash%s = "%s"\n' % (str(i + 1), hash)

                rule += "   strings:\n"

                # Get the strings -----------------------------------------
                # Rule String generation
                (
                    rule_strings,
                    opcodes_included,
                    string_rule_count,
                    high_scoring_strings,
                ) = get_rule_strings(
                    state,
                    inverse_stats[fileName],
                    file_opcodes[fileName],
                )

                rule += rule_strings

                # Condition -----------------------------------------------
                folderNames = ""
                if not state.args.nodirname:
                    folderNames += "and ( filepath matches /"
                    folderNames += "$/ or filepath matches /".join(
                        file_info[fileName]["folder_names"]
                    )
                    folderNames += "$/ )"
                condition = 'filename == "%s" %s and not ( all of them )' % (
                    fileName,
                    folderNames,
                )

                rule += "   condition:\n"
                rule += "      %s\n" % condition
                rule += "}\n\n"

                # print rule
                # Add to rules string
                inverse_rules += rule

            except Exception as e:
                traceback.print_exc()

        try:
            # Try to write rule to file
            if state.args.o:
                fh.write(inverse_rules)
            inverse_rule_count += 1
        except Exception as e:
            traceback.print_exc()

    # Close the rules file --------------------------------------------
    if state.args.o:
        try:
            fh.close()
        except Exception as e:
            traceback.print_exc()

    # Print rules to command line -------------------------------------
    if state.args.debug:
        print(rules)

    return (rule_count, inverse_rule_count, super_rule_count)


def get_rule_strings(state, string_elements, opcode_elements):
    rule_strings = ""
    high_scoring_strings = 0
    string_rule_count = 0

    # Adding the strings --------------------------------------

    string_elements = list(set(string_elements))

    string_elements = sorted(
        string_elements, key=lambda x: state.stringScores[x], reverse=True
    )
    for i, string in enumerate(string_elements):

        # Collect the data
        is_fullword = True
        initial_string = string
        enc = " ascii"
        base64comment = ""
        hexEncComment = ""
        reversedComment = ""
        fullword = ""
        pestudio_comment = ""
        score_comment = ""
        goodware_comment = ""

        if string in state.good_strings_db:
            goodware_comment = " /* Goodware String - occured %s times */" % (
                state.good_strings_db[string]
            )
        if string[:8] == "UTF16LE:":
            string = string[8:]
            enc = " wide"
        if string in state.stringScores:
            if state.args.score:
                cat_comment = state.string_to_comms[string]
                score_comment += (
                    f" /* score: {state.stringScores[string]}  {cat_comment}*/"
                )
        else:
            print("NO SCORE: %s" % string)

        if string in state.utf16strings:
            enc = " wide"
        if string in state.base64strings:
            base64comment = (
                " /* base64 encoded string '%s' */"
                % state.base64strings[string].decode()
            )
        if string in state.hexEncStrings:
            hexEncComment = (
                " /* hex encoded string '%s' */"
                % removeNonAsciiDrop(state.hexEncStrings[string]).decode()
            )
        if string in state.pestudioMarker and state.args.score:
            pestudio_comment = (
                " /* PEStudio Blacklist: %s */" % state.pestudioMarker[string]
            )
        if string in state.reversedStrings:
            reversedComment = (
                " /* reversed goodware string '%s' */" % state.reversedStrings[string]
            )

        # Extra checks
        if is_hex_encoded(string, check_length=False):
            is_fullword = False

        # Checking string length
        if len(string) >= state.args.s:
            # cut string
            string = string[: state.args.s].rstrip("\\")
            # not fullword anymore
            is_fullword = False
        # Show as fullword
        if is_fullword:
            fullword = " fullword"

        # Now compose the rule line
        if float(state.stringScores[initial_string]) > state.args.score_highly_specific:
            high_scoring_strings += 1
            rule_strings += '      $x%s = "%s"%s%s%s%s%s%s%s%s\n' % (
                str(i + 1),
                string,
                fullword,
                enc,
                base64comment,
                reversedComment,
                pestudio_comment,
                score_comment,
                goodware_comment,
                hexEncComment,
            )
        else:
            rule_strings += '      $s%s = "%s"%s%s%s%s%s%s%s%s\n' % (
                str(i + 1),
                string,
                fullword,
                enc,
                base64comment,
                reversedComment,
                pestudio_comment,
                score_comment,
                goodware_comment,
                hexEncComment,
            )

        # If too many string definitions found - cut it at the
        # count defined via command line param -rc
        if (i + 1) >= 20:  # state.args.strings_per_rule:
            break

        string_rule_count += 1

    # Adding the opcodes --------------------------------------
    opcodes_included = False
    if len(opcode_elements) > 0:
        rule_strings += "\n"
        for i, opcode in enumerate(opcode_elements):
            rule_strings += "      $op%s = { %s }\n" % (str(i), opcode)
            opcodes_included = True
    else:
        if state.args.opcodes:
            print("[-] Not enough unique opcodes found to include them")

    return rule_strings, opcodes_included, string_rule_count, high_scoring_strings
