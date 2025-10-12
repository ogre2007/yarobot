import base64
import binascii
import operator
import re
import logging
import traceback


import yarobot_rs

from app.heuristics.heuristics import get_pestudio_score, score_with_regex


def get_opcode_string(opcode):
    return " ".join(opcode[i : i + 2] for i in range(0, len(opcode), 2))


def filter_string_set(string_set, state):
    # This is the only set we have - even if it's a weak one
    useful_set = []

    # Local string scores
    localStringScores = {}

    # Local UTF strings
    if getattr(state, "utf16strings", None) is None:
        state.utf16strings = []

    for string in string_set:

        # Goodware string marker
        goodstring = False
        goodcount = 0

        # Goodware Strings
        if string in state.good_strings_db:
            goodstring = True
            goodcount = state.good_strings_db[string]
            # print "%s - %s" % ( goodstring, good_strings[string] )
            if state.args.excludegood:
                continue

        # UTF
        original_string = string
        if string[:8] == "UTF16LE:":
            # print "removed UTF16LE from %s" % string
            string = string[8:]
            state.utf16strings.append(string)

        # Good string evaluation (after the UTF modification)
        if goodstring:
            # Reduce the score by the number of occurence in goodware files
            localStringScores[string] = (goodcount * -1) + 5
        else:
            localStringScores[string] = 0

        # PEStudio String Blacklist Evaluation
        if state.pestudio_available:
            (pescore, type) = get_pestudio_score(string, state.pestudio_strings)
            # print("PE Match: %s" % string)
            # Reset score of goodware files to 5 if blacklisted in PEStudio
            if type != "":
                state.pestudioMarker[string] = type
                # Modify the PEStudio blacklisted strings with their goodware stats count
                if goodstring:
                    pescore = pescore - (goodcount / 1000.0)
                    # print "%s - %s - %s" % (string, pescore, goodcount)
                localStringScores[string] = pescore

        if not goodstring:
            score, cats = score_with_regex(string)
            if state.args.trace:
                print(f"{string} - {score} - {cats}")
            localStringScores[string] += score
            state.string_to_comms[string] = cats
            # ENCODING DETECTIONS --------------------------------------------------
            try:
                if len(string) > 8:
                    # Try different ways - fuzz string
                    # Base64
                    if state.args.trace:
                        print("Starting Base64 string analysis ...")
                    for m_string in (
                        string,
                        string[1:],
                        string[:-1],
                        string[1:] + "=",
                        string + "=",
                        string + "==",
                    ):
                        if yarobot_rs.is_base_64(m_string):
                            try:
                                decoded_string = base64.b64decode(
                                    m_string, validate=False
                                )
                            except binascii.Error as e:
                                continue
                            if yarobot_rs.is_ascii_string(
                                decoded_string, padding_allowed=True
                            ):
                                # print "match"
                                localStringScores[string] += 10
                                state.base64strings[string] = decoded_string
                    # Hex Encoded string
                    if state.args.trace:
                        print("Starting Hex encoded string analysis ...")
                    for m_string in [string, re.sub("[^a-zA-Z0-9]", "", string)]:
                        # print m_string
                        if yarobot_rs.is_hex_encoded(m_string, True):
                            # print("^ is HEX")
                            decoded_string = bytes.fromhex(m_string)
                            if yarobot_rs.is_ascii_string(
                                decoded_string, padding_allowed=True
                            ):
                                # not too many 00s
                                if "00" in m_string:
                                    if (
                                        len(m_string) / float(m_string.count("0"))
                                        <= 1.2
                                    ):
                                        continue
                                # print("^ is ASCII / WIDE")
                                localStringScores[string] += 8
                                state.hexEncStrings[string] = decoded_string
            except Exception as e:
                if state.args.debug:
                    traceback.print_exc()
                pass

            # Reversed String -----------------------------------------------------
            if string[::-1] in state.good_strings_db:
                localStringScores[string] += 10
                state.reversedStrings[string] = string[::-1]

            # Certain string reduce	-----------------------------------------------
            if re.search(r"(rundll32\.exe$|kernel\.dll$)", string, re.IGNORECASE):
                localStringScores[string] -= 4

        # Set the global string score
        state.stringScores[original_string] = localStringScores[string]

        if state.args.debug:
            if string in state.utf16strings:
                is_utf = True
            else:
                is_utf = False
                # print "SCORE: %s\tUTF: %s\tSTRING: %s" % ( localStringScores[string], is_utf, string )

    sorted_set = sorted(
        localStringScores.items(), key=operator.itemgetter(1), reverse=True
    )

    # Only the top X strings
    c = 0
    result_set = []
    for string in sorted_set:

        if string[1] < int(state.args.z):
            continue

        if string[0] in state.utf16strings:
            result_set.append("UTF16LE:%s" % string[0])
        else:
            result_set.append(string[0])

        # c += 1
        # if c > int(state.args.rc):
        #    break

    if state.args.trace:
        print("RESULT SET:")
        print(result_set)

    # return the filtered set
    return result_set


def filter_opcode_set(state, opcode_set: list[str], good_opcodes_db) -> list[str]:
    # Preferred Opcodes
    pref_opcodes = [" 34 ", "ff ff ff "]

    # Useful set
    useful_set = []
    pref_set = []

    for opcode in opcode_set:
        # Exclude all opcodes found in goodware
        if opcode in good_opcodes_db:
            if state.args.trace:
                print("skipping %s" % opcode)
            continue

        # Format the opcode
        formatted_opcode = get_opcode_string(opcode)

        # Preferred opcodes
        set_in_pref = False
        for pref in pref_opcodes:
            if pref in formatted_opcode:
                pref_set.append(formatted_opcode)
                set_in_pref = True
        if set_in_pref:
            continue

        # Else add to useful set
        useful_set.append(get_opcode_string(opcode))

    # Preferred opcodes first
    useful_set = pref_set + useful_set

    # Only return the number of opcodes defined with the "-n" parameter
    return useful_set[: int(state.args.n)]


def extract_stats_by_file(stats, outer_dict, flt=lambda x: x):
    for token, value in stats.items():
        # if len(token) < 5:
        #    print(token, value)
        count = 0
        files = []
        if type(value) == dict:
            raise TypeError
        else:
            count = value.count
            files = value.files
        if flt(count):
            logging.getLogger("yarobot").info(
                f" [-] Adding {token} ({value}) to {len(files)} files."
            )
            for filePath in files:
                if filePath in outer_dict:
                    outer_dict[filePath].append(token)
                else:
                    outer_dict[filePath] = [token]


def sample_string_evaluation(string_stats, opcode_stats, state, utf16string_stats):

    # Generate Stats -----------------------------------------------------------
    logging.getLogger("yarobot").info("[+] Generating statistical data ...")
    logging.getLogger("yarobot").info(f"\t[INPUT] Strings %s:", len(string_stats))
    file_strings = {}
    file_utf16strings = {}
    file_opcodes = {}
    combinations = {}
    max_combi_count = 0
    super_rules = []

    # OPCODE EVALUATION -----------------------------------------------
    extract_stats_by_file(opcode_stats, file_opcodes, lambda x: x < 10)

    # STRING EVALUATION -------------------------------------------------------
    extract_stats_by_file(string_stats, file_strings)

    extract_stats_by_file(utf16string_stats, file_utf16strings)
    if not state.args.nosuper:
        for string in string_stats: 
            if len(string_stats[string].files) > 1:
                if state.args.debug:
                    logging.getLogger("yarobot").debug(
                        'OVERLAP Count: %s\nString: "%s"%s',
                        string_stats[string].count,
                        string,
                        "\nFILE: ".join(string_stats[string].files),
                    )
                # Create a combination string from the file set that matches to that string
                combi = ":".join(sorted(string_stats[string].files))
                # print "STRING: " + string
                if state.args.debug:
                    logging.getLogger("yarobot").debug("COMBI: %s", combi)
                # If combination not yet known
                if combi not in combinations:
                    combinations[combi] = {}
                    combinations[combi]["count"] = 1
                    combinations[combi]["strings"] = []
                    combinations[combi]["strings"].append(string)
                    combinations[combi]["files"] = string_stats[string].files
                else:
                    combinations[combi]["count"] += 1
                    combinations[combi]["strings"].append(string)
                # Set the maximum combination count
                max_combi_count = (
                    combinations[combi]["count"]
                    if combinations[combi]["count"] > max_combi_count
                    else max_combi_count
                )
                # print "Max Combi Count set to: %s" % max_combi_count

    logging.getLogger("yarobot").info("[+] Generating Super Rules ... (a lot of magic)")
    for combi_count in range(max_combi_count, 1, -1):
        for combi in combinations:
            if combi_count == combinations[combi]["count"]: 
                string_set = combinations[combi]["strings"]
                combinations[combi]["strings"] = []
                combinations[combi]["strings"] = filter_string_set(string_set, state) 
                if len(combinations[combi]["strings"]) >= int(state.args.w):
                    # Remove the files in the combi rule from the simple set
                    if state.args.nosimple:
                        for file in combinations[combi]["files"]:
                            if file in file_strings:
                                del file_strings[file]
                    # Add it as a super rule
                    logging.getLogger("yarobot").info(
                        "[-] Adding Super Rule with %s strings.",
                        str(len(combinations[combi]["strings"])),
                    ) 
                    super_rules.append(combinations[combi])
    logging.getLogger("yarobot").info("OUTPUT:%", len(file_strings))
    # Return all data
    return (file_strings, file_opcodes, combinations, super_rules)
