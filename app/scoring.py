import base64
import binascii
import re
import logging
import traceback


import yarobot_rs

from app.heuristics.heuristics import get_pestudio_score, score_with_regex


def get_opcode_string(opcode):
    return " ".join(opcode.reprz[i : i + 2] for i in range(0, len(opcode.reprz), 2))


def filter_string_set(tokens, state):
    # This is the only set we have - even if it's a weak one
    useful_set = []

    # Local string scores
    localStringScores = []

    # Local UTF strings
    if getattr(state, "utf16strings", None) is None:
        state.utf16strings = []
    if len(tokens) == 0:
        raise Exception("No tokens found")
    for tok in tokens:
        if tok.reprz == "":
            print(tok)
            print("Empty string")
            raise Exception()
        # Goodware string marker
        goodstring = False
        goodcount = 0

        # Goodware Strings
        if tok.reprz in state.good_strings_db:
            goodstring = True
            goodcount = state.good_strings_db[tok.reprz]
            # print "%s - %s" % ( goodstring, good_strings[string] )
            if state.args.excludegood:
                continue
        # TODO:
        # UTF16
        original_string = tok.reprz
        if tok.reprz[:8] == "UTF16LE:":
            # print "removed UTF16LE from %s" % string
            tok.reprz = tok.reprz[8:]
            state.utf16strings.append(tok.reprz)

        # Good string evaluation (after the UTF modification)

        if goodstring:
            # Reduce the score by the number of occurence in goodware files
            tok.score += (goodcount * -1) + 5
        # print "Good string: %s" % string

        # PEStudio String Blacklist Evaluation
        if state.pestudio_available:
            (pescore, type) = get_pestudio_score(tok.reprz, state.pestudio_strings)
            # print("PE Match: %s" % string)
            # Reset score of goodware files to 5 if blacklisted in PEStudio
            if type != "":
                state.pestudioMarker[tok.reprz] = type
                # Modify the PEStudio blacklisted strings with their goodware stats count
                if goodstring:
                    pescore = pescore - (goodcount / 1000.0)
                    # print "%s - %s - %s" % (string, pescore, goodcount)
                tok.score = pescore

        if not goodstring:
            score, cats = score_with_regex(tok)
            if state.args.trace:
                print(f"{tok.reprz} - {score} - {cats}")
            # ENCODING DETECTIONS --------------------------------------------------
            try:
                if len(tok.reprz) > 8:
                    # Try different ways - fuzz string
                    # Base64
                    if state.args.trace:
                        print("Starting Base64 string analysis ...")
                    for m_string in (
                        tok.reprz,
                        tok.reprz[1:],
                        tok.reprz[:-1],
                        tok.reprz[1:] + "=",
                        tok.reprz + "=",
                        tok.reprz + "==",
                    ):
                        if yarobot_rs.is_base_64(m_string):
                            try:
                                decoded_string = base64.b64decode(
                                    m_string, validate=False
                                )
                            except binascii.Error:
                                continue
                            if yarobot_rs.is_ascii_string(
                                decoded_string, padding_allowed=True
                            ):
                                # print "match"
                                tok.score += 10
                                state.base64strings[tok.reprz] = decoded_string
                    # Hex Encoded string
                    if state.args.trace:
                        print("Starting Hex encoded string analysis ...")
                    for m_string in [tok.reprz, re.sub("[^a-zA-Z0-9]", "", tok.reprz)]:
                        # print m_string
                        if yarobot_rs.is_hex_encoded(m_string, True):
                            # print("^ is HEX")
                            decoded_string = bytes.fromhex(m_string)
                            if len(decoded_string) == 0:
                                raise Exception()
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
                                tok.score += 8
                                state.hexEncStrings[tok.reprz] = decoded_string

            except Exception:
                if state.args.debug:
                    traceback.print_exc()
                pass

            # Reversed String -----------------------------------------------------
            if tok.reprz[::-1] in state.good_strings_db:
                tok.score += 10
                state.reversedStrings[tok.reprz] = tok.reprz[::-1]

            # Certain string reduce	-----------------------------------------------
            if re.search(r"(rundll32\.exe$|kernel\.dll$)", tok.reprz, re.IGNORECASE):
                tok.score -= 4

        # Set the global string score
        state.stringScores[original_string] = tok

        if state.args.debug:
            if tok.reprz in state.utf16strings:
                is_utf = True
            else:
                is_utf = False
                # print "SCORE: %s\tUTF: %s\tSTRING: %s" % ( localStringScores[string], is_utf, string )
        localStringScores.append(tok)
    sorted_set = sorted(localStringScores, key=lambda x: x.score, reverse=True)

    # Only the top X strings
    c = 0
    result_set = []
    for tok in sorted_set:
        if state.args.trace:
            print("TOP STRINGS:", tok.reprz, tok.score)
        if tok.score < int(state.args.z):
            continue

        if tok.reprz in state.utf16strings:
            result_set.append("UTF16LE:%s" % tok.reprz)
        else:
            result_set.append(tok.reprz)

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
            logging.getLogger("yarobot").debug(
                f" [-] Adding {token} ({value}) to {len(files)} files."
            )
            for filePath in files:
                if filePath in outer_dict:
                    outer_dict[filePath].append(value)
                else:
                    outer_dict[filePath] = [value]


def find_combinations(stats):
    combinations = {}
    max_combi_count = 0
    for token, info in stats.items():
        if len(info.files) > 1:
            logging.getLogger("yarobot").debug(
                'OVERLAP Count: %s\nString: "%s"%s',
                info.count,
                token,
                "\nFILE: ".join(info.files),
            )
            # Create a combination string from the file set that matches to that string
            combi = ":".join(sorted(info.files))
            # print "STRING: " + string
            logging.getLogger("yarobot").debug("COMBI: %s", combi)
            # If combination not yet known
            if combi not in combinations:
                combinations[combi] = {}
                combinations[combi]["count"] = 1
                combinations[combi]["strings"] = []
                combinations[combi]["strings"].append(info)
                combinations[combi]["files"] = info.files
            else:
                combinations[combi]["count"] += 1
                combinations[combi]["strings"].append(info)
            # Set the maximum combination count
            max_combi_count = (
                combinations[combi]["count"]
                if combinations[combi]["count"] > max_combi_count
                else max_combi_count
            )
            # print "Max Combi Count set to: %s" % max_combi_count
    return combinations, max_combi_count


def make_super_rules(combinations, max_combi_count, state, file_strings=None):
    super_rules = []
    for combi_count in range(max_combi_count, 1, -1):
        for combi in combinations:
            if combi_count == combinations[combi]["count"]:
                string_set = combinations[combi]["strings"]
                combinations[combi]["strings"] = []
                combinations[combi]["strings"] = filter_string_set(string_set, state)
                if len(combinations[combi]["strings"]) >= int(state.args.w):
                    # Remove the files in the combi rule from the simple set
                    if file_strings:
                        for file in combinations[combi]["files"]:
                            if file in file_strings:
                                del file_strings[file]
                    # Add it as a super rule
                    logging.getLogger("yarobot").info(
                        "[-] Adding Super Rule with %s strings.",
                        str(len(combinations[combi]["strings"])),
                    )
                    super_rules.append(combinations[combi])
    return super_rules


def sample_string_evaluation(
    state,
    string_stats,
    opcode_stats,
    utf16string_stats,
    file_strings,
    file_utf16strings,
    file_opcodes,
):
    # Generate Stats -----------------------------------------------------------
    logging.getLogger("yarobot").info("[+] Generating statistical data ...")
    logging.getLogger("yarobot").info("\t[INPUT] Strings %s:", len(string_stats))

    combinations = {}
    max_combi_count = 0
    super_rules = []

    combinations, max_combi_count = find_combinations(string_stats)
    # TODO: opcode combos, utf16 combos

    logging.getLogger("yarobot").info("[+] Generating Super Rules ... (a lot of magic)")
    super_rules = make_super_rules(combinations, max_combi_count, state, file_strings)
    # TODO: opcode rules, utf16 rules
    logging.getLogger("yarobot").info("OUTPUT:%s super rules", len(super_rules))
    # Return all data
    return (combinations, super_rules)
