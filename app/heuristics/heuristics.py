import re
from app.heuristics.regex_base import REGEX_INSENSETIVE, REGEX_SENSETIVE


def get_pestudio_score(string, pestudio_strings):
    for type in pestudio_strings:
        for elem in pestudio_strings[type]:
            # Full match
            if elem.text.lower() == string.lower():
                # Exclude the "extension" black list for now
                if type != "ext":
                    return 5, type
    return 0, ""


def _filter_rg(tok, regex_base, ignorecase):
    score_local = 0
    cats = ""
    flags = 0 if not ignorecase else re.IGNORECASE
    for cat, regexes in regex_base.items():
        found = False
        for regex in regexes:
            if m := re.search(regex[0], tok.reprz, flags):
                score_local += regex[1]
                # print(cat, m)
                found = True
        if found:
            cats += cat + ", "

    tok.score += int(score_local)
    tok.add_note(cats)
    return score_local, cats


def score_with_regex(tok):
    score = 0
    cats = ""
    new_score, new_cats = _filter_rg(tok, REGEX_INSENSETIVE, True)
    score += new_score
    cats += new_cats
    new_score, new_cats = _filter_rg(tok, REGEX_SENSETIVE, False)
    score += new_score
    cats += new_cats

    return score, cats


HEURISTICS = [score_with_regex]
