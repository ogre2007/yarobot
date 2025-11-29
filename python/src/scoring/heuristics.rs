use crate::{
    regex_base::{RegexRules, REGEX_INSENSITIVE, REGEX_SENSITIVE},
    TokenInfo,
};

fn filter_rg(tok: &mut TokenInfo, regex_base: &RegexRules, _ignore_case: bool) -> (i64, String) {
    let mut score_local = 0;
    let mut cats = String::new();

    for (category, regexes) in regex_base {
        let mut found = false;

        for (re, score) in regexes {
            if re.is_match(&tok.reprz) {
                score_local += score;
                found = true;
            }
        }

        if found {
            cats.push_str(category);
            cats.push_str(", ");
        }
    }

    tok.score += score_local;
    tok.add_note(cats.clone());
    (score_local, cats)
}

pub fn score_with_regex(tok: &mut TokenInfo) -> (i64, String) {
    let mut total_score = 0;
    let mut all_cats = String::new();

    let (score1, cats1) = filter_rg(tok, &REGEX_INSENSITIVE, true);
    total_score += score1;
    all_cats.push_str(&cats1);

    let (score2, cats2) = filter_rg(tok, &REGEX_SENSITIVE, false);
    total_score += score2;
    all_cats.push_str(&cats2);

    (total_score, all_cats)
}
