import binascii
from collections import Counter
import os
import traceback
from dataclasses import dataclass, field

from hashlib import sha256 
from app.rule_generator import generate_rules
from app.scoring import sample_string_evaluation
from app.config import RELEVANT_EXTENSIONS

import yarobot_rs




def merge_stats(new_stats, old_stats): 
    for string, info in new_stats.items():
        assert info 
        if string not in old_stats:
            old_stats[string] = info
            for f in old_stats[string].files:
                if len(f) <5:
                    print(string, f)
                    exit()
        elif info.typ == old_stats[string].typ:
            old_stats[string].count += new_stats[string].count
            for f in new_stats[string].files:
                if f not in old_stats[string].files:
                    old_stats[string].files.add(f)

        else:
            print(info.typ, old_stats[string].typ)
            assert info.typ == old_stats[string].typ
            raise ValueError(f"String {string}:{info} has different encoding than \n\t{old_stats[string]}")

 
def process_file_with_checks(filePath, onlyRelevantExtensions, state, string_stats, utf16string_stats, opcode_stats, file_infos):

        #print("[+] Processing %s ..." % filePath)
        extension = os.path.splitext(filePath)[1].lower()
        if not extension in RELEVANT_EXTENSIONS and onlyRelevantExtensions:
            if state.args.debug:
                pass
                #print("[-] EXTENSION %s - Skipping file %s" % (extension, filePath))
            return False 
        
        # Info file check
        if os.path.basename(filePath) == os.path.basename(
            state.args.b
        ) or os.path.basename(filePath) == os.path.basename(state.args.r):
            return False

        # Size Check
        size = os.stat(filePath).st_size
        try:
            size = os.stat(filePath).st_size
            if size > (state.args.fs * 1024 * 1024):
                if state.args.debug:
                    pass
                    print("[-] File is to big - Skipping file %s (use -fs to adjust this behaviour)"% (filePath))
                return False
        except Exception as e:
            pass

        fi, strings, utf16strings, opcodes =yarobot_rs.process_single_file(filePath, getattr(state.args, "y", 8), getattr(state.args, "s", 128), state.args.opcodes)
        if fi is None:
            if state.args.debug:
                print(
                    "[-] File is empty - Skipping file %s" % (filePath)
                )
            return False
        if fi.sha256 in [v.sha256 for _,v in file_infos.items()]:
            # if state.args.debug:
            print(
                "[-] Skipping strings/opcodes from %s due to MD5 duplicate detection"
                % filePath
            )
            return False
        file_infos[filePath] = fi
        merge_stats(strings, string_stats)
        merge_stats(utf16strings, utf16string_stats)
        merge_stats(opcodes, opcode_stats) 
        if state.args.debug:
            print(
                "[+] Processed "
                + filePath
                + " Size: "
                + str(size)
                + " Strings: "
                + str(len(string_stats))
                + " Utf16Strings: "
                + str(len(utf16string_stats))
                + " OpCodes: "
                + str(len(opcode_stats))
                + " ... "
            )
            #print(string_stats)
        return True

def parse_sample_dir(
    dir, state, notRecursive=False, generateInfo=False, onlyRelevantExtensions=False
):
    # Prepare dictionary
    string_stats = {}
    utf16string_stats = {}
    opcode_stats = {}
    file_infos = {}
    known_sha1sums = []

    for filePath in yarobot_rs.get_files(dir, notRecursive):
        try:
            process_file_with_checks(
                filePath,
                onlyRelevantExtensions,
                state,
                string_stats,
                utf16string_stats,
                opcode_stats,
                file_infos
                )

        except Exception as e:
            traceback.print_exc()
            print("[E] ERROR reading file: %s" % filePath) 
    return string_stats, opcode_stats, file_infos, utf16string_stats


def parse_good_dir(state, dir, notRecursive=False, onlyRelevantExtensions=True):
    print(":: Parsing good samples ...")
    return parse_sample_dir(dir, state, notRecursive, False, onlyRelevantExtensions) 


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
    '''
    for k, v in sample_string_stats.items():
        #print(v.files)
        for f in v.files:
            print(f)
            if len(f) < 5:
                print(k, v)

    exit()
    '''
    # Evaluate Strings
    (file_strings, file_opcodes, combinations, super_rules) = (
        sample_string_evaluation(
            sample_string_stats,
            sample_opcode_stats,
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
