from pathlib import Path
from types import SimpleNamespace
from src.yarobot.generate import process_folder
import stringzz
import yara
import pstats

import cProfile


def test_get_pe_info_fast_rejects():
    # Not a PE
    fi = stringzz.get_file_info(b"\x7fELF......")
    assert fi.imphash == ""
    assert fi.exports == []

    # MZ but no PE signature
    fake_mz = bytearray(b"MZ" + b"\x00" * 0x3A + b"\x00\x00\x00\x00" + b"\x00" * 64)
    fi = stringzz.get_file_info(bytes(fake_mz))
    assert fi.imphash == ""
    assert fi.exports == []


def test_create_rust_struc():
    x = stringzz.TokenInfo("wasd", 16, stringzz.TokenType.BINARY, {"file", "file2"}, [""])
    print(str(x))


def test_integration(shared_datadir):
    # pr = cProfile.Profile()
    # pr.enable()

    args = SimpleNamespace(
        max_file_size=10,
        debug=False,
        max_size=128,
        min_size=4,
        get_opcodes=False,
        b="",
        recursive=True,
        oe=False,
        c=False,
        excludegood=False,
        min_score=1,
        superrule_overlap=5,
        prefix="test",
        author="test",
        ref="test",
        output_rule_file="test.yar",
        identifier="test",
        license="test",
        globalrule=True,
        nofilesize=False,
        filesize_multiplier=3,
        noextras=True,
        opcode_num=3,
        score=True,
        high_scoring=10,
        strings_per_rule=10,
        nosuper=False,
        max_file_count=10000
    )
    data = shared_datadir.joinpath("binary").read_bytes()[
        : 1024 * 1024 * args.max_file_size
    ]

    rules = process_folder(args, str(shared_datadir))
    # pr.disable()

    # stats = pstats.Stats(pr)
    # stats.sort_stats("cumulative").print_stats(10)  # Sort by cumulative time and print top 10
    r = yara.compile(source=rules)
    m = r.match(data=data)
    print(rules)
    assert len(m) > 0
    print(m)
