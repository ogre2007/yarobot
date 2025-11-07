from pathlib import Path
from types import SimpleNamespace
from yarobot.generate import process_folder
from yarobot import yarobot_rs
import yara
import pstats

import cProfile


def test_string_extraction():
    strings, utf16strs = yarobot_rs.extract_strings(b"string1\0string2\nmultilinestring\n1\0string1", 5, 128)
    print(strings)
    assert strings["string1"].count == 2
    assert strings["string2"].count == 1
    assert strings["multilinestring"].count == 1


def test_string_extraction_file(shared_datadir):
    current_dir = Path(__file__).parent
    data = shared_datadir.joinpath("binary").read_bytes()[: 1024 * 1024]
    # print(pstr)
    # assert len(data) > 100
    assert data[0:2] == b"MZ"
    strings, utf16strs = yarobot_rs.extract_strings(data, 5, 128)

    for string in strings.keys():
        # print(string)
        assert len(string) >= 5
        assert len(string) <= 128


def test_string_extraction_min_max():
    data = b"short\0eight888\0A"
    # Min len 8, max 10 should include 'eight888' but not 'short'
    strings, _ = yarobot_rs.extract_strings(data, min_len=8, max_len=10)
    assert "eight888" in strings
    assert "short" not in strings


def test_get_pe_info_fast_rejects():
    # Not a PE
    fi = yarobot_rs.get_file_info(b"\x7fELF......")
    assert fi.imphash == ""
    assert fi.exports == []

    # MZ but no PE signature
    fake_mz = bytearray(b"MZ" + b"\x00" * 0x3A + b"\x00\x00\x00\x00" + b"\x00" * 64)
    fi = yarobot_rs.get_file_info(bytes(fake_mz))
    assert fi.imphash == ""
    assert fi.exports == []


def test_create_rust_struc():
    x = yarobot_rs.TokenInfo("wasd", 16, yarobot_rs.TokenType.BINARY, {"file", "file2"}, "")
    print(str(x))


def test_integration(shared_datadir):
    # pr = cProfile.Profile()
    # pr.enable()

    args = SimpleNamespace(
        max_file_size=10,
        debug=False,
        max_size=128,
        min_size=4,
        opcodes=False,
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
    )
    data = shared_datadir.joinpath("binary").read_bytes()[: 1024 * 1024 * args.max_file_size]

    rules = process_folder(args, str(shared_datadir))
    # pr.disable()

    # stats = pstats.Stats(pr)
    # stats.sort_stats("cumulative").print_stats(10)  # Sort by cumulative time and print top 10
    r = yara.compile(source=rules)
    m = r.match(data=data)
    print(rules)
    assert len(m) > 0
    print(m)
