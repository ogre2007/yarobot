
from pathlib import Path
import tempfile
from types import SimpleNamespace
from pytest_datadir.plugin import LazyDataDir
from app.main import parse_good_dir
import yarobot_rs 

def test_string_extraction():  
    strings, utf16strs = yarobot_rs.extract_strings(b"string1\0string2\nmultilinestring\n1\0string1", 5, 128) 
    print(strings)
    assert strings["string1"].count == 2
    assert strings["string2"].count == 1
    assert strings["multilinestring"].count == 1

def test_string_extraction_file(shared_datadir):
    current_dir = Path(__file__).parent
    data = shared_datadir.joinpath("binary").read_bytes()[:1024*1024]
    #print(pstr) 
    #assert len(data) > 100
    assert data[0:2] == b"MZ"
    strings, utf16strs = yarobot_rs.extract_strings(data, 5, 128)

    for string in strings.keys():
        #print(string)
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
    fi = yarobot_rs.get_file_info(b"\x7FELF......")
    assert fi.imphash == ""
    assert fi.exports == []

    # MZ but no PE signature
    fake_mz = bytearray(b"MZ" + b"\x00" * 0x3A + b"\x00\x00\x00\x00" + b"\x00" * 64)
    fi = yarobot_rs.get_file_info(bytes(fake_mz))
    assert fi.imphash == ""
    assert fi.exports == []


def test_parse_good_dir_aggregates_counts(tmp_path):
    # Create temp files with overlapping strings
    f1 = tmp_path / "a.exe"
    f2 = tmp_path / "b.dll"
    f1.write_bytes(b"alpha\0beta\0alpha\0gamma")
    f2.write_bytes(b"alpha\0delta\0beta")

    # Minimal state.args needed by parse_good_dir
    args = SimpleNamespace(fs=1, debug=False, s=128, y=4, opcodes=False, b="", ref="", R=True, oe=False,)
    state = SimpleNamespace(args=args)

    all_strings, all_opcodes, all_imphashes, all_exports = parse_good_dir(
        state, str(tmp_path)
    )
    print(all_strings)
    # alpha appears 3 times across files
    assert all_strings["alpha"].count == 3
    # beta appears 2 times
    assert all_strings["beta"].count == 2
    # gamma and delta once each
    assert all_strings["gamma"].count == 1
    assert all_strings["delta"].count == 1


def test_create_rust_struc():
    x = yarobot_rs.TokenInfo("wasd", 16, yarobot_rs.TokenType.BINARY, {"file", "file2"}, "")
    print(str(x)) 