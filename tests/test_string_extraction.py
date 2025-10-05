
from app.parse_files import extract_strings 

def test_string_extraction():  
    strings, utf16strs = extract_strings(b"string1\0string2\nmultilinestring\n1\0string1") 

    assert strings["string1"].count == 2
    assert strings["string2"].count == 1
    assert strings["multilinestring"].count == 1