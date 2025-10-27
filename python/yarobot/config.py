"""
yarGen - Yara Rule Generator, Copyright (c) 2015, Florian Roth
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
    * Neither the name of the copyright owner nor the
      names of its contributors may be used to endorse or promote products
      derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL Florian Roth BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""

import os

# Resolve DB path relative to project root (two levels up from this file)
_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir, os.pardir))
DB_PATH = os.path.normpath(os.path.join(_ROOT, "dbs"))


PE_STRINGS_FILE = os.path.normpath(os.path.join(_ROOT, "3rdparty", "strings.xml"))

"../3rdparty/strings.xml"

KNOWN_IMPHASHES = {
    "a04dd9f5ee88d7774203e0a0cfa1b941": "PsExec",
    "2b8c9d9ab6fefc247adaf927e83dcea6": "RAR SFX variant",
}

REPO_URLS = {
    "good-opcodes-part1.db": "https://www.bsk-consulting.de/yargen/good-opcodes-part1.db",
    "good-opcodes-part2.db": "https://www.bsk-consulting.de/yargen/good-opcodes-part2.db",
    "good-opcodes-part3.db": "https://www.bsk-consulting.de/yargen/good-opcodes-part3.db",
    "good-opcodes-part4.db": "https://www.bsk-consulting.de/yargen/good-opcodes-part4.db",
    "good-opcodes-part5.db": "https://www.bsk-consulting.de/yargen/good-opcodes-part5.db",
    "good-opcodes-part6.db": "https://www.bsk-consulting.de/yargen/good-opcodes-part6.db",
    "good-opcodes-part7.db": "https://www.bsk-consulting.de/yargen/good-opcodes-part7.db",
    "good-opcodes-part8.db": "https://www.bsk-consulting.de/yargen/good-opcodes-part8.db",
    "good-opcodes-part9.db": "https://www.bsk-consulting.de/yargen/good-opcodes-part9.db",
    "good-strings-part1.db": "https://www.bsk-consulting.de/yargen/good-strings-part1.db",
    "good-strings-part2.db": "https://www.bsk-consulting.de/yargen/good-strings-part2.db",
    "good-strings-part3.db": "https://www.bsk-consulting.de/yargen/good-strings-part3.db",
    "good-strings-part4.db": "https://www.bsk-consulting.de/yargen/good-strings-part4.db",
    "good-strings-part5.db": "https://www.bsk-consulting.de/yargen/good-strings-part5.db",
    "good-strings-part6.db": "https://www.bsk-consulting.de/yargen/good-strings-part6.db",
    "good-strings-part7.db": "https://www.bsk-consulting.de/yargen/good-strings-part7.db",
    "good-strings-part8.db": "https://www.bsk-consulting.de/yargen/good-strings-part8.db",
    "good-strings-part9.db": "https://www.bsk-consulting.de/yargen/good-strings-part9.db",
    "good-exports-part1.db": "https://www.bsk-consulting.de/yargen/good-exports-part1.db",
    "good-exports-part2.db": "https://www.bsk-consulting.de/yargen/good-exports-part2.db",
    "good-exports-part3.db": "https://www.bsk-consulting.de/yargen/good-exports-part3.db",
    "good-exports-part4.db": "https://www.bsk-consulting.de/yargen/good-exports-part4.db",
    "good-exports-part5.db": "https://www.bsk-consulting.de/yargen/good-exports-part5.db",
    "good-exports-part6.db": "https://www.bsk-consulting.de/yargen/good-exports-part6.db",
    "good-exports-part7.db": "https://www.bsk-consulting.de/yargen/good-exports-part7.db",
    "good-exports-part8.db": "https://www.bsk-consulting.de/yargen/good-exports-part8.db",
    "good-exports-part9.db": "https://www.bsk-consulting.de/yargen/good-exports-part9.db",
    "good-imphashes-part1.db": "https://www.bsk-consulting.de/yargen/good-imphashes-part1.db",
    "good-imphashes-part2.db": "https://www.bsk-consulting.de/yargen/good-imphashes-part2.db",
    "good-imphashes-part3.db": "https://www.bsk-consulting.de/yargen/good-imphashes-part3.db",
    "good-imphashes-part4.db": "https://www.bsk-consulting.de/yargen/good-imphashes-part4.db",
    "good-imphashes-part5.db": "https://www.bsk-consulting.de/yargen/good-imphashes-part5.db",
    "good-imphashes-part6.db": "https://www.bsk-consulting.de/yargen/good-imphashes-part6.db",
    "good-imphashes-part7.db": "https://www.bsk-consulting.de/yargen/good-imphashes-part7.db",
    "good-imphashes-part8.db": "https://www.bsk-consulting.de/yargen/good-imphashes-part8.db",
    "good-imphashes-part9.db": "https://www.bsk-consulting.de/yargen/good-imphashes-part9.db",
}

RELEVANT_EXTENSIONS = [
    "asp",
    "vbs",
    "ps",
    "ps1",
    "tmp",
    "bas",
    "bat",
    "cmd",
    "com",
    "cpl",
    "crt",
    "dll",
    "exe",
    "msc",
    "scr",
    "sys",
    "vb",
    "vbe",
    "vbs",
    "wsc",
    "wsf",
    "wsh",
    "input",
    "war",
    "jsp",
    "php",
    "asp",
    "aspx",
    "psd1",
    "psm1",
    "py",
]
