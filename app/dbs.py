import os
import shutil
import sys
import traceback
import urllib.request


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


def update_databases(args):
    # Preparations
    try:
        dbDir = "./dbs/"
        if not os.path.exists(dbDir):
            os.makedirs(dbDir)
    except Exception:
        if args.debug:
            traceback.print_exc()
        print("Error while creating the database directory ./dbs")
        sys.exit(1)

    # Downloading current repository
    try:
        for filename, repo_url in REPO_URLS.items():
            print("Downloading %s from %s ..." % (filename, repo_url))
            with (
                urllib.request.urlopen(repo_url) as response,
                open("./dbs/%s" % filename, "wb") as out_file,
            ):
                shutil.copyfileobj(response, out_file)
    except Exception:
        if args.debug:
            traceback.print_exc()
        print(
            "Error while downloading the database file - check your Internet connection "
            "(try to run it with --debug to see the full error message)"
        )
        sys.exit(1)
