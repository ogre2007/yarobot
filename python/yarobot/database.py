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

from collections import Counter
import logging
import os
import shutil
import urllib.request

import click
from yarobot import yarobot_rs

from .common import get_abs_path, load, save
from .config import DB_PATH, RELEVANT_EXTENSIONS, REPO_URLS


def process_goodware_folder(goodware_path, extensions, recursive, minssize, maxssize, fsize, get_opcodes, debug):
    fp = yarobot_rs.FileProcessor(
        recursive,
        extensions,
        minssize,
        maxssize,
        fsize,
        get_opcodes,
        debug,
    )
    (string_scores, opcodes, utf16strings, file_infos) = fp.parse_sample_dir(goodware_path)
    # print(file_infos)
    good_json = Counter({k: v.count for k, v in string_scores.items()})
    good_opcodes_json = {k: v.count for k, v in opcodes.items()}
    good_json.update({k: v.count for k, v in utf16strings.items()})
    good_exports_json = [fi.exports for _, fi in file_infos.items() if fi.exports]
    good_imphashes_json = [fi.imphash for _, fi in file_infos.items() if fi.imphash]

    # print(sorted(good_json.items(), key=lambda x: x[1], reverse=True)[:10])

    # Save
    save(good_json, "good-strings.json")
    save(good_opcodes_json, "good-opcodes.json")
    save(good_exports_json, "good-exports.json")
    save(good_imphashes_json, "good-imphashes.json")

    click.echo(
        "New database with %d string, %d opcode, %d imphash, %d export entries created. "
        "(remember to use --opcodes to extract opcodes from the samples and create the opcode databases)"
        % (
            len(good_json),
            len(good_opcodes_json),
            len(good_imphashes_json),
            len(good_exports_json),
        )
    )


@click.group()
def cli():
    """database manager"""
    pass


@cli.command()
@click.argument("goodware_path", type=click.Path(exists=True), required=True)
@click.option("-i", "--identifier", help="Identifier for the database files", required=True)
@click.option(
    "--update",
    help="Update existing database with new goodware samples",
    is_flag=True,
    default=False,
)
@click.option("--debug", help="Debug output", is_flag=True, default=False)
def update(goodware_path, **kwargs):
    """Manage goodware databases"""
    args = type("Args", (), kwargs)()
    print("[+] Processing goodware files ...")
    good_strings_db, good_opcodes_db, good_imphashes_db, good_exports_db = process_goodware_folder(goodware_path)

    # Update existing databases
    if args.update:
        print("[+] Updating databases ...")

        # Evaluate the database identifiers
        db_identifier = ""
        if args.i != "":
            db_identifier = "-%s" % args.i
        strings_db = "./dbs/good-strings%s.db" % db_identifier
        opcodes_db = "./dbs/good-opcodes%s.db" % db_identifier
        imphashes_db = "./dbs/good-imphashes%s.db" % db_identifier
        exports_db = "./dbs/good-exports%s.db" % db_identifier

        # Strings -----------------------------------------------------
        print("[+] Updating %s ..." % strings_db)
        good_pickle = load(get_abs_path(strings_db))
        print("Old string database entries: %s" % len(good_pickle))
        good_pickle.update(good_strings_db)
        print("New string database entries: %s" % len(good_pickle))
        save(good_pickle, strings_db)

        # Opcodes -----------------------------------------------------
        print("[+] Updating %s ..." % opcodes_db)
        good_opcode_pickle = load(get_abs_path(opcodes_db))
        print("Old opcode database entries: %s" % len(good_opcode_pickle))
        good_opcode_pickle.update(good_opcodes_db)
        print("New opcode database entries: %s" % len(good_opcode_pickle))
        save(good_opcode_pickle, opcodes_db)

        # Imphashes ---------------------------------------------------
        print("[+] Updating %s ..." % imphashes_db)
        good_imphashes_pickle = load(get_abs_path(imphashes_db))
        print("Old opcode database entries: %s" % len(good_imphashes_pickle))
        good_imphashes_pickle.update(good_imphashes_db)
        print("New opcode database entries: %s" % len(good_imphashes_pickle))
        save(good_imphashes_pickle, imphashes_db)

        # Exports -----------------------------------------------------
        print("[+] Updating %s ..." % exports_db)
        good_exports_pickle = load(get_abs_path(exports_db))
        print("Old opcode database entries: %s" % len(good_exports_pickle))
        good_exports_pickle.update(good_exports_db)
        print("New opcode database entries: %s" % len(good_exports_pickle))
        save(good_exports_pickle, exports_db)

    if args.update:
        click.echo(f"[+] Updating goodware database with samples from {goodware_path}")
        # from app.dbs import update_goodware_db
        # update_goodware_db(args)


@cli.command()
@click.option(
    "-y",
    "--min-size",
    help="Minimum string length to consider (default=8)",
    type=int,
    default=8,
)
@click.option(
    "-s",
    "--max-size",
    help="Maximum length to consider (default=128)",
    type=int,
    default=128,
)
@click.option(
    "-R",
    "--recursive",
    help="Recursively scan directories",
    is_flag=True,
    default=False,
)
@click.option(
    "--oe",
    "--only-executable",
    help="Only scan executable extensions EXE, DLL, ASP, JSP, PHP, BIN, INFECTED",
    is_flag=True,
    default=False,
)
@click.option(
    "-fs",
    "--max-file-size",
    help="Max file size in MB to analyze (default=2)",
    type=int,
    default=5,
)
@click.option("--debug", help="Debug output", is_flag=True, default=False)
@click.option(
    "--opcodes",
    help="Do use the OpCode feature (use this if not enough high scoring strings can be found)",
    is_flag=True,
    default=False,
)
@click.argument("goodware_path", type=click.Path(exists=True), required=True)
def create(goodware_path, **kwargs):
    args = type("Args", (), kwargs)()
    click.echo("[+] Creating local database ...")
    process_goodware_folder(
        goodware_path,
        RELEVANT_EXTENSIONS if args.oe else None,
        args.recursive,
        args.min_size,
        args.max_size,
        args.max_file_size,
        args.opcodes,
        args.debug,
    )


@cli.command()
def update_remote():
    """Update the local strings and opcodes databases from the online repository"""
    if not os.path.exists(DB_PATH):
        os.makedirs(DB_PATH)

    for filename, repo_url in REPO_URLS.items():
        print("Downloading %s from %s ..." % (filename, repo_url))
        with (
            urllib.request.urlopen(repo_url) as response,
            open("./dbs/%s" % filename, "wb") as out_file,
        ):
            shutil.copyfileobj(response, out_file)

    click.echo("[+] Updated databases - you can now start creating YARA rules")


if __name__ == "__main__":
    logging.basicConfig(level=os.environ.get("YAROBOT_LOG_LEVEL", "INFO"))
    logging.getLogger().setLevel(logging.DEBUG)
    cli()
    # Identifier
