#!/usr/bin/env python
"""
HTTP Service for yarobot - YARA Rule Generator
File upload only version
"""

import cProfile
import os
import pstats
import tempfile
import uuid
from flask import Flask, request, jsonify
from yarobot.config import RELEVANT_EXTENSIONS
from werkzeug.utils import secure_filename
import logging
from typing import Dict

from yarobot.generate import process_folder, process_bytes
from yarobot.common import load_databases, initialize_pestudio_strings, getIdentifier, getPrefix, getReference
from yarobot import yarobot_rs

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("yarobot-service")

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024  # 100MB max file size

# Global variables for databases (loaded once at startup)
DATABASES = None
PESTUDIO_STRINGS = None
FP = None
SE = None


def initialize_databases():
    """Initialize databases on startup"""
    global DATABASES, PESTUDIO_STRINGS
    try:
        logger.info("Initializing databases...")
        PESTUDIO_STRINGS = initialize_pestudio_strings()
        DATABASES = load_databases()
        logger.info("Databases initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize databases: {e}")
        raise


def init_context(dbs, pestudio):
    # Scan malware files
    global FP, SE
    fp, se = yarobot_rs.init_analysis(
        True,
        RELEVANT_EXTENSIONS,
        5,
        128,
        10,
        True,
        False,
        False,
        5,
        5,
        *dbs,
        pestudio,
    )
    FP = fp
    SE = se
    return fp, se


class AnalysisRequest:
    """Wrapper for analysis parameters"""

    def __init__(self, params: Dict):
        for key in [
            "min_size",
            "min_score",
            "high_scoring",
            "max_size",
            "strings_per_rule",
            "filesize_multiplier",
            "max_file_size",
            "opcode_num",
            "superrule_overlap",
        ]:
            if key in params:
                try:
                    params[key] = int(params[key])
                except (ValueError, TypeError):
                    raise Exception()

        # Convert boolean parameters
        for key in [
            "excludegood",
            "score",
            "nomagic",
            "nofilesize",
            "only_executable",
            "noextras",
            "debug",
            "trace",
            "opcodes",
            "nosimple",
            "globalrule",
            "nosuper",
            "recursive",
            "get_opcodes",
        ]:
            if key in params:
                params[key] = params[key].lower() in ["true", "1", "yes", "on"]

        self.min_size = params.get("min_size", 8)
        self.min_score = params.get("min_score", 0)
        self.high_scoring = params.get("high_scoring", 30)
        self.max_size = params.get("max_size", 128)
        self.strings_per_rule = params.get("strings_per_rule", 15)
        self.excludegood = params.get("excludegood", False)
        self.author = params.get("author", "yarobot HTTP Service")
        self.ref = params.get("reference", "https://github.com/ogre2007/yarobot")
        self.license = params.get("license", "")
        self.prefix = params.get("prefix", "Auto-generated rule")
        self.identifier = params.get("identifier", "not set")
        self.score = params.get("show_scores", False)
        self.nomagic = params.get("no_magic", False)
        self.nofilesize = params.get("no_filesize", False)
        self.filesize_multiplier = params.get("filesize_multiplier", 2)
        self.only_executable = params.get("only_executable", False)
        self.max_file_size = params.get("max_file_size", 2)
        self.noextras = params.get("no_extras", False)
        self.debug = params.get("debug", False)
        self.trace = params.get("trace", False)
        self.opcodes = params.get("get_opcodes", False)
        self.opcode_num = params.get("opcode_num", 3)
        self.superrule_overlap = params.get("superrule_overlap", 5)
        self.nosimple = params.get("no_simple_rules", False)
        self.globalrule = params.get("global_rules", False)
        self.nosuper = params.get("no_super_rules", False)
        self.recursive = params.get("recursive", False)
        self.output_rule_file = params.get("output_file", "yarobot_rules.yar")
        self.output_dir_strings = params.get("output_dir_strings", "")


def save_uploaded_files(files) -> str:
    """Save uploaded files to temporary directory and return path"""
    temp_dir = tempfile.mkdtemp(prefix="yarobot_")

    for file in files:
        if file.filename:
            filename = secure_filename(file.filename)
            file_path = os.path.join(temp_dir, filename)
            file.save(file_path)
            logger.info(f"Saved uploaded file: {file_path}")
        else:
            print("no file name!")

    return temp_dir


@app.route("/health", methods=["GET"])
def health_check():
    """Health check endpoint"""
    return jsonify({"status": "healthy", "service": "yarobot-http", "databases_loaded": DATABASES is not None})


@app.route("/api/analyze", methods=["POST"])
def analyze():
    # pr = cProfile.Profile()
    # pr.enable()
    """
    Analyze uploaded files and generate YARA rules
    Accepts file uploads with analysis parameters
    """
    # Check if files were uploaded
    if "files" not in request.files:
        return jsonify({"error": "No files provided"}), 400

    files = request.files.getlist("files")
    if not files or all(file.filename == "" for file in files):
        return jsonify({"error": "No files selected"}), 400
    print(f"fsize:{len(files)}")
    # Get analysis parameters from form data
    params = request.form.to_dict()

    # Convert string parameters to appropriate types
    if DATABASES == None:
        initialize_databases()
        init_context(DATABASES, PESTUDIO_STRINGS)
    # Create analysis request
    try:
        args = AnalysisRequest(params)
    except Exception as e:
        return jsonify({"error": f"Invalid value forkey"}), 400

    # Set identifier based on upload
    if args.identifier == "not set":
        args.identifier = f"upload_{uuid.uuid4().hex[:8]}"

    args.ref = getReference(args.ref)
    args.prefix = getPrefix(args.prefix, args.identifier)

    logger.info(f"Starting analysis for {len(files)} files")

    # Process files and generate rules
    if len(files) == 1:
        rules_content = process_bytes(FP, SE, args, files[0].read(), *DATABASES, PESTUDIO_STRINGS)

    else:
        return jsonify({"error": "no many file analysis yet"}), 400
    # pr.disable()

    # stats = pstats.Stats(pr)
    # stats.sort_stats("cumulative").print_stats(10)  # Sort by cumulative time and print top 10
    # logger.error(f"Error during analysis: {e}")
    # Return rules content directly
    return jsonify(
        {
            "status": "success",
            "rules_generated": True,
            "rules_content": rules_content,
            "rules_count": rules_content.count("rule ") if rules_content else 0,
            "identifier": args.identifier,
            "files_analyzed": len(files),
        }
    )


@app.route("/api/status", methods=["GET"])
def get_status():
    """Get service status and database information"""
    db_info = {}
    if DATABASES:
        good_strings_db, good_opcodes_db, good_imphashes_db, good_exports_db = DATABASES
        db_info = {
            "good_strings_entries": len(good_strings_db),
            "good_opcodes_entries": len(good_opcodes_db),
            "good_imphashes_entries": len(good_imphashes_db),
            "good_exports_entries": len(good_exports_db),
            "pestudio_strings_loaded": PESTUDIO_STRINGS is not None,
        }

    return jsonify({"status": "running", "databases": db_info})


# Error handlers
@app.errorhandler(413)
def too_large(e):
    return jsonify({"error": "File too large"}), 413


@app.errorhandler(500)
def internal_error(e):
    return jsonify({"error": "Internal server error"}), 500


if __name__ == "__main__":
    # Initialize databases before starting the server
    initialize_databases()
    init_context(DATABASES, PESTUDIO_STRINGS)
    # Start Flask app
    app.run(
        host=os.getenv("YAROBOT_HOST", "0.0.0.0"),
        port=int(os.getenv("YAROBOT_PORT", 5000)),
        debug=os.getenv("YAROBOT_DEBUG", "false").lower() == "true",
    )
