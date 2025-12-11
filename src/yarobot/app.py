#!/usr/bin/env python
"""
HTTP Service for yarobot - YARA Rule Generator
File upload only version
"""

from argparse import ArgumentParser
import os
import tempfile
import uuid
import click
from flask import Flask, render_template, request, jsonify
from werkzeug.utils import secure_filename
import logging
from typing import Dict, List, Optional, Any, Tuple
from .generate import process_buffers
from .common import (
    load_databases,
    initialize_pestudio_strings,
    getPrefix,
    getReference,
)
import stringzz
from dataclasses import dataclass, field, asdict


DB_PATH = os.environ.get("YAROBOT_DB_PATH", "./dbs")
MAX_FILES = 10

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("yarobot-service")

current_dir = os.path.dirname(os.path.abspath(__file__))
template_dir = os.path.join(current_dir, "templates")

app = Flask(
    __name__,
    template_folder=template_dir,
    static_folder=os.path.join(current_dir, "static"),
)

app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024  # 100MB max file size

# Global variables for databases (loaded once at startup)
DATABASES = None
PESTUDIO_STRINGS = None
FP = None
SE = None


@dataclass
class DatabaseContext:
    """Container for all database-related objects"""

    good_strings_db: Optional[Any] = None
    good_opcodes_db: Optional[Any] = None
    good_imphashes_db: Optional[Any] = None
    good_exports_db: Optional[Any] = None
    pestudio_strings: Optional[Any] = None
    fp: Optional[Any] = None
    se: Optional[Any] = None

    @property
    def databases_tuple(self) -> Tuple:
        """Return databases as a tuple for compatibility with existing code"""
        return (
            self.good_strings_db,
            self.good_opcodes_db,
            self.good_imphashes_db,
            self.good_exports_db,
        )

    def is_initialized(self) -> bool:
        """Check if all databases are loaded"""
        return all(
            [
                self.good_strings_db is not None,
                self.good_opcodes_db is not None,
                self.good_imphashes_db is not None,
                self.good_exports_db is not None,
                self.pestudio_strings is not None,
            ]
        )


@dataclass
class AnalysisParameters:
    """Analysis parameters with type conversions and validation"""

    # Integer parameters with defaults
    min_size: int = 8
    min_score: int = 5
    high_scoring: int = 30
    max_size: int = 128
    strings_per_rule: int = 15
    filesize_multiplier: int = 2
    max_file_size: int = 2
    opcode_num: int = 3
    superrule_overlap: int = 5

    # Boolean parameters with defaults
    excludegood: bool = False
    score: bool = True
    nomagic: bool = False
    nofilesize: bool = False
    only_executable: bool = False
    noextras: bool = False
    debug: bool = False
    trace: bool = False
    nosimple: bool = False
    globalrule: bool = False
    nosuper: bool = False
    recursive: bool = False
    get_opcodes: bool = False

    # String parameters with defaults
    author: str = "yarobot Web Service"
    ref: str = "https://github.com/ogre2007/yarobot"
    license: str = ""
    prefix: str = "Auto-generated rule"
    identifier: str = "not set"

    def to_config(self) -> stringzz.Config:
        """Convert to stringzz.Config object"""
        return stringzz.Config(
            min_string_len=self.min_size,
            max_string_len=self.max_size,
            max_file_size_mb=self.max_size,
            extract_opcodes=self.get_opcodes,
        )

    @classmethod
    def from_form_data(cls, form_data: Dict[str, str]) -> "AnalysisParameters":
        """Create AnalysisParameters from Flask form data"""
        processed = {}

        # Integer field conversions
        int_fields = [
            "min_size",
            "min_score",
            "high_scoring",
            "max_size",
            "strings_per_rule",
            "filesize_multiplier",
            "max_file_size",
            "opcode_num",
            "superrule_overlap",
        ]

        for field in int_fields:
            if field in form_data:
                try:
                    processed[field] = int(form_data[field])
                except (ValueError, TypeError):
                    raise ValueError(f"Invalid integer value for {field}")

        # Boolean field conversions
        bool_fields = [
            "excludegood",
            "score",
            "nomagic",
            "nofilesize",
            "only_executable",
            "noextras",
            "debug",
            "trace",
            "nosimple",
            "globalrule",
            "nosuper",
            "recursive",
            "get_opcodes",
        ]

        bool_mapping = {
            "show_scores": "score",
            "no_magic": "nomagic",
            "no_filesize": "nofilesize",
            "no_extras": "noextras",
            "no_simple_rules": "nosimple",
            "global_rules": "globalrule",
            "no_super_rules": "nosuper",
        }

        for form_field, dataclass_field in bool_mapping.items():
            if form_field in form_data:
                processed[dataclass_field] = form_data[form_field].lower() in [
                    "true",
                    "1",
                    "yes",
                    "on",
                ]

        for field in bool_fields:
            if field in form_data and field not in processed:
                processed[field] = form_data[field].lower() in [
                    "true",
                    "1",
                    "yes",
                    "on",
                ]

        # String field mappings
        string_mapping = {
            "reference": "ref",
            "author": "author",
            "license": "license",
            "prefix": "prefix",
            "identifier": "identifier",
        }

        for form_field, dataclass_field in string_mapping.items():
            if form_field in form_data:
                processed[dataclass_field] = form_data[form_field]

        return cls(**processed)

    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization"""
        return asdict(self)


# Add form configuration constants
FORM_FIELDS_CONFIG = {
    "basic": [
        {
            "name": "min_score",
            "type": "number",
            "label": "Minimum Score",
            "default": 5,
            "min": 0,
            "max": 100,
        },
        {
            "name": "author",
            "type": "text",
            "label": "Author",
            "default": "yarobot Web Interface",
        },
        {
            "name": "get_opcodes",
            "type": "checkbox",
            "label": "Use Opcodes",
            "form_field": "use-opcodes",
            "default": False,
        },
        {
            "name": "globalrule",
            "type": "checkbox",
            "label": "Generate Global Rules",
            "form_field": "global_rules",
            "default": False,
        },
        {
            "name": "excludegood",
            "type": "checkbox",
            "label": "Exclude good",
            "form_field": "excludegood",
            "default": False,
        },
    ],
    "advanced": [
        {
            "name": "min_size",
            "type": "number",
            "label": "Minimum String Size",
            "default": 8,
            "min": 1,
        },
        {
            "name": "max_size",
            "type": "number",
            "label": "Maximum String Size",
            "default": 128,
            "min": 1,
        },
        {
            "name": "strings_per_rule",
            "type": "number",
            "label": "Strings per Rule",
            "default": 15,
            "min": 1,
        },
        {
            "name": "high_scoring",
            "type": "number",
            "label": "High Scoring Threshold",
            "default": 30,
            "min": 0,
        },
        {
            "name": "nomagic",
            "type": "checkbox",
            "label": "No Magic",
            "form_field": "no_magic",
            "default": False,
        },
        {
            "name": "nofilesize",
            "type": "checkbox",
            "label": "No Filesize",
            "form_field": "no_filesize",
            "default": False,
        },
        {
            "name": "noextras",
            "type": "checkbox",
            "label": "No Extras",
            "form_field": "no_extras",
            "default": False,
        },
        {
            "name": "nosimple",
            "type": "checkbox",
            "label": "No Simple Rules",
            "form_field": "no_simple_rules",
            "default": False,
        },
        {
            "name": "nosuper",
            "type": "checkbox",
            "label": "No Super Rules",
            "form_field": "no_super_rules",
            "default": False,
        },
        {
            "name": "recursive",
            "type": "checkbox",
            "label": "Recursive Analysis",
            "default": False,
        },
        {
            "name": "prefix",
            "type": "text",
            "label": "Rule Prefix",
            "default": "Auto-generated rule",
        },
        {"name": "license", "type": "text", "label": "License", "default": ""},
        {
            "name": "opcode_num",
            "type": "number",
            "label": "Opcode Number",
            "default": 3,
            "min": 1,
        },
    ],
}


@dataclass
class AnalysisRequest:
    """Complete analysis request with parameters and files"""

    parameters: AnalysisParameters
    files: List[Any]
    identifier: str = field(default_factory=lambda: f"upload_{uuid.uuid4().hex[:8]}")

    def __post_init__(self):
        """Post-initialization processing"""
        # Set identifier if not already set
        if self.parameters.identifier == "not set":
            self.parameters.identifier = self.identifier
        else:
            self.identifier = self.parameters.identifier

        # Process ref and prefix
        self.parameters.ref = getReference(self.parameters.ref)
        self.parameters.prefix = getPrefix(self.parameters.prefix, self.identifier)

    @classmethod
    def from_flask_request(cls, flask_request) -> "AnalysisRequest":
        """Create AnalysisRequest from Flask request object"""
        # Get files
        if "files" not in flask_request.files:
            raise ValueError("No files provided")

        files = flask_request.files.getlist("files")
        if len(files) > MAX_FILES:
            raise ValueError(f"Too many files, max {MAX_FILES}")

        if not files or all(file.filename == "" for file in files):
            raise ValueError("No files selected")

        # Get parameters from form data
        params = AnalysisParameters.from_form_data(flask_request.form.to_dict())

        return cls(parameters=params, files=files)

    @property
    def files_count(self) -> int:
        return len(self.files)


@dataclass
class AnalysisResult:
    """Result of analysis operation"""

    status: str
    rules_content: Optional[str] = None
    error: Optional[str] = None
    rules_count: int = 0
    files_analyzed: int = 0
    identifier: str = ""

    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON response"""
        result = {
            "status": self.status,
            "rules_count": self.rules_count,
            "files_analyzed": self.files_analyzed,
            "identifier": self.identifier,
        }

        if self.rules_content:
            result.update(
                {"rules_generated": True, "rules_content": self.rules_content}
            )

        if self.error:
            result["error"] = str(self.error)

        return result

    @classmethod
    def success(
        cls, rules_content: str, identifier: str, files_analyzed: int
    ) -> "AnalysisResult":
        """Create successful result"""
        return cls(
            status="success",
            rules_content=rules_content,
            rules_count=rules_content.count("rule ") if rules_content else 0,
            files_analyzed=files_analyzed,
            identifier=identifier,
        )

    @classmethod
    def error(cls, error_message: str) -> "AnalysisResult":
        """Create error result"""
        return cls(status="error", error=error_message)


# Global database context
db_context = DatabaseContext()


def initialize_databases(db_path: str):
    """Initialize databases on startup"""
    try:
        logger.info("Initializing databases...")

        # Load pestudio strings
        db_context.pestudio_strings = initialize_pestudio_strings()

        # Load databases
        (
            db_context.good_strings_db,
            db_context.good_opcodes_db,
            db_context.good_imphashes_db,
            db_context.good_exports_db,
        ) = load_databases(db_path)

        logger.info("Databases initialized successfully")

    except Exception as e:
        logger.error(f"Failed to initialize databases: {e}")
        raise


def init_analysis_context():
    """Initialize analysis context (FP, SE)"""
    config = stringzz.Config()
    global db_context
    db_context.fp, db_context.se = stringzz.init_analysis(
        config,
        False,
        5,
        5,
        *db_context.databases_tuple,
        db_context.pestudio_strings,
    )
    return db_context.fp, db_context.se


def ensure_databases_initialized():
    """Ensure databases are initialized before analysis"""
    if not db_context.is_initialized():
        initialize_databases(DB_PATH)
        init_analysis_context()


# Web Routes
@app.route("/")
def index():
    """Main web interface"""
    return render_template("index.html", form_config=FORM_FIELDS_CONFIG)


@app.route("/health", methods=["GET"])
def health_check():
    """Health check endpoint"""
    return jsonify(
        {
            "status": "healthy",
            "service": "yarobot-http",
            "databases_loaded": db_context.is_initialized(),
        }
    )


@app.route("/api/analyze", methods=["POST"])
def analyze():
    """Analyze uploaded files and generate YARA rules"""
    try:
        # Create analysis request from Flask request
        analysis_request = AnalysisRequest.from_flask_request(request)
        print(analysis_request)
        # Ensure databases are initialized
        ensure_databases_initialized()
        global db_context
        logger.info(f"Starting analysis for {analysis_request.files_count} files")
        db_context.fp = stringzz.FileProcessor(analysis_request.parameters.to_config())
        db_context.se.min_score = analysis_request.parameters.min_score
        db_context.se.excludegood = analysis_request.parameters.excludegood
        db_context.se.superrule_overlap = analysis_request.parameters.superrule_overlap
        rules_content = process_buffers(
            db_context.fp,
            db_context.se,
            analysis_request.parameters,
            [f.read() for f in analysis_request.files],
            *db_context.databases_tuple,
            db_context.pestudio_strings,
        )

        result = AnalysisResult.success(
            rules_content=rules_content,
            identifier=analysis_request.identifier,
            files_analyzed=analysis_request.files_count,
        )
        result = result.to_dict()
        # print(result)
        init_analysis_context()
        return jsonify(result)

    except ValueError as e:
        logger.error(f"Validation error: {e}")
        return jsonify(AnalysisResult.error(str(e)).to_dict()), 400
    # except Exception as e:
    #    logger.error(f"Error during analysis: {e}")
    #    return jsonify(AnalysisResult.error("Internal server error").to_dict()), 500


@app.route("/api/status", methods=["GET"])
def get_status():
    """Get service status and database information"""
    db_info = {}

    if db_context.is_initialized():
        db_info = {
            "good_strings_entries": len(db_context.good_strings_db),
            "good_opcodes_entries": len(db_context.good_opcodes_db),
            "good_imphashes_entries": len(db_context.good_imphashes_db),
            "good_exports_entries": len(db_context.good_exports_db),
            "pestudio_strings_loaded": db_context.pestudio_strings is not None,
        }

    return jsonify(
        {
            "status": "running",
            "databases": db_info,
            "databases_initialized": db_context.is_initialized(),
        }
    )


# Error handlers
@app.errorhandler(413)
def too_large(e):
    return jsonify(AnalysisResult.error("File too large").to_dict()), 413


@app.errorhandler(500)
def internal_error(e):
    return jsonify(AnalysisResult.error("Internal server error").to_dict()), 500


@app.errorhandler(404)
def not_found(e):
    return render_template("index.html", form_config=FORM_FIELDS_CONFIG), 404


def create_template_directories():
    """Create necessary directories for templates"""
    os.makedirs(template_dir, exist_ok=True)

    # Create static directory if needed
    static_dir = os.path.join(current_dir, "static")
    os.makedirs(static_dir, exist_ok=True)


@click.command()
@click.option(
    "-g", type=click.Path(exists=True), help="path to folder with goodware dbs"
)
def main(g=None):
    """Main entry point"""
    global DB_PATH

    if g:
        DB_PATH = g

    # Initialize databases before starting the server
    initialize_databases(DB_PATH)
    init_analysis_context()

    # Create templates directory if it doesn't exist
    create_template_directories()

    logger.info(
        f"Starting yarobot web interface on "
        f"http://{os.getenv('YAROBOT_HOST', '0.0.0.0')}:{os.getenv('YAROBOT_PORT', 5000)}"
    )
    logger.info(f"Template directory: {template_dir}")

    # Start Flask app
    app.run(
        host=os.getenv("YAROBOT_HOST", "0.0.0.0"),
        port=int(os.getenv("YAROBOT_PORT", 5000)),
        debug=os.getenv("YAROBOT_DEBUG", "false").lower() == "true",
    )


if __name__ == "__main__":
    main()
