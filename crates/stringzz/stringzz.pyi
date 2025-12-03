# stringzz.pyi - Add Config and ConfigBuilder
from typing import Any, List, Set, Optional, Dict, Tuple
from dataclasses import dataclass
from enum import Enum

class TokenType(Enum):
    """Enum representing different types of tokens."""
    ASCII = 0
    UTF16LE = 1
    BINARY = 2
    
    def __eq__(self, other: Any) -> bool: ...

@dataclass
class FileInfo:
    """File information container for PE file analysis."""
    imphash: str
    exports: List[str]
    sha256: str
    size: int
    magic: bytes
    
    def __str__(self) -> str: ...

@dataclass
class TokenInfo:
    """Container for token information used in string extraction and analysis."""
    reprz: str
    count: int
    typ: TokenType
    files: Set[str]
    notes: str
    score: int = 0
    fullword: bool = True
    b64: bool = False
    hexed: bool = False
    reversed: bool = False
    from_pestudio: bool = False
    
    def __post_init__(self) -> None: ...
    def __str__(self) -> str: ...
    def generate_string_repr(self, i: int, is_super_string: bool) -> str: ...
    def merge(self, value: 'TokenInfo') -> None: ...
    def add_file(self, value: str) -> None: ...
    def add_note(self, value: str) -> None: ...

class Config:
    """Configuration for file processing."""
    min_string_len: int
    max_string_len: int
    max_file_size_mb: int
    recursive: bool
    extensions: Optional[List[str]]
    extract_opcodes: bool
    debug: bool
    
    def __init__(
        self,
        min_string_len: Optional[int] = None,
        max_string_len: Optional[int] = None,
        max_file_size_mb: Optional[int] = None,
        recursive: Optional[bool] = None,
        extensions: Optional[List[str]] = None,
        extract_opcodes: Optional[bool] = None,
        debug: Optional[bool] = None
    ) -> None: ...
    
    @staticmethod
    def builder() -> 'ConfigBuilder': ...
    
    def validate(self) -> None: ...

class ConfigBuilder:
    """Builder for Config objects."""
    def __init__(self) -> None: ...
    def min_string_len(self, value: int) -> 'ConfigBuilder': ...
    def max_string_len(self, value: int) -> 'ConfigBuilder': ...
    def max_file_size_mb(self, value: int) -> 'ConfigBuilder': ...
    def recursive(self, value: bool) -> 'ConfigBuilder': ...
    def extensions(self, value: List[str]) -> 'ConfigBuilder': ...
    def extract_opcodes(self, value: bool) -> 'ConfigBuilder': ...
    def debug(self, value: bool) -> 'ConfigBuilder': ...
    def build(self) -> Config: ...

class FileProcessor:
    """Process files to extract strings and opcodes."""
    config: Config
    strings: Dict[str, TokenInfo]
    utf16strings: Dict[str, TokenInfo]
    opcodes: Dict[str, TokenInfo]
    file_infos: Dict[str, FileInfo]
    
    def __init__(self, config: Optional[Config] = None) -> None: ...
    
    def parse_sample_dir(
        self,
        dir: str
    ) -> Tuple[Dict[str, TokenInfo], Dict[str, TokenInfo], Dict[str, TokenInfo], Dict[str, FileInfo]]: ...
    
    def clear_context(self) -> None: ...
    
    def process_file_with_checks(self, file_path: str) -> bool: ...
    
    def deduplicate_strings(self) -> None: ...
    
    def get_config(self) -> Config: ...
    
    def set_config(self, config: Config) -> None: ...

def get_file_info(file_data: bytes) -> FileInfo: ...

def extract_strings(
    file_data: bytes,
    min_len: int,
    max_len: Optional[int] = None
) -> Tuple[Dict[str, TokenInfo], Dict[str, TokenInfo]]: ...

def remove_non_ascii_drop(data: bytes) -> str: ...

def is_base_64(s: str) -> bool: ...

def is_hex_encoded(s: str, check_length: bool) -> bool: ...

__all__ = [
    "FileInfo",
    "TokenType", 
    "TokenInfo",
    "Config",
    "ConfigBuilder",
    "FileProcessor",
    "get_file_info",
    "extract_strings",
    "remove_non_ascii_drop",
    "is_base_64",
    "is_hex_encoded"
]