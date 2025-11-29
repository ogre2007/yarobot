from typing import Any, List, Set
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

def get_file_info(file_data: bytes) -> FileInfo: ...

__all__ = [
    "FileInfo",
    "TokenType", 
    "TokenInfo",
    "get_file_info"
]