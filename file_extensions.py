"""
file_extensions.py

Centralized list of known file extensions, used to identify standalone
"word.word"-shaped candidates that are actually filenames/resources
rather than domains - e.g. "settings.py", "wp-cron.php", "malware.exe",
"index.html".

This is deliberately NOT trying to solve TLD-ambiguity cases like
".py" (Paraguay's ccTLD) or ".md" (Moldova's ccTLD) - a string like
"settings.py" is filtered out here purely because ".py" is a known file
extension, independent of whether ".py" also happens to be a valid TLD.
That dual nature is an intentional, accepted limitation: the goal for
this list is to catch common filename patterns, not to arbitrate TLD
policy (see domain_validation.py for the separate, real-TLD-based
domain check that policy question belongs to).

Only used for STANDALONE candidates - see artifacts/_scan.py and
domain_validation.py for how this and the TLD check combine, and
artifacts/_scan.py's URL-handling for why this list must never be
applied to a URL's host or path (a URL's own extension, e.g.
"http://evil.com/malware.exe", is legitimate and must not be discarded).

The list is centralized here specifically so it's easy to find and
extend in one place without touching extraction or classification logic.
"""

from __future__ import annotations

# Grouped by rough category purely for readability/maintainability - the
# set itself is flat and unordered at lookup time.
_SCRIPT_AND_EXECUTABLE_EXTENSIONS = {
    "py", "php", "sh", "ps1", "bat", "cmd", "exe", "dll", "msi",
    "jsp", "aspx", "asp", "js", "vbs", "pl", "rb", "jar", "war",
    "scr", "bin", "dex", "apk", "elf", "psm1", "psd1",
}

_DOCUMENT_EXTENSIONS = {
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "odt", "ods",
    "odp", "rtf", "txt", "csv", "log",
}

_DATA_AND_CONFIG_EXTENSIONS = {
    "json", "xml", "yaml", "yml", "conf", "ini", "config", "cfg",
    "toml", "env", "properties", "plist",
}

_ARCHIVE_EXTENSIONS = {
    "zip", "rar", "7z", "tar", "gz", "bz2", "xz", "iso", "cab",
}

_WEB_ASSET_EXTENSIONS = {
    "html", "htm", "css", "scss", "sass", "less", "map",
}

_MEDIA_EXTENSIONS = {
    "png", "jpg", "jpeg", "gif", "bmp", "svg", "ico", "webp", "tiff",
    "mp3", "mp4", "avi", "mov", "wav", "flac", "mkv", "wmv", "webm",
}

_FONT_EXTENSIONS = {
    "woff", "woff2", "ttf", "otf", "eot",
}

# Union of every category above - the single, centralized source of
# truth used by domain_validation.py's standalone-filename check.
KNOWN_FILE_EXTENSIONS: frozenset[str] = frozenset(
    _SCRIPT_AND_EXECUTABLE_EXTENSIONS
    | _DOCUMENT_EXTENSIONS
    | _DATA_AND_CONFIG_EXTENSIONS
    | _ARCHIVE_EXTENSIONS
    | _WEB_ASSET_EXTENSIONS
    | _MEDIA_EXTENSIONS
    | _FONT_EXTENSIONS
)


def has_known_file_extension(value: str) -> bool:
    """
    True if `value`'s final dot-separated segment matches a known file
    extension (case-insensitive). Only meaningful for standalone
    candidates - never apply this to a URL's host or path, where a file
    extension is entirely normal and expected.
    """
    if "." not in value:
        return False
    extension = value.rsplit(".", 1)[-1].lower()
    return extension in KNOWN_FILE_EXTENSIONS
