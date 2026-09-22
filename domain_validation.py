"""
domain_validation.py

THE single, canonical domain validation used everywhere a value needs to
be judged "is this actually a domain": the direct CLI path (detector.py),
artifact extraction (artifacts/_scan.py), and provider-side input
validation (e.g. providers/otx.py, providers/threatfox.py) before a
value classified as a Domain IOC is ever sent to a threat-intelligence
API.

There is deliberately only ONE implementation here. Previously,
detector.py (direct CLI) and artifacts/_scan.py (artifact extraction)
each had their own separate domain-shape regex, and only the artifact
path had been updated to also check against real TLD data - so the two
paths could disagree about the same value (e.g. detector.py alone would
accept "wp-cron.php" as a Domain, while the artifact path correctly
rejected it). That divergence is exactly the class of bug this module
exists to make structurally impossible: every caller imports
`is_valid_domain` from here, so there is nowhere left for the two paths
to drift apart.

Validation has three layers, all required:

    1. RFC-1035-ish shape - labels of 1-63 alphanumeric/hyphen
       characters (no leading/trailing hyphen), joined by dots, total
       length under 254 characters, with a final label of 2-63 letters.
       This is a necessary but NOT sufficient condition on its own -
       "wp-cron.php" satisfies this shape just as well as
       "evil.example.com" does, which is exactly why layers 2 and 3
       exist.

    2. NOT a known filename - see file_extensions.py. A standalone value
       whose final segment is a common file extension ("settings.py",
       "wp-cron.php", "malware.exe", "index.html") is rejected here,
       independent of whether that extension also happens to be a real
       TLD. This is a deliberately separate concern from layer 3: layer
       3 answers "is the suffix a real TLD", which for something like
       "settings.py" is actually YES (.py is Paraguay's ccTLD) - this
       layer exists specifically to catch that class of case without
       having to declare .py (or .zip, .sh, .mov, and other real TLDs
       that also happen to be common extensions) an "invalid" TLD, which
       is a separate policy question this module intentionally does not
       try to resolve.

    3. Real TLD/public-suffix validation via tldextract - "xpaywa" or
       "th.bing.c" have no valid suffix, while "evil.example.com"
       resolves to a real suffix (".com") with a real registrable domain
       ("example.com"). This is what distinguishes an actual domain from
       an arbitrary "word.word" string whose final segment isn't a
       common file extension AND isn't a real TLD either.

CRITICAL: this function is deliberately used ONLY for standalone
candidates. A URL's own host and path are never passed through here -
URLs are matched and extracted entirely separately (see
artifacts/_scan.py's URL step), so something like
"http://evil.com/malware.exe" is never at risk of layer 2 rejecting it
just because its path ends in ".exe". Do not call this function on any
part of a URL.

Known, unavoidable limitation: a handful of real ccTLDs/gTLDs happen to
also be common file extensions - ".md" (Moldova), ".io" (British Indian
Ocean Territory), ".ai" (Anguilla), and others not covered by layer 2's
extension list. A string shaped like one of those is genuinely ambiguous
by syntax alone - no purely syntactic check can resolve it without
additional context (e.g. whether the file actually exists on disk). This
is a known, accepted trade-off; single-word values ("c", "xpaywa"),
values with a too-short final label ("th.bing.c"), and any filename whose
extension is in file_extensions.py's list (which covers every extension
named in this project's spec, including ".py" and ".sh") are all
unambiguous and correctly rejected regardless of their TLD status.

Configured to use ONLY the snapshot bundled with the tldextract package
(no live fetch of the public suffix list) - this keeps validation fast,
deterministic, and fully offline, appropriate for a CLI tool that may run
in network-restricted environments and shouldn't make an unrelated HTTP
call just to validate a string's shape.
"""

from __future__ import annotations

import re

import tldextract

from file_extensions import has_known_file_extension

# RFC-1035-ish shape check: labels separated by dots, each 1-63 chars
# with no leading/trailing hyphen, whole string under 254 characters,
# and a final label (the TLD position) of 2-63 letters. Necessary but
# not sufficient - see module docstring layers 2 and 3 for what actually
# distinguishes a domain from a same-shaped filename.
_DOMAIN_SHAPE_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.[A-Za-z]{2,63}$"
)

# suffix_list_urls=() disables tldextract's live-fetch-and-cache behavior
# entirely, forcing it to rely solely on the snapshot bundled in the
# installed package. A single module-level instance is reused for every
# call - constructing it isn't free, and validation happens for every
# candidate domain found during extraction.
_extractor = tldextract.TLDExtract(suffix_list_urls=())


def is_valid_domain(value: str) -> bool:
    """
    True if `value` is shaped like a real domain name (RFC-1035-ish),
    its final segment isn't a known file extension, AND its suffix is a
    real, currently-recognized TLD/public suffix - i.e. it's an actual
    domain, not a filename, path segment, single word, or other
    "word.word"-shaped string that only superficially resembles a
    domain.

    Only call this on a standalone candidate - never on any part of a
    URL (see module docstring).
    """
    if not value or not _DOMAIN_SHAPE_RE.match(value):
        return False

    if has_known_file_extension(value):
        return False

    result = _extractor(value)
    return bool(result.domain and result.suffix)
