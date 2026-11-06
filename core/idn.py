"""
Internationalized domain names. DNS, passive DNS, certificates, Iris Investigate and Domain History all store the
ASCII (punycode, `xn--`) form, so lookups always use it: Unicode input is converted first. For reading, any `xn--`
label in a text can be shown in Unicode again (bücher.de instead of xn--bcher-kva.de).
"""
import re

import idna

ACE_PREFIX = "xn--"
_ACE_LABEL = re.compile(r"(?<![a-z0-9-])xn--[a-z0-9-]+", re.IGNORECASE)


def to_ascii(name):
    """Punycode form of a domain or hostname (`*.` kept); the name unchanged when it is ASCII or cannot be encoded."""
    name = str(name or "")
    if name.isascii():
        return name
    wildcard = name.startswith("*.")
    body = name[2:] if wildcard else name
    try:
        encoded = idna.encode(body, uts46=True).decode("ascii")
    except idna.IDNAError:
        try:   # IDNA 2003 is more lenient (e.g. some symbols registries still hold)
            encoded = body.encode("idna").decode("ascii")
        except UnicodeError:
            return name
    return ("*." if wildcard else "") + encoded


def _label_to_unicode(match):
    label = match.group(0)
    try:
        return idna.decode(label.lower())
    except idna.IDNAError:
        try:
            return label.encode("ascii").decode("idna")
        except UnicodeError:
            return label


def has_ace(text):
    return ACE_PREFIX in str(text).lower()


def to_unicode(text):
    """`text` with every `xn--` label decoded (domains inside longer text too); other text unchanged."""
    if not isinstance(text, str) or ACE_PREFIX not in text.lower():
        return text
    return _ACE_LABEL.sub(_label_to_unicode, text)


def unicode_label(name):
    """'xn--bcher-kva.de (bücher.de)' for an internationalized name, the name alone otherwise."""
    decoded = to_unicode(name)
    return f"{name} ({decoded})" if decoded != name else name
