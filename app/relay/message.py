"""Byte-level message editing.

We edit headers on the raw bytes and leave the body untouched wherever we can.
Round-tripping a whole MIME tree through Python's email package can change
encodings and line wrapping, which we never want to do to someone's mail.
"""

import re
import uuid
from email.header import Header, decode_header, make_header
from email.utils import formataddr, getaddresses, parseaddr

_HEADER_NAME = re.compile(rb"^([!-9;-~]+):")


class RawMessage:
    """A message as an ordered list of raw header fields plus body bytes."""

    def __init__(self, headers: list[tuple[str, bytes]], body: bytes):
        # Each header is (name, raw field bytes *including* "Name:" and folding
        # and the trailing CRLF), so untouched headers round-trip exactly.
        self.headers = headers
        self.body = body

    @classmethod
    def parse(cls, raw: bytes) -> "RawMessage":
        raw = raw.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
        sep = raw.find(b"\r\n\r\n")
        if sep == -1:
            head, body = raw, b""
        else:
            head, body = raw[: sep + 2], raw[sep + 4 :]
        headers: list[tuple[str, bytes]] = []
        for line in head.split(b"\r\n"):
            if not line:
                continue
            if line[:1] in (b" ", b"\t") and headers:
                name, field = headers[-1]
                headers[-1] = (name, field + line + b"\r\n")
                continue
            m = _HEADER_NAME.match(line)
            if not m:
                # Garbage line in the header block (e.g. mbox "From " line): drop it.
                continue
            headers.append((m.group(1).decode("ascii"), line + b"\r\n"))
        return cls(headers, body)

    def to_bytes(self) -> bytes:
        return b"".join(f for _, f in self.headers) + b"\r\n" + self.body

    # --- reading -----------------------------------------------------------

    def get_all(self, name: str) -> list[str]:
        lname = name.lower()
        return [_field_value(f) for n, f in self.headers if n.lower() == lname]

    def get(self, name: str, default: str | None = None) -> str | None:
        values = self.get_all(name)
        return values[0] if values else default

    def has(self, name: str) -> bool:
        lname = name.lower()
        return any(n.lower() == lname for n, _ in self.headers)

    # --- writing -----------------------------------------------------------

    def remove(self, name: str) -> None:
        lname = name.lower()
        self.headers = [(n, f) for n, f in self.headers if n.lower() != lname]

    def remove_matching(self, predicate) -> None:
        self.headers = [(n, f) for n, f in self.headers if not predicate(n.lower())]

    def set(self, name: str, value: str) -> None:
        """Replace the first occurrence in place (keeps header order) and drop
        any duplicates; append if absent."""
        lname = name.lower()
        field = encode_field(name, value)
        out, done = [], False
        for n, f in self.headers:
            if n.lower() == lname:
                if not done:
                    out.append((name, field))
                    done = True
                continue
            out.append((n, f))
        if not done:
            out.append((name, field))
        self.headers = out

    def prepend(self, name: str, value: str) -> None:
        self.headers.insert(0, (name, encode_field(name, value)))

    def prepend_raw(self, field: bytes) -> None:
        """Prepend an already formatted header field (e.g. from dkimpy)."""
        if not field.endswith(b"\r\n"):
            field += b"\r\n"
        m = _HEADER_NAME.match(field)
        self.headers.insert(0, (m.group(1).decode("ascii"), field))


def _field_value(field: bytes) -> str:
    _, _, value = field.partition(b":")
    text = value.decode("utf-8", errors="replace")
    # Unfold.
    return re.sub(r"\r\n([ \t])", r"\1", text).strip()


def encode_field(name: str, value: str) -> bytes:
    """Format a header field. Callers pass values already RFC 2047-encoded
    where needed (see format_address); we only fold long lines."""
    line = f"{name}: {value}"
    if len(line) <= 998:
        return line.encode("utf-8") + b"\r\n"
    # Fold at spaces/commas for very long values (References, To lists).
    parts, current = [], f"{name}:"
    for token in value.split(" "):
        if len(current) + 1 + len(token) > 76 and current.strip():
            parts.append(current)
            current = " " + token
        else:
            current += " " + token
    parts.append(current)
    return "\r\n".join(parts).encode("utf-8") + b"\r\n"


# --- address helpers ------------------------------------------------------


def decode_words(value: str) -> str:
    """Decode RFC 2047 encoded words to text."""
    try:
        return str(make_header(decode_header(value)))
    except Exception:
        return value


def parse_addresses(value: str | None) -> list[tuple[str, str]]:
    """Return [(display name, lowercased address)] from an address header."""
    if not value:
        return []
    out = []
    for name, addr in getaddresses([value]):
        addr = addr.strip().lower()
        if "@" in addr:
            out.append((decode_words(name).strip(), addr))
    return out


def parse_address(value: str | None) -> tuple[str, str]:
    if not value:
        return "", ""
    name, addr = parseaddr(value)
    return decode_words(name).strip(), addr.strip().lower()


def format_address(name: str, addr: str) -> str:
    if not name:
        return addr
    try:
        name.encode("ascii")
        return formataddr((name, addr))
    except UnicodeEncodeError:
        return formataddr((Header(name, "utf-8").encode(), addr))


def format_address_list(items: list[tuple[str, str]]) -> str:
    return ", ".join(format_address(n, a) for n, a in items)


def domain_of(addr: str) -> str:
    return addr.rpartition("@")[2].lower()


def local_of(addr: str) -> str:
    return addr.rpartition("@")[0]


_MSGID = re.compile(r"<[^<>\s]+>")


def parse_msgids(value: str | None) -> list[str]:
    return _MSGID.findall(value or "")


def make_msgid(domain: str) -> str:
    return f"<{uuid.uuid4().hex}@{domain}>"


def normalize_mailbox(addr: str) -> str:
    """Canonical form used to compare a sender with the registered address.

    For Gmail, dots in the local part are ignored, +tags are stripped and
    googlemail.com is the same as gmail.com.
    """
    addr = addr.strip().lower()
    local, _, domain = addr.rpartition("@")
    if domain == "googlemail.com":
        domain = "gmail.com"
    if domain == "gmail.com":
        local = local.split("+", 1)[0].replace(".", "")
    return f"{local}@{domain}"
