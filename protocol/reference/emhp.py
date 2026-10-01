"""ExitMesh History Protocol v1 reference oracle (standard library only)."""

import copy
import hashlib
import math
import re
import struct

VERSION = 1
MAX_RECORD_BYTES = 4 << 20
MAX_DEPTH = 32
MAX_CONTAINER = 1 << 20
EXT_MIN = 1000

MALFORMED = "malformed"
TOO_LARGE = "too_large"
UNSUPPORTED_FIELD = "unsupported_field"
INVALID_VALUE = "invalid_value"
INVALID_CHAIN = "invalid_chain"
INVALID_OP = "invalid_op"
INVALID_STATE_HASH = "invalid_state_hash"
UNAVAILABLE = "unavailable"
FOLD = "fold"

CHECKPOINT, DELTA, RANGE, FINDING = 1, 2, 3, 4
TYPE_NAMES = {CHECKPOINT: "checkpoint", DELTA: "delta", RANGE: "range", FINDING: "finding"}
CREATE, UPDATE, DELETE, EDGE_ADD, EDGE_REMOVE, EDGE_REPLACE, SCOPE_SET = 1, 2, 3, 4, 5, 6, 7

_TARGET_RE = re.compile(r"[A-Za-z0-9._-]{1,128}")


class ProtocolError(Exception):
    def __init__(self, code, message=""):
        super().__init__(code + (": " + message if message else ""))
        self.code = code


class Key:
    """A map key that is neither an unsigned integer nor text; equality follows Go map key semantics."""

    __slots__ = ("kind", "value")

    def __init__(self, kind, value):
        self.kind = kind
        self.value = value

    def __eq__(self, other):
        return isinstance(other, Key) and self.kind == other.kind and self.value == other.value

    def __hash__(self):
        return hash((self.kind, self.value))

    def __repr__(self):
        return "Key(%s, %r)" % (self.kind, self.value)


# Deterministic encoding (SPEC 3.1).

def _head(major, n):
    if n < 24:
        return bytes([major << 5 | n])
    if n < 0x100:
        return bytes([major << 5 | 24, n])
    if n < 0x10000:
        return bytes([major << 5 | 25]) + n.to_bytes(2, "big")
    if n < 0x100000000:
        return bytes([major << 5 | 26]) + n.to_bytes(4, "big")
    return bytes([major << 5 | 27]) + n.to_bytes(8, "big")


def encode_float(x):
    if math.isnan(x) or math.isinf(x):
        raise ProtocolError(INVALID_VALUE, "non-finite float")
    for fmt, ib in ((">e", 0xF9), (">f", 0xFA)):
        try:
            b = struct.pack(fmt, x)
        except (OverflowError, struct.error):
            continue
        if struct.unpack(fmt, b)[0] == x:
            return bytes([ib]) + b
    return b"\xfb" + struct.pack(">d", x)


def _enc(v, out):
    if v is None:
        out.append(0xF6)
    elif v is True:
        out.append(0xF5)
    elif v is False:
        out.append(0xF4)
    elif isinstance(v, int):
        if v >= 0:
            if v >= 1 << 64:
                raise ProtocolError(INVALID_VALUE, "integer out of range")
            out += _head(0, v)
        else:
            if v < -(1 << 64):
                raise ProtocolError(INVALID_VALUE, "integer out of range")
            out += _head(1, -1 - v)
    elif isinstance(v, float):
        out += encode_float(v)
    elif isinstance(v, str):
        b = v.encode("utf-8")
        out += _head(3, len(b))
        out += b
    elif isinstance(v, (bytes, bytearray)):
        out += _head(2, len(v))
        out += v
    elif isinstance(v, (list, tuple)):
        out += _head(4, len(v))
        for e in v:
            _enc(e, out)
    elif isinstance(v, dict):
        pairs = sorted((encode(k), encode(e)) for k, e in v.items())
        out += _head(5, len(pairs))
        for k, e in pairs:
            out += k
            out += e
    elif isinstance(v, Key):
        _enc(v.value, out)
    else:
        raise ProtocolError(INVALID_VALUE, "unsupported type " + type(v).__name__)


def encode(v):
    out = bytearray()
    _enc(v, out)
    return bytes(out)


# Strict decoding (SPEC 3.2).

class _Reader:
    __slots__ = ("b", "i")

    def __init__(self, b):
        self.b = b
        self.i = 0

    def take(self, n):
        j = self.i + n
        if j > len(self.b):
            raise ProtocolError(MALFORMED, "truncated")
        s = self.b[self.i:j]
        self.i = j
        return s


def _arg(r, ai):
    if ai < 24:
        return ai
    if ai == 24:
        return r.take(1)[0]
    if ai == 25:
        return int.from_bytes(r.take(2), "big")
    if ai == 26:
        return int.from_bytes(r.take(4), "big")
    if ai == 27:
        return int.from_bytes(r.take(8), "big")
    if ai == 31:
        raise ProtocolError(MALFORMED, "indefinite length")
    raise ProtocolError(MALFORMED, "reserved additional information")


def _map_key(k):
    if k is None or isinstance(k, bool):
        return Key("simple", k)
    if isinstance(k, int):
        if k >= 0:
            return k
        if k < -(1 << 63):
            raise ProtocolError(MALFORMED, "invalid map key")
        return Key("nint", k)
    if isinstance(k, float):
        return Key("float", k)
    if isinstance(k, str):
        return k
    if isinstance(k, bytes):
        return Key("bytes", k)
    raise ProtocolError(MALFORMED, "invalid map key type")


def _item(r, depth):
    ib = r.take(1)[0]
    major, ai = ib >> 5, ib & 0x1F
    if major == 7:
        if ai == 20:
            return False
        if ai == 21:
            return True
        if ai == 22:
            return None
        if ai == 25:
            v = struct.unpack(">e", r.take(2))[0]
        elif ai == 26:
            v = struct.unpack(">f", r.take(4))[0]
        elif ai == 27:
            v = struct.unpack(">d", r.take(8))[0]
        elif ai == 31:
            raise ProtocolError(MALFORMED, "unexpected break")
        elif ai == 24:
            r.take(1)
            raise ProtocolError(MALFORMED, "simple value")
        elif ai > 24:
            raise ProtocolError(MALFORMED, "reserved additional information")
        else:
            raise ProtocolError(MALFORMED, "simple value")
        if math.isnan(v) or math.isinf(v):
            raise ProtocolError(MALFORMED, "non-finite float")
        return v
    if major == 6:
        raise ProtocolError(MALFORMED, "tag")
    n = _arg(r, ai)
    if major == 0:
        return n
    if major == 1:
        return -1 - n
    if major == 2:
        return bytes(r.take(n))
    if major == 3:
        try:
            return r.take(n).decode("utf-8")
        except UnicodeDecodeError:
            raise ProtocolError(MALFORMED, "invalid utf-8") from None
    depth += 1
    if depth > MAX_DEPTH:
        raise ProtocolError(MALFORMED, "nesting too deep")
    if n > MAX_CONTAINER:
        raise ProtocolError(MALFORMED, "container too large")
    if major == 4:
        return [_item(r, depth) for _ in range(n)]
    m = {}
    for _ in range(n):
        k = _map_key(_item(r, depth))
        v = _item(r, depth)
        if k in m:
            raise ProtocolError(MALFORMED, "duplicate map key")
        m[k] = v
    return m


def decode_strict(b):
    b = bytes(b)
    if len(b) > MAX_RECORD_BYTES:
        raise ProtocolError(TOO_LARGE, "%d bytes" % len(b))
    r = _Reader(b)
    v = _item(r, 0)
    if r.i != len(b):
        raise ProtocolError(MALFORMED, "%d trailing bytes" % (len(b) - r.i))
    if encode(v) != b:
        raise ProtocolError(MALFORMED, "not deterministically encoded")
    return v


# Hashes and identifiers (SPEC 7).

def domain_hash(domain, *parts):
    h = hashlib.sha256(domain.encode() + b"\x00")
    for p in parts:
        h.update(p)
    return h.digest()


def record_hash(b):
    return domain_hash("EMHPv1/record", b)


def genesis(target_id, epoch, writer):
    return domain_hash("EMHPv1/genesis", encode([target_id, bytes(epoch), bytes(writer)]))


def chain_hash(prev, rec_hash):
    return domain_hash("EMHPv1/chain", prev, rec_hash)


def finding_id(target_id, dedup_key, first_seen):
    return domain_hash("EMHPv1/finding", encode([target_id, dedup_key, first_seen]))[:16].hex()


def query_hash(language, normalized_query, source):
    return domain_hash("EMHPv1/query", encode([language, normalized_query, source]))


def valid_target_id(s):
    return isinstance(s, str) and _TARGET_RE.fullmatch(s) is not None


# Record decoding (SPEC 4).

def _is_uint(v):
    return type(v) is int and v >= 0


class _IntMap:
    def __init__(self, v):
        if type(v) is not dict:
            raise ProtocolError(MALFORMED, "expected map")
        for k in v:
            if type(k) is not int:
                raise ProtocolError(MALFORMED, "expected unsigned integer key")
        self.m = v
        self.used = set()

    def has(self, k):
        return k in self.m

    def get(self, k):
        if k in self.m:
            self.used.add(k)
            return True, self.m[k]
        return False, None

    def require(self, k):
        ok, v = self.get(k)
        if not ok:
            raise ProtocolError(MALFORMED, "missing key %d" % k)
        return v

    def uint(self, k):
        v = self.require(k)
        if not _is_uint(v):
            raise ProtocolError(MALFORMED, "key %d: expected uint" % k)
        return v

    def opt_uint(self, k):
        if not self.has(k):
            return None
        return self.uint(k)

    def text(self, k):
        v = self.require(k)
        if type(v) is not str:
            raise ProtocolError(MALFORMED, "key %d: expected text" % k)
        return v

    def bytes_n(self, k, n):
        v = self.require(k)
        if type(v) is not bytes or len(v) != n:
            raise ProtocolError(MALFORMED, "key %d: expected %d-byte string" % (k, n))
        return v

    def array(self, k):
        v = self.require(k)
        if type(v) is not list:
            raise ProtocolError(MALFORMED, "key %d: expected array" % k)
        return v

    def unknown(self):
        keys = sorted(k for k in self.m if k not in self.used and k < EXT_MIN)
        if keys:
            raise ProtocolError(UNSUPPORTED_FIELD, "key %d" % keys[0])

    def extensions(self):
        return {k: v for k, v in self.m.items() if k >= EXT_MIN}


def _value(v, allow_null):
    if v is None:
        if allow_null:
            return None
        raise ProtocolError(INVALID_VALUE, "null")
    if isinstance(v, (bool, str, bytes, float)):
        return v
    if isinstance(v, int):
        if v < -(1 << 63):
            raise ProtocolError(INVALID_VALUE, "integer out of range")
        return v
    if isinstance(v, list):
        return [_value(e, False) for e in v]
    if isinstance(v, dict):
        out = {}
        for k, e in v.items():
            if type(k) is not str:
                raise ProtocolError(INVALID_VALUE, "non-text map key")
            out[k] = _value(e, False)
        return out
    raise ProtocolError(INVALID_VALUE, "unsupported value")


def _fields(v, allow_null):
    if type(v) is not dict:
        raise ProtocolError(MALFORMED, "expected map")
    out = {}
    for k, e in v.items():
        if type(k) is not str:
            raise ProtocolError(MALFORMED, "non-text field key")
        out[k] = _value(e, allow_null)
    return out


def _interval(v):
    if type(v) is not list or len(v) != 2 or not _is_uint(v[0]) or not _is_uint(v[1]):
        raise ProtocolError(MALFORMED, "interval")
    return (v[0], v[1])


def _scope_status(v):
    m = _IntMap(v)
    state = m.uint(0)
    reason = ""
    if m.has(1):
        reason = m.text(1)
        if reason == "":
            raise ProtocolError(MALFORMED, "empty scope reason must be omitted")
    since = 0
    if m.has(2):
        since = m.uint(2)
        if since == 0:
            raise ProtocolError(MALFORMED, "zero scope since must be omitted")
    m.unknown()
    return (state, reason, since), m


def _op(v):
    m = _IntMap(v)
    kind = m.uint(0)
    o = {"op": kind}
    if kind == CREATE:
        o["uid"] = m.text(1)
        o["kind"] = m.text(2)
        o["ns"] = m.text(3)
        o["name"] = m.text(4)
        o["fields"] = _fields(m.require(5), False)
    elif kind == UPDATE:
        o["uid"] = m.text(1)
        o["fields"] = _fields(m.require(5), True)
    elif kind == DELETE:
        o["uid"] = m.text(1)
        o["reason"] = m.uint(6)
    elif kind in (EDGE_ADD, EDGE_REMOVE, EDGE_REPLACE):
        o["uid"] = m.text(1)
        o["type"] = m.text(7)
        o["to"] = m.text(8)
        o["attrs"] = _fields(m.require(9), False)
        if kind == EDGE_REPLACE:
            o["prev"] = _fields(m.require(10), False)
    elif kind == SCOPE_SET:
        o["scope_key"] = m.text(11)
        o["scope"], sm = _scope_status(m.require(12))
        if sm.extensions():
            raise ProtocolError(UNSUPPORTED_FIELD, "extension keys are not allowed inside ops")
    else:
        raise ProtocolError(INVALID_OP, "op kind %d" % kind)
    m.unknown()
    if m.extensions():
        raise ProtocolError(UNSUPPORTED_FIELD, "extension keys are not allowed inside ops")
    return o


def _strings(v, non_empty):
    if type(v) is not list or (non_empty and not v):
        raise ProtocolError(MALFORMED, "expected text array")
    for s in v:
        if type(s) is not str:
            raise ProtocolError(MALFORMED, "expected text")
    return list(v)


def _string_map(v):
    if type(v) is not dict or not v:
        raise ProtocolError(MALFORMED, "expected non-empty text map")
    for k, e in v.items():
        if type(k) is not str or type(e) is not str:
            raise ProtocolError(MALFORMED, "expected text map")
    return dict(v)


def _provenance(v):
    m = _IntMap(v)
    kind = m.uint(0)
    if kind == 1:
        p = {"kind": 1, "rule_id": m.text(1), "rule_version": m.uint(2), "bundle_version": m.text(3)}
    elif kind == 2:
        p = {"kind": 2, "query_hash": m.bytes_n(4, 32), "requester": m.text(5)}
    else:
        raise ProtocolError(MALFORMED, "provenance kind %d" % kind)
    m.unknown()
    return p


def _evidence(v):
    m = _IntMap(v)
    e = {"source": m.text(0), "time": m.uint(1), "text": m.text(2), "count": 0, "labels": {},
         "truncated": False, "context": False}
    c = m.opt_uint(3)
    if c is not None:
        if c == 0:
            raise ProtocolError(MALFORMED, "zero count must be omitted")
        e["count"] = c
    ok, x = m.get(4)
    if ok:
        e["labels"] = _string_map(x)
    for k, name in ((5, "truncated"), (6, "context")):
        ok, x = m.get(k)
        if ok:
            if x is not True:
                raise ProtocolError(MALFORMED, "flag key %d must be true when present" % k)
            e[name] = True
    m.unknown()
    return e


def _finding(v):
    m = _IntMap(v)
    f = {"id": m.text(0), "dedup_key": m.text(1), "transition": m.uint(2)}
    f["provenance"] = _provenance(m.require(3))
    f["category"] = m.text(4)
    f["severity"] = m.uint(5)
    for k, name in ((6, "eval_time"), (7, "first_seen"), (8, "last_seen"), (9, "count")):
        f[name] = m.uint(k)
    f["resources"] = _strings(m.require(10), False)
    f.update(facts={}, evidence=[], flags=0, node="", labels={}, summary="", suggestions=[], coverage=[])
    ok, x = m.get(11)
    if ok:
        f["facts"] = _fields(x, False)
        if not f["facts"]:
            raise ProtocolError(MALFORMED, "empty facts must be omitted")
    if m.has(12):
        ev = m.array(12)
        if not ev:
            raise ProtocolError(MALFORMED, "empty evidence must be omitted")
        f["evidence"] = [_evidence(x) for x in ev]
    fl = m.opt_uint(13)
    if fl is not None:
        if fl == 0:
            raise ProtocolError(MALFORMED, "zero flags must be omitted")
        f["flags"] = fl
    for k, name in ((14, "node"), (16, "summary")):
        if m.has(k):
            f[name] = m.text(k)
            if f[name] == "":
                raise ProtocolError(MALFORMED, "empty text key %d must be omitted" % k)
    ok, x = m.get(15)
    if ok:
        f["labels"] = _string_map(x)
    if m.has(17):
        ss = m.array(17)
        if not ss:
            raise ProtocolError(MALFORMED, "empty suggestions must be omitted")
        for x in ss:
            sm = _IntMap(x)
            s = {"language": sm.text(0), "query": sm.text(1), "source": ""}
            if sm.has(2):
                s["source"] = sm.text(2)
                if s["source"] == "":
                    raise ProtocolError(MALFORMED, "empty suggestion source must be omitted")
            sm.unknown()
            f["suggestions"].append(s)
    ok, x = m.get(18)
    if ok:
        f["coverage"] = _strings(x, True)
    m.unknown()
    return f


def _resource(v):
    if type(v) is not list or len(v) != 5:
        raise ProtocolError(MALFORMED, "resource")
    if not all(type(x) is str for x in v[:4]):
        raise ProtocolError(MALFORMED, "resource identity")
    return [v[0], v[1], v[2], v[3], _fields(v[4], False)]


def _edge(v):
    if type(v) is not list or len(v) != 4:
        raise ProtocolError(MALFORMED, "edge")
    if not all(type(x) is str for x in v[:3]):
        raise ProtocolError(MALFORMED, "edge key")
    return [v[0], v[1], v[2], _fields(v[3], False)]


def _checkpoint(v):
    m = _IntMap(v)
    c = {"reason": m.uint(0), "interval": _interval(m.require(1))}
    c["resources"] = [_resource(x) for x in m.array(2)]
    c["edges"] = [_edge(x) for x in m.array(3)]
    sc = m.require(4)
    if type(sc) is not dict:
        raise ProtocolError(MALFORMED, "scopes")
    c["scopes"] = {}
    for k, x in sc.items():
        if type(k) is not str:
            raise ProtocolError(MALFORMED, "scope key")
        c["scopes"][k] = _scope_status(x)[0]
    caps = m.array(5)
    for x in caps:
        if type(x) is not str:
            raise ProtocolError(MALFORMED, "capability")
    c["caps"] = list(caps)
    c["state_hash"] = m.bytes_n(6, 32)
    c["prev_epoch"] = m.bytes_n(7, 16) if m.has(7) else None
    c["prev_head"] = m.opt_uint(8)
    m.unknown()
    return c


def _delta(v):
    m = _IntMap(v)
    d = {"ops": [_op(x) for x in m.array(0)], "flags": 0, "uncertain": None}
    fl = m.opt_uint(1)
    if fl is not None:
        if fl == 0:
            raise ProtocolError(MALFORMED, "zero flags must be omitted")
        d["flags"] = fl
    if m.has(2):
        d["uncertain"] = _interval(m.get(2)[1])
    m.unknown()
    return d


def _range(v):
    m = _IntMap(v)
    g = {"ops": [_op(x) for x in m.array(0)]}
    g["span"] = _interval(m.require(1))
    g["findings"] = []
    for x in m.array(2):
        if type(x) is not list or len(x) != 2:
            raise ProtocolError(MALFORMED, "range finding")
        if not _is_uint(x[0]):
            raise ProtocolError(MALFORMED, "range finding seq")
        g["findings"].append((x[0], _finding(x[1])))
    g["flags"] = 0
    fl = m.opt_uint(3)
    if fl is not None:
        if fl == 0:
            raise ProtocolError(MALFORMED, "zero flags must be omitted")
        g["flags"] = fl
    g["uncertain"] = []
    if m.has(4):
        ivs = m.array(4)
        if not ivs:
            raise ProtocolError(MALFORMED, "empty uncertainty list must be omitted")
        g["uncertain"] = [_interval(x) for x in ivs]
    m.unknown()
    return g


class Record:
    __slots__ = ("type", "target_id", "epoch", "seq", "writer", "incarnation", "parent", "base",
                 "time", "schema", "body", "ext", "raw", "hash")

    def __init__(self, **kw):
        for k in self.__slots__:
            setattr(self, k, kw.get(k))


def decode_record(b):
    """Strictly decodes and validates one record, mirroring the acceptance rules of pkg/protocol."""
    b = bytes(b)
    env = _IntMap(decode_strict(b))
    if env.uint(0) != VERSION:
        raise ProtocolError(UNSUPPORTED_FIELD, "protocol version")
    r = Record(type=env.uint(1))
    r.target_id = env.text(2)
    r.epoch = env.bytes_n(3, 16)
    r.seq = env.uint(4)
    r.writer = env.bytes_n(5, 16)
    r.incarnation, r.parent, r.base, r.time, r.schema = (env.uint(k) for k in (6, 7, 8, 9, 10))
    body = env.require(11)
    parsers = {CHECKPOINT: _checkpoint, DELTA: _delta, RANGE: _range, FINDING: _finding}
    if r.type not in parsers:
        raise ProtocolError(UNSUPPORTED_FIELD, "record type %d" % r.type)
    r.body = parsers[r.type](body)
    env.unknown()
    r.ext = env.extensions()
    validate_record(r)
    r.raw = b
    r.hash = record_hash(b)
    return r


# Validation (SPEC 4).

def _sb(s):
    return s.encode("utf-8")


def _ekey(k):
    return (_sb(k[0]), _sb(k[1]), _sb(k[2]))


def _op_class(o):
    return 0 if o["op"] <= DELETE else (1 if o["op"] <= EDGE_REPLACE else 2)


def op_sort_key(o):
    c = _op_class(o)
    if c == 0:
        return (0, (_sb(o["uid"]),))
    if c == 1:
        return (1, _ekey((o["uid"], o["type"], o["to"])))
    return (2, (_sb(o["scope_key"]),))


def _validate_op(o):
    k = o["op"]
    if k == CREATE:
        if o["uid"] == "" or o["kind"] == "":
            raise ProtocolError(INVALID_OP, "create requires uid and kind")
    elif k == UPDATE:
        if o["uid"] == "" or not o["fields"]:
            raise ProtocolError(INVALID_OP, "update requires uid and changes")
    elif k == DELETE:
        if o["uid"] == "" or o["reason"] not in (1, 2):
            raise ProtocolError(INVALID_OP, "delete requires uid and a valid reason")
    elif k in (EDGE_ADD, EDGE_REMOVE, EDGE_REPLACE):
        if o["uid"] == "" or o["type"] == "" or o["to"] == "":
            raise ProtocolError(INVALID_OP, "edge op requires from, type, to")
    elif k == SCOPE_SET:
        if o["scope_key"] == "" or o["scope"][0] > 2:
            raise ProtocolError(INVALID_OP, "scope-set requires a key and valid state")
    else:
        raise ProtocolError(INVALID_OP, "op kind %d" % k)


def validate_ops(ops, canonical):
    seen = set()
    for o in ops:
        _validate_op(o)
        c = _op_class(o)
        if c == 0:
            key = (0, o["uid"])
        elif c == 1:
            key = (1, o["uid"], o["type"], o["to"])
        else:
            key = (2, o["scope_key"])
        if key in seen:
            raise ProtocolError(INVALID_OP, "two ops for the same key")
        seen.add(key)
    if canonical:
        for i in range(1, len(ops)):
            if not op_sort_key(ops[i - 1]) < op_sort_key(ops[i]):
                raise ProtocolError(MALFORMED, "range ops not in canonical order")


def validate_finding(f):
    if f["id"] == "" or f["dedup_key"] == "":
        raise ProtocolError(MALFORMED, "finding requires id and dedup key")
    if not 1 <= f["transition"] <= 5:
        raise ProtocolError(MALFORMED, "transition")
    if not 1 <= f["severity"] <= 5:
        raise ProtocolError(MALFORMED, "severity")
    p = f["provenance"]
    if p["kind"] == 1:
        if p["rule_id"] == "" or p["bundle_version"] == "":
            raise ProtocolError(MALFORMED, "rule provenance requires rule id and bundle version")
    elif p["requester"] == "":
        raise ProtocolError(MALFORMED, "query provenance requires requester")
    rs = f["resources"]
    for i in range(1, len(rs)):
        if not _sb(rs[i - 1]) < _sb(rs[i]):
            raise ProtocolError(MALFORMED, "finding resources not sorted and unique")


def _validate_checkpoint(c, seq):
    if not 1 <= c["reason"] <= 5:
        raise ProtocolError(MALFORMED, "checkpoint reason")
    if c["interval"][0] > c["interval"][1]:
        raise ProtocolError(MALFORMED, "interval start after end")
    rs, es, caps = c["resources"], c["edges"], c["caps"]
    for i in range(1, len(rs)):
        if not _sb(rs[i - 1][0]) < _sb(rs[i][0]):
            raise ProtocolError(MALFORMED, "resources not sorted by uid")
    for i in range(1, len(es)):
        if not _ekey(es[i - 1]) < _ekey(es[i]):
            raise ProtocolError(MALFORMED, "edges not sorted")
    for i in range(1, len(caps)):
        if not _sb(caps[i - 1]) < _sb(caps[i]):
            raise ProtocolError(MALFORMED, "capabilities not sorted and unique")
    for r in rs:
        if r[0] == "" or r[1] == "":
            raise ProtocolError(MALFORMED, "resource requires uid and kind")
    for k, s in c["scopes"].items():
        if k == "" or s[0] > 2:
            raise ProtocolError(MALFORMED, "invalid scope")
    if (c["prev_epoch"] is not None or c["prev_head"] is not None) and seq != 1:
        raise ProtocolError(MALFORMED, "previous epoch only on the first checkpoint")
    if state_hash_of(rs, es, c["scopes"]) != c["state_hash"]:
        raise ProtocolError(INVALID_STATE_HASH, "content does not hash to the declared state hash")


def _validate_linked(r):
    if r.seq != r.parent + 1 or r.seq < 2:
        raise ProtocolError(INVALID_CHAIN, "seq must equal parent+1 and follow a checkpoint")
    if r.base < 1 or r.base > r.parent:
        raise ProtocolError(INVALID_CHAIN, "base outside [1, parent]")


def validate_range(g):
    validate_ops(g["ops"], True)
    a, b = g["span"]
    prev = 0
    for seq, f in g["findings"]:
        if seq < a or seq > b or seq <= prev:
            raise ProtocolError(MALFORMED, "range finding seq %d" % seq)
        prev = seq
        validate_finding(f)
    for s, e in g["uncertain"]:
        if s > e:
            raise ProtocolError(MALFORMED, "uncertainty interval")


def validate_record(r):
    if not valid_target_id(r.target_id):
        raise ProtocolError(MALFORMED, "invalid target_id")
    if r.incarnation < 1:
        raise ProtocolError(INVALID_CHAIN, "incarnation must be at least 1")
    if r.seq < 1:
        raise ProtocolError(INVALID_CHAIN, "seq must be at least 1")
    if r.type == CHECKPOINT:
        if r.seq != r.parent + 1 or r.base != r.seq:
            raise ProtocolError(INVALID_CHAIN, "checkpoint requires seq = parent+1 and base = seq")
        _validate_checkpoint(r.body, r.seq)
    elif r.type == DELTA:
        _validate_linked(r)
        d = r.body
        if not d["ops"]:
            raise ProtocolError(INVALID_OP, "delta without ops")
        if d["uncertain"] is not None and d["uncertain"][0] > d["uncertain"][1]:
            raise ProtocolError(MALFORMED, "uncertainty interval")
        validate_ops(d["ops"], False)
    elif r.type == FINDING:
        _validate_linked(r)
        validate_finding(r.body)
    elif r.type == RANGE:
        a, b = r.body["span"]
        if not (1 < a <= b) or r.seq != b or r.parent != a - 1:
            raise ProtocolError(INVALID_CHAIN, "range span inconsistent with seq and parent")
        if r.base < 1 or r.base > r.parent:
            raise ProtocolError(INVALID_CHAIN, "base outside [1, parent]")
        validate_range(r.body)
    else:
        raise ProtocolError(UNSUPPORTED_FIELD, "record type %d" % r.type)


# Encoding of bodies, mirroring the canonical layouts of SPEC 4.

def scope_map(s):
    m = {0: s[0]}
    if s[1] != "":
        m[1] = s[1]
    if s[2] != 0:
        m[2] = s[2]
    return m


def op_map(o):
    k = o["op"]
    m = {0: k}
    if k == CREATE:
        m.update({1: o["uid"], 2: o["kind"], 3: o["ns"], 4: o["name"], 5: o["fields"]})
    elif k == UPDATE:
        m.update({1: o["uid"], 5: o["fields"]})
    elif k == DELETE:
        m.update({1: o["uid"], 6: o["reason"]})
    elif k in (EDGE_ADD, EDGE_REMOVE):
        m.update({1: o["uid"], 7: o["type"], 8: o["to"], 9: o["attrs"]})
    elif k == EDGE_REPLACE:
        m.update({1: o["uid"], 7: o["type"], 8: o["to"], 9: o["attrs"], 10: o["prev"]})
    else:
        m.update({11: o["scope_key"], 12: scope_map(o["scope"])})
    return m


def finding_map(f):
    p = f["provenance"]
    if p["kind"] == 2:
        pm = {0: 2, 4: p["query_hash"], 5: p["requester"]}
    else:
        pm = {0: 1, 1: p["rule_id"], 2: p["rule_version"], 3: p["bundle_version"]}
    m = {0: f["id"], 1: f["dedup_key"], 2: f["transition"], 3: pm, 4: f["category"], 5: f["severity"],
         6: f["eval_time"], 7: f["first_seen"], 8: f["last_seen"], 9: f["count"], 10: f["resources"]}
    if f["facts"]:
        m[11] = f["facts"]
    if f["evidence"]:
        ev = []
        for e in f["evidence"]:
            em = {0: e["source"], 1: e["time"], 2: e["text"]}
            if e["count"]:
                em[3] = e["count"]
            if e["labels"]:
                em[4] = e["labels"]
            if e["truncated"]:
                em[5] = True
            if e["context"]:
                em[6] = True
            ev.append(em)
        m[12] = ev
    if f["flags"]:
        m[13] = f["flags"]
    if f["node"]:
        m[14] = f["node"]
    if f["labels"]:
        m[15] = f["labels"]
    if f["summary"]:
        m[16] = f["summary"]
    if f["suggestions"]:
        ss = []
        for s in f["suggestions"]:
            sm = {0: s["language"], 1: s["query"]}
            if s["source"]:
                sm[2] = s["source"]
            ss.append(sm)
        m[17] = ss
    if f["coverage"]:
        m[18] = f["coverage"]
    return m


def range_map(g):
    m = {0: [op_map(o) for o in g["ops"]], 1: list(g["span"]),
         2: [[seq, finding_map(f)] for seq, f in g["findings"]]}
    if g["flags"]:
        m[3] = g["flags"]
    if g["uncertain"]:
        m[4] = [list(iv) for iv in g["uncertain"]]
    return m


def envelope_map(rtype, target_id, epoch, seq, writer, incarnation, parent, base, time, schema, body):
    return {0: VERSION, 1: rtype, 2: target_id, 3: bytes(epoch), 4: seq, 5: bytes(writer), 6: incarnation,
            7: parent, 8: base, 9: time, 10: schema, 11: body}


def range_record(template, g, parent, base):
    """Encodes the range record for folded body g, copying identity, incarnation, time, and schema from template."""
    if parent != g["span"][0] - 1:
        raise ProtocolError(FOLD, "parent does not precede range start")
    b = encode(envelope_map(RANGE, template.target_id, template.epoch, g["span"][1], template.writer,
                            template.incarnation, parent, base, template.time, template.schema, range_map(g)))
    return decode_record(b)


# State (SPEC 6).

def state_hash_of(resources, edges, scopes):
    canon = [[list(r[:4]) + [r[4]] for r in resources], [list(e[:3]) + [e[3]] for e in edges],
             {k: scope_map(s) for k, s in scopes.items()}]
    return domain_hash("EMHPv1/state", encode(canon))


class State:
    def __init__(self):
        self.resources = {}
        self.edges = {}
        self.scopes = {}

    @classmethod
    def from_checkpoint(cls, c):
        s = cls()
        for uid, kind, ns, name, fields in c["resources"]:
            s.resources[uid] = [kind, ns, name, copy.deepcopy(fields)]
        for f, t, to, attrs in c["edges"]:
            s.edges[(f, t, to)] = copy.deepcopy(attrs)
        s.scopes = dict(c["scopes"])
        return s

    def clone(self):
        s = State()
        s.resources = copy.deepcopy(self.resources)
        s.edges = copy.deepcopy(self.edges)
        s.scopes = dict(self.scopes)
        return s

    def hash(self):
        res = [[uid] + self.resources[uid] for uid in sorted(self.resources, key=_sb)]
        edges = [list(k) + [self.edges[k]] for k in sorted(self.edges, key=_ekey)]
        return state_hash_of(res, edges, self.scopes)

    def _check(self, o):
        k = o["op"]
        if k == CREATE and o["uid"] in self.resources:
            raise ProtocolError(INVALID_OP, "create of existing uid " + o["uid"])
        if k in (UPDATE, DELETE) and o["uid"] not in self.resources:
            raise ProtocolError(INVALID_OP, "op on absent uid " + o["uid"])
        ek = (o.get("uid"), o.get("type"), o.get("to"))
        if k == EDGE_ADD and ek in self.edges:
            raise ProtocolError(INVALID_OP, "add of existing edge")
        if k in (EDGE_REMOVE, EDGE_REPLACE) and ek not in self.edges:
            raise ProtocolError(INVALID_OP, "remove or replace of absent edge")
        if k > SCOPE_SET or k < CREATE:
            raise ProtocolError(INVALID_OP, "op kind %d" % k)

    def _apply(self, o):
        k = o["op"]
        if k == CREATE:
            self.resources[o["uid"]] = [o["kind"], o["ns"], o["name"], copy.deepcopy(o["fields"])]
        elif k == UPDATE:
            fields = self.resources[o["uid"]][3]
            for f, v in o["fields"].items():
                if v is None:
                    fields.pop(f, None)
                else:
                    fields[f] = copy.deepcopy(v)
        elif k == DELETE:
            del self.resources[o["uid"]]
        elif k in (EDGE_ADD, EDGE_REPLACE):
            self.edges[(o["uid"], o["type"], o["to"])] = copy.deepcopy(o["attrs"])
        elif k == EDGE_REMOVE:
            del self.edges[(o["uid"], o["type"], o["to"])]
        else:
            self.scopes[o["scope_key"]] = o["scope"]

    def apply_ops(self, ops):
        for o in ops:
            self._check(o)
        for o in ops:
            self._apply(o)

    def apply_record(self, r):
        if r.type in (DELTA, RANGE):
            self.apply_ops(r.body["ops"])


# Fold (SPEC 5).

def _fold_op(o, res, edges, scopes):
    k = o["op"]
    if k in (CREATE, UPDATE, DELETE):
        f = res.get(o["uid"])
        if f is None:
            f = {"absent_before": False, "deleted": False, "reason": 0, "fields": {}}
            res[o["uid"]] = f
            if k == CREATE:
                f.update(absent_before=True, kind=o["kind"], ns=o["ns"], name=o["name"],
                         fields=copy.deepcopy(o["fields"]))
            elif k == UPDATE:
                f["fields"] = copy.deepcopy(o["fields"])
            else:
                f.update(deleted=True, reason=o["reason"])
            return
        if f["deleted"]:
            raise ProtocolError(FOLD, "op after delete of uid " + o["uid"])
        if k == CREATE:
            raise ProtocolError(FOLD, "create of existing uid " + o["uid"])
        if k == UPDATE:
            for name, v in o["fields"].items():
                if f["absent_before"] and v is None:
                    f["fields"].pop(name, None)
                else:
                    f["fields"][name] = copy.deepcopy(v)
        else:
            f.update(deleted=True, reason=o["reason"])
    elif k in (EDGE_ADD, EDGE_REMOVE, EDGE_REPLACE):
        key = (o["uid"], o["type"], o["to"])
        e = edges.get(key)
        if e is None:
            e = {"before": False, "now": False, "p": None, "q": None}
            edges[key] = e
            if k == EDGE_ADD:
                e.update(now=True, q=copy.deepcopy(o["attrs"]))
            elif k == EDGE_REMOVE:
                e.update(before=True, p=copy.deepcopy(o["attrs"]))
            else:
                e.update(before=True, p=copy.deepcopy(o["prev"]), now=True, q=copy.deepcopy(o["attrs"]))
            return
        if k == EDGE_ADD:
            if e["now"]:
                raise ProtocolError(FOLD, "add of existing edge")
            e.update(now=True, q=copy.deepcopy(o["attrs"]))
        elif k == EDGE_REMOVE:
            if not e["now"]:
                raise ProtocolError(FOLD, "remove of absent edge")
            e.update(now=False, q=None)
        else:
            if not e["now"]:
                raise ProtocolError(FOLD, "replace of absent edge")
            e["q"] = copy.deepcopy(o["attrs"])
    elif k == SCOPE_SET:
        scopes[o["scope_key"]] = o["scope"]
    else:
        raise ProtocolError(FOLD, "op kind %d" % k)


def fold(records):
    """Coalesces a contiguous run of delta, range, and finding records into a range body."""
    if not records:
        raise ProtocolError(FOLD, "empty run")
    first = records[0]
    a = first.body["span"][0] if first.type == RANGE else first.seq
    g = {"ops": [], "span": (a, records[-1].seq), "findings": [], "flags": 0, "uncertain": []}
    res, edges, scopes = {}, {}, {}
    for i, r in enumerate(records):
        if i > 0 and r.parent != records[i - 1].seq:
            raise ProtocolError(FOLD, "record %d does not follow %d" % (r.seq, records[i - 1].seq))
        if r.type == DELTA:
            ops = r.body["ops"]
            g["flags"] |= r.body["flags"]
            if r.body["uncertain"] is not None:
                g["uncertain"].append(r.body["uncertain"])
        elif r.type == RANGE:
            ops = r.body["ops"]
            g["flags"] |= r.body["flags"]
            g["uncertain"].extend(r.body["uncertain"])
            g["findings"].extend((s, copy.deepcopy(f)) for s, f in r.body["findings"])
        elif r.type == FINDING:
            ops = []
            g["findings"].append((r.seq, copy.deepcopy(r.body)))
        else:
            raise ProtocolError(FOLD, "%s record %d cannot be coalesced" % (TYPE_NAMES.get(r.type), r.seq))
        for o in ops:
            _fold_op(o, res, edges, scopes)
    for uid, f in res.items():
        if f["absent_before"] and f["deleted"]:
            continue
        if f["absent_before"]:
            g["ops"].append({"op": CREATE, "uid": uid, "kind": f["kind"], "ns": f["ns"], "name": f["name"],
                             "fields": f["fields"]})
        elif f["deleted"]:
            g["ops"].append({"op": DELETE, "uid": uid, "reason": f["reason"]})
        else:
            g["ops"].append({"op": UPDATE, "uid": uid, "fields": f["fields"]})
    for (fr, t, to), e in edges.items():
        base = {"uid": fr, "type": t, "to": to}
        if not e["before"] and not e["now"]:
            continue
        if not e["before"]:
            g["ops"].append(dict(base, op=EDGE_ADD, attrs=e["q"]))
        elif not e["now"]:
            g["ops"].append(dict(base, op=EDGE_REMOVE, attrs=e["p"]))
        elif encode(e["p"]) != encode(e["q"]):
            g["ops"].append(dict(base, op=EDGE_REPLACE, attrs=e["q"], prev=e["p"]))
    for key, st in scopes.items():
        g["ops"].append({"op": SCOPE_SET, "scope_key": key, "scope": st})
    g["ops"].sort(key=op_sort_key)
    validate_range(g)
    return g


# Reconstruction (SPEC 6.3).

class Replayer:
    def __init__(self, target_id, epoch, writer):
        self.target_id, self.epoch, self.writer = target_id, bytes(epoch), bytes(writer)
        self.head = 0
        self.head_hash = genesis(target_id, epoch, writer)
        self.last_checkpoint = 0
        self.state = State()
        self.states = {}
        self.chain_hashes = {}
        self.boundaries = []
        self.unavailable = []

    def check(self, r):
        if r.target_id != self.target_id or r.epoch != self.epoch:
            raise ProtocolError(INVALID_CHAIN, "record outside chain")
        if r.writer != self.writer:
            raise ProtocolError(INVALID_CHAIN, "record from a writer other than the epoch owner")
        if r.parent != self.head:
            raise ProtocolError(INVALID_CHAIN, "parent %d, head is %d" % (r.parent, self.head))
        if self.head == 0 and r.type != CHECKPOINT:
            raise ProtocolError(INVALID_CHAIN, "epoch must start with a checkpoint")
        if r.type != CHECKPOINT and r.base != self.last_checkpoint:
            raise ProtocolError(INVALID_CHAIN, "base %d, governing checkpoint is %d" % (r.base, self.last_checkpoint))
        return chain_hash(self.head_hash, r.hash)

    def apply(self, r):
        h = self.check(r)
        if r.type == CHECKPOINT:
            if self.head != 0:
                got = self.state.hash()
                if got != r.body["state_hash"]:
                    self.boundaries.append((r.seq, r.body["state_hash"], got))
            self.state = State.from_checkpoint(r.body)
        elif r.type in (DELTA, RANGE):
            nxt = self.state.clone()
            nxt.apply_record(r)
            self.state = nxt
            a, b = r.body["span"] if r.type == RANGE else (0, 0)
            if r.type == RANGE and a < b:
                self.unavailable.append((a, b - 1))
        self.head, self.head_hash = r.seq, h
        if r.type == CHECKPOINT:
            self.last_checkpoint = r.seq
        self.states[r.seq] = self.state.hash()
        self.chain_hashes[r.seq] = h
        return h

    def state_hash_at(self, seq):
        for a, b in self.unavailable:
            if a <= seq <= b:
                raise ProtocolError(UNAVAILABLE, "sequence %d is inside a coalesced range" % seq)
        if seq not in self.states:
            raise KeyError(seq)
        return self.states[seq]


def reconstruct(records, seq):
    """Returns the state at seq of an epoch given its records in chain order."""
    if not records:
        raise ProtocolError(INVALID_CHAIN, "no records")
    first = records[0]
    p = Replayer(first.target_id, first.epoch, first.writer)
    for r in records:
        if r.type == RANGE and r.body["span"][0] <= seq < r.body["span"][1]:
            raise ProtocolError(UNAVAILABLE, "sequence %d is inside a range" % seq)
        if r.seq > seq:
            break
        p.apply(r)
        if r.seq == seq:
            return p.state.clone()
    raise KeyError(seq)


# Ownership decision table (SPEC 8.3).

def _reject(row, code, **extra):
    d = {"row": row, "accept": False, "code": code, "outcome": "", "open_epoch": False, "close_epoch": None,
         "retire_writer": None, "supersede": False, "set_conflict": False, "clear_binding": False,
         "audit": True, "alarm": False}
    d.update(extra)
    return d


def _accept(row, outcome, **extra):
    d = _reject(row, "", accept=True, outcome=outcome, audit=False)
    d.update(extra)
    return d


def decide(state, hello, credential_valid):
    """Evaluates the ownership decision table. state and hello use the ownership.json vector layout."""
    if not credential_valid or state["revoked"]:
        return _reject(1, "unauthorized")
    if state["conflict"]:
        return _reject(2, "identity_conflict")
    host = state["target_type"] == "host"
    if host and state["enrolled_machine_id"] != "" and hello["machine_id"] != state["enrolled_machine_id"]:
        return _reject(3, "identity_conflict", set_conflict=True, alarm=True)
    w, inc, e = hello["writer_id"], hello["incarnation"], hello["epoch"]
    if w in state["retired"]:
        return _reject(4, "writer_retired")
    epochs = {x["id"]: x for x in state["epochs"]}
    ep = epochs.get(e)
    if ep is not None and not ep["open"]:
        return _reject(5, "epoch_closed")
    if ep is not None and ep["owner"] != w:
        return _reject(6, "not_owner")
    hi = state["highest_incarnation"].get(w)
    if hi is not None and inc < hi:
        return _reject(7, "stale_incarnation")
    active = state["active"]
    reconnect = False
    if active is not None and active["writer_id"] == w and active["incarnation"] == inc:
        instance = hello.get("instance")
        if not instance or instance != active.get("instance"):
            return _reject(8, "identity_conflict", alarm=True)
        reconnect = True
    supersede = reconnect or (active is not None and active["writer_id"] == w and active["incarnation"] < inc)
    if ep is not None:
        lc = hello["last_committed"]
        if lc is not None:
            if lc["seq"] > ep["head"]["seq"]:
                return _reject(9, "divergence")
            if ep["chain_hashes"].get(lc["seq"]) != lc["chain_hash"]:
                return _reject(9, "divergence")
        return _accept(10, "resume", supersede=supersede)
    if state["open_epoch"] is None:
        if not state["epochs"]:
            return _accept(11, "opened", open_epoch=True, supersede=supersede)
        return _reject(16, "invalid_hello")
    cur = state["open_epoch"]
    owner = epochs[cur]["owner"]
    if owner == w:
        eo = hello["epoch_open"]
        if eo is not None and eo["reason"] == "rebaseline" and eo.get("prev_epoch") == cur:
            return _accept(12, "opened", open_epoch=True, close_epoch=cur, supersede=supersede, audit=True)
        return _reject(16, "invalid_hello")
    if not host:
        return _accept(13, "opened", open_epoch=True, close_epoch=cur, retire_writer=owner,
                       supersede=active is not None, audit=True)
    if state["pending_binding"]:
        return _accept(14, "opened", open_epoch=True, close_epoch=cur, retire_writer=owner, clear_binding=True,
                       supersede=active is not None, audit=True)
    return _reject(15, "identity_conflict", set_conflict=True, alarm=True)
