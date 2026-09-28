"""Unit tests for the reference oracle plus a runner over every file in protocol/vectors."""

import json
import math
import os
import random
import struct
import unittest

import emhp
from emhp import ProtocolError

VECTORS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "vectors")


def load(name):
    with open(os.path.join(VECTORS, name), encoding="utf-8") as f:
        return json.load(f)


def expand(h, pad):
    b = bytes.fromhex(h)
    if pad:
        b += bytes.fromhex(pad["byte"]) * (pad["length"] - len(b))
    return b


def typed(t, key=False):
    (kind, v), = t.items()
    if kind == "uint":
        return int(v)
    if kind == "nint":
        return emhp.Key("nint", int(v)) if key else int(v)
    if kind == "float":
        f = struct.unpack(">d", bytes.fromhex(v))[0]
        return emhp.Key("float", f) if key else f
    if kind == "text":
        return v
    if kind == "bytes":
        return emhp.Key("bytes", bytes.fromhex(v)) if key else bytes.fromhex(v)
    if kind == "bool":
        return emhp.Key("simple", v) if key else v
    if kind == "null":
        return emhp.Key("simple", None) if key else None
    if kind == "array":
        return [typed(e) for e in v]
    if kind == "map":
        return {typed(k, True): typed(e) for k, e in v}
    raise ValueError(kind)


def code_of(fn, *args):
    try:
        fn(*args)
    except ProtocolError as e:
        return e.code
    return None


def env(seq, body, rtype=emhp.DELTA, parent=None, base=1):
    return emhp.envelope_map(rtype, "t-unit", b"\x01" * 16, seq, b"\x02" * 16, 1,
                             seq - 1 if parent is None else parent, base, 1000 + seq, 1, body)


def checkpoint_bytes(state=None, seq=1, parent=0):
    st = state or emhp.State()
    res = [[uid] + st.resources[uid] for uid in sorted(st.resources)]
    edges = [list(k) + [st.edges[k]] for k in sorted(st.edges)]
    body = {0: 1, 1: [0, 0], 2: res, 3: edges, 4: {k: emhp.scope_map(s) for k, s in st.scopes.items()}, 5: [],
            6: st.hash()}
    return emhp.encode(env(seq, body, emhp.CHECKPOINT, parent, seq))


class CBORTest(unittest.TestCase):
    def test_integers(self):
        cases = {0: "00", 23: "17", 24: "1818", 255: "18ff", 256: "190100", 65536: "1a00010000",
                 (1 << 64) - 1: "1bffffffffffffffff", -1: "20", -25: "3818", -(1 << 64): "3bffffffffffffffff"}
        for v, h in cases.items():
            self.assertEqual(emhp.encode(v).hex(), h)
            self.assertEqual(emhp.decode_strict(bytes.fromhex(h)), v)
        self.assertEqual(code_of(emhp.encode, 1 << 64), emhp.INVALID_VALUE)

    def test_floats_shortest(self):
        cases = {1.5: "f93e00", -0.0: "f98000", 65504.0: "f97bff", 65520.0: "fa477ff000", 0.1: "fb3fb999999999999a",
                 math.ldexp(1, -24): "f90001", math.ldexp(1, -25): "fa33000000", math.ldexp(1, -150): "fb3690000000000000"}
        for v, h in cases.items():
            self.assertEqual(emhp.encode(v).hex(), h)
        self.assertEqual(code_of(emhp.encode, float("nan")), emhp.INVALID_VALUE)
        self.assertEqual(code_of(emhp.encode, float("inf")), emhp.INVALID_VALUE)

    def test_map_key_order(self):
        self.assertEqual(emhp.encode({"b": 1, "aa": 2}).hex(), "a2616201626161" + "02")
        self.assertEqual(emhp.encode({10: 0, 1000: 0, 1: 0}).hex(), "a301000a001903e800")

    def test_bool_is_not_int(self):
        self.assertEqual(emhp.encode([True, 1, False, 0]).hex(), "84f501f400")

    def test_strict_rejections(self):
        bad = ["", "00ff", "1801", "5f40ff", "c100", "f97e00", "f97c00", "f7", "f0", "f820", "f814", "1c",
               "a20001" + "0001", "a20101" + "0001", "a2f90000" + "01" + "f98000" + "02", "a18001", "62c328",
               "63eda080", "fa3fc00000", "ff"]
        for h in bad:
            self.assertEqual(code_of(emhp.decode_strict, bytes.fromhex(h)), emhp.MALFORMED, h)
        self.assertEqual(code_of(emhp.decode_strict, b"\x40" * (emhp.MAX_RECORD_BYTES + 1)), emhp.TOO_LARGE)

    def test_depth_limit(self):
        self.assertIsInstance(emhp.decode_strict(b"\x81" * 32 + b"\x00"), list)
        self.assertEqual(code_of(emhp.decode_strict, b"\x81" * 33 + b"\x00"), emhp.MALFORMED)

    def test_mixed_keys_round_trip(self):
        b = emhp.encode({emhp.Key("bytes", b"a"): 1, "b": 2, 1: 3, emhp.Key("nint", -1): 4, emhp.Key("simple", None): 5})
        self.assertEqual(emhp.encode(emhp.decode_strict(b)), b)


class RecordTest(unittest.TestCase):
    def test_round_trip_and_state(self):
        ck = emhp.decode_record(checkpoint_bytes())
        ops = [{0: 1, 1: "u1", 2: "Pod", 3: "ns", 4: "p", 5: {"a": 1, "f": 1.5}},
               {0: 4, 1: "u1", 7: "owns", 8: "u2", 9: {}},
               {0: 7, 11: "Pod", 12: {0: 1, 1: "forbidden"}}]
        d = emhp.decode_record(emhp.encode(env(2, {0: ops, 1: 1})))
        self.assertEqual(d.body["flags"], 1)
        st = emhp.State.from_checkpoint(ck.body)
        st.apply_ops(d.body["ops"])
        self.assertEqual(st.resources["u1"][3], {"a": 1, "f": 1.5})
        again = emhp.decode_record(checkpoint_bytes(st, 3, 2))
        self.assertEqual(again.body["state_hash"], st.hash())

    def test_rejections(self):
        op = {0: 1, 1: "u1", 2: "Pod", 3: "", 4: "p", 5: {}}
        self.assertEqual(code_of(emhp.decode_record, emhp.encode({**env(2, {0: [op]}), 12: 1})), emhp.UNSUPPORTED_FIELD)
        self.assertEqual(code_of(emhp.decode_record, emhp.encode(env(2, {0: [{**op, 5: {"x": None}}]}))), emhp.INVALID_VALUE)
        self.assertEqual(code_of(emhp.decode_record, emhp.encode(env(2, {0: [op, op]}))), emhp.INVALID_OP)
        self.assertEqual(code_of(emhp.decode_record, emhp.encode(env(2, {0: [op], 1: 0}))), emhp.MALFORMED)
        self.assertEqual(code_of(emhp.decode_record, emhp.encode(env(2, {0: [op]}, parent=0))), emhp.INVALID_CHAIN)
        ok = emhp.decode_record(emhp.encode({**env(2, {0: [op], 1000: "x"}), 1000: [None]}))
        self.assertEqual(ok.ext, {1000: [None]})

    def test_hash_domains(self):
        self.assertEqual(emhp.State().hash(), emhp.domain_hash("EMHPv1/state", bytes.fromhex("8380" + "80" + "a0")))
        self.assertEqual(len(emhp.finding_id("t", "k", 1)), 32)
        g = emhp.genesis("t", b"\x00" * 16, b"\x01" * 16)
        self.assertEqual(emhp.chain_hash(g, b"\x00" * 32), emhp.domain_hash("EMHPv1/chain", g, b"\x00" * 32))


class FoldPropertyTest(unittest.TestCase):
    def test_random_runs(self):
        rng = random.Random(7)
        for _ in range(40):
            st = emhp.State()
            recs = [emhp.decode_record(checkpoint_bytes())]
            states = [st.clone()]
            nxt = 0
            for seq in range(2, 2 + rng.randint(1, 12)):
                ops, used = [], set()
                for _ in range(rng.randint(1, 3)):
                    live = sorted(u for u in st.resources if u not in used)
                    if live and rng.random() < 0.6:
                        uid = rng.choice(live)
                        if rng.random() < 0.25:
                            ops.append({0: 3, 1: uid, 6: rng.choice([1, 2])})
                        else:
                            ops.append({0: 2, 1: uid, 5: {rng.choice("abc"): rng.choice([None, 1, "x", 2.5])}})
                    else:
                        uid = "u%d" % nxt
                        nxt += 1
                        ops.append({0: 1, 1: uid, 2: "Pod", 3: "", 4: uid, 5: {"a": rng.randint(0, 9)}})
                    used.add(uid)
                r = emhp.decode_record(emhp.encode(env(seq, {0: ops})))
                st.apply_record(r)
                recs.append(r)
                states.append(st.clone())
            a = rng.randint(2, len(recs))
            b = rng.randint(a, len(recs))
            g = emhp.fold(recs[a - 1:b])
            base = states[a - 2].clone()
            base.apply_ops(g["ops"])
            self.assertEqual(base.hash(), states[b - 1].hash())
            rr = emhp.range_record(recs[b - 1], g, a - 1, 1)
            self.assertEqual(emhp.decode_record(rr.raw).body["span"], (a, b))


class VectorTest(unittest.TestCase):
    def test_encoding(self):
        v = load("encoding.json")
        for c in v["values"]:
            with self.subTest(c["name"]):
                self.assertEqual(emhp.encode(typed(c["value"])).hex(), c["hex"])
                self.assertEqual(emhp.encode(emhp.decode_strict(bytes.fromhex(c["hex"]))).hex(), c["hex"])
        for c in v["records"]:
            with self.subTest(c["name"]):
                r = emhp.decode_record(expand(c["hex"], c.get("pad")))
                self.assertEqual(emhp.TYPE_NAMES[r.type], c["type"])
                self.assertEqual(r.seq, c["seq"])
                self.assertEqual(r.hash.hex(), c["record_hash"])
        for c in v["chains"]:
            with self.subTest(c["name"]):
                prev = emhp.genesis(c["target_id"], bytes.fromhex(c["epoch"]), bytes.fromhex(c["writer_id"]))
                self.assertEqual(prev.hex(), c["genesis"])
                p = emhp.Replayer(c["target_id"], bytes.fromhex(c["epoch"]), bytes.fromhex(c["writer_id"]))
                for rc in c["records"]:
                    r = emhp.decode_record(bytes.fromhex(rc["hex"]))
                    self.assertEqual((emhp.TYPE_NAMES[r.type], r.seq, r.hash.hex()), (rc["type"], rc["seq"], rc["record_hash"]))
                    self.assertEqual(p.apply(r).hex(), rc["chain_hash"])

    def test_rejection(self):
        for c in load("rejection.json")["vectors"]:
            with self.subTest(c["name"]):
                self.assertEqual(code_of(emhp.decode_record, expand(c["hex"], c.get("pad"))), c["error"])

    def test_fold(self):
        for c in load("fold.json")["vectors"]:
            with self.subTest(c["name"]):
                run = [emhp.decode_record(bytes.fromhex(h)) for h in c["run"]]
                if c.get("error"):
                    self.assertEqual(code_of(emhp.fold, run), c["error"])
                    continue
                e = c["expect"]
                prefix = [emhp.decode_record(bytes.fromhex(h)) for h in c["prefix"]]
                p = emhp.Replayer(prefix[0].target_id, prefix[0].epoch, prefix[0].writer)
                for r in prefix:
                    p.apply(r)
                self.assertEqual(p.state.hash().hex(), e["state_before"])
                head_hash, before = p.head_hash, p.state.clone()
                g = emhp.fold(run)
                self.assertEqual(list(g["span"]), e["span"])
                self.assertEqual(emhp.encode(emhp.range_map(g)).hex(), e["range_body"])
                self.assertEqual(len(g["ops"]), e["ops"])
                self.assertEqual([s for s, _ in g["findings"]], e["finding_seqs"])
                self.assertEqual(g["flags"], e["flags"])
                self.assertEqual([list(iv) for iv in g["uncertain"]], e["uncertain"])
                before.apply_ops(g["ops"])
                self.assertEqual(before.hash().hex(), e["state_after"])
                for r in run:
                    p.apply(r)
                self.assertEqual(p.state.hash().hex(), e["state_after"])
                last = run[-1]
                rr = emhp.range_record(last, g, run[0].parent, last.base)
                self.assertEqual(rr.raw.hex(), e["range_record"])
                self.assertEqual(emhp.chain_hash(head_hash, rr.hash).hex(), e["range_chain_hash"])

    def test_reconstruction(self):
        for c in load("reconstruction.json")["vectors"]:
            with self.subTest(c["name"]):
                p, recs, err = None, [], None
                for i, h in enumerate(c["records"]):
                    try:
                        r = emhp.decode_record(bytes.fromhex(h))
                        if p is None:
                            p = emhp.Replayer(r.target_id, r.epoch, r.writer)
                        p.apply(r)
                        recs.append(r)
                    except ProtocolError as e:
                        err = {"index": i, "code": e.code}
                        break
                self.assertEqual(err, c["error"])
                states = []
                if p is not None:
                    for seq in range(1, p.head + 1):
                        try:
                            states.append({"seq": seq, "state_hash": p.state_hash_at(seq).hex()})
                        except ProtocolError as e:
                            self.assertEqual(e.code, emhp.UNAVAILABLE)
                            states.append({"seq": seq, "state_hash": "unavailable"})
                self.assertEqual(states, c["states"])
                self.assertEqual([{"seq": s, "chain_hash": h.hex()} for s, h in sorted((p.chain_hashes if p else {}).items())],
                                 c["chain_hashes"])
                self.assertEqual([{"seq": s, "expected": x.hex(), "got": g.hex()} for s, x, g in (p.boundaries if p else [])],
                                 c["boundaries"])
                self.assertEqual([list(s) for s in (p.unavailable if p else [])], c["unavailable"])
                for st in c["states"]:
                    if st["state_hash"] == "unavailable":
                        self.assertEqual(code_of(emhp.reconstruct, recs, st["seq"]), emhp.UNAVAILABLE)
                    else:
                        self.assertEqual(emhp.reconstruct(recs, st["seq"]).hash().hex(), st["state_hash"])

    def test_ids(self):
        v = load("ids.json")
        for c in v["finding_ids"]:
            self.assertEqual(emhp.finding_id(c["target_id"], c["dedup_key"], c["first_seen"]), c["finding_id"])
        for c in v["query_hashes"]:
            self.assertEqual(emhp.query_hash(c["language"], c["query"], c["source"]).hex(), c["query_hash"])
        for c in v["genesis"]:
            g = emhp.genesis(c["target_id"], bytes.fromhex(c["epoch"]), bytes.fromhex(c["writer_id"]))
            self.assertEqual(g.hex(), c["genesis"])
        for c in v["record_hashes"]:
            self.assertEqual(emhp.record_hash(bytes.fromhex(c["hex"])).hex(), c["record_hash"])
        for c in v["chain_links"]:
            self.assertEqual(emhp.chain_hash(bytes.fromhex(c["prev"]), bytes.fromhex(c["record_hash"])).hex(), c["chain_hash"])
        for c in v["state_hashes"]:
            self.assertEqual(c["name"], "empty")
            self.assertEqual(emhp.State().hash().hex(), c["state_hash"])

    def test_ownership(self):
        for c in load("ownership.json")["vectors"]:
            with self.subTest(c["name"]):
                s = dict(c["state"])
                s["epochs"] = [dict(e, chain_hashes={p["seq"]: p["chain_hash"] for p in e["chain_hashes"]}) for e in s["epochs"]]
                s["retired"] = set(s["retired"])
                s["highest_incarnation"] = {h["writer_id"]: h["incarnation"] for h in s["highest_incarnation"]}
                self.assertEqual(emhp.decide(s, c["hello"], c["credential_valid"]), c["expect"])


if __name__ == "__main__":
    unittest.main()
