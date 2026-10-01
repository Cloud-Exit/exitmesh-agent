package protocol

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

func loadVectors(t *testing.T, name string, v any) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "protocol", "vectors", name))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
}

type vecPad struct {
	Byte   string `json:"byte"`
	Length int    `json:"length"`
}

func vecBytes(t *testing.T, h string, p *vecPad) []byte {
	t.Helper()
	b, err := hex.DecodeString(h)
	if err != nil {
		t.Fatal(err)
	}
	if p != nil {
		fill, err := hex.DecodeString(p.Byte)
		if err != nil {
			t.Fatal(err)
		}
		b = append(b, bytes.Repeat(fill, p.Length-len(b))...)
	}
	return b
}

func vecRecord(t *testing.T, h string) *Record {
	t.Helper()
	r, err := Decode(vecBytes(t, h, nil))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	return r
}

func vecRecords(t *testing.T, hs []string) []*Record {
	t.Helper()
	out := make([]*Record, len(hs))
	for i, h := range hs {
		out[i] = vecRecord(t, h)
	}
	return out
}

func typedValue(t *testing.T, raw json.RawMessage, key bool) any {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil || len(m) != 1 {
		t.Fatalf("typed value %s", raw)
	}
	str := func(r json.RawMessage) string {
		var s string
		if err := json.Unmarshal(r, &s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	for k, v := range m {
		switch k {
		case "uint":
			u, err := strconv.ParseUint(str(v), 10, 64)
			if err != nil {
				t.Fatal(err)
			}
			return u
		case "nint":
			n, ok := new(big.Int).SetString(str(v), 10)
			if !ok {
				t.Fatal("bad nint")
			}
			if n.IsInt64() {
				return n.Int64()
			}
			return *n
		case "float":
			bits, err := strconv.ParseUint(str(v), 16, 64)
			if err != nil {
				t.Fatal(err)
			}
			return math.Float64frombits(bits)
		case "text":
			return str(v)
		case "bytes":
			b, err := hex.DecodeString(str(v))
			if err != nil {
				t.Fatal(err)
			}
			if key {
				return cbor.ByteString(b)
			}
			return b
		case "bool":
			return string(v) == "true"
		case "null":
			return nil
		case "array":
			var items []json.RawMessage
			if err := json.Unmarshal(v, &items); err != nil {
				t.Fatal(err)
			}
			out := make([]any, len(items))
			for i, e := range items {
				out[i] = typedValue(t, e, false)
			}
			return out
		case "map":
			var pairs [][2]json.RawMessage
			if err := json.Unmarshal(v, &pairs); err != nil {
				t.Fatal(err)
			}
			out := map[any]any{}
			for _, pr := range pairs {
				out[typedValue(t, pr[0], true)] = typedValue(t, pr[1], false)
			}
			return out
		}
	}
	t.Fatalf("unknown typed value %s", raw)
	return nil
}

func TestVectorsEncoding(t *testing.T) {
	var f struct {
		Values []struct {
			Name  string          `json:"name"`
			Value json.RawMessage `json:"value"`
			Hex   string          `json:"hex"`
		} `json:"values"`
		Records []struct {
			Name       string  `json:"name"`
			Hex        string  `json:"hex"`
			Pad        *vecPad `json:"pad"`
			Type       string  `json:"type"`
			Seq        uint64  `json:"seq"`
			RecordHash string  `json:"record_hash"`
		} `json:"records"`
		Chains []struct {
			Name     string `json:"name"`
			TargetID string `json:"target_id"`
			Epoch    string `json:"epoch"`
			WriterID string `json:"writer_id"`
			Genesis  string `json:"genesis"`
			Records  []struct {
				Hex        string `json:"hex"`
				Type       string `json:"type"`
				Seq        uint64 `json:"seq"`
				RecordHash string `json:"record_hash"`
				ChainHash  string `json:"chain_hash"`
			} `json:"records"`
		} `json:"chains"`
	}
	loadVectors(t, "encoding.json", &f)
	for _, v := range f.Values {
		b, err := Marshal(typedValue(t, v.Value, false))
		if err != nil || hex.EncodeToString(b) != v.Hex {
			t.Errorf("value %s: encoded %x (%v), want %s", v.Name, b, err, v.Hex)
		}
		d, err := decodeStrict(vecBytes(t, v.Hex, nil))
		if err != nil {
			t.Errorf("value %s: decode: %v", v.Name, err)
			continue
		}
		if re, _ := Marshal(d); hex.EncodeToString(re) != v.Hex {
			t.Errorf("value %s: re-encoded %x", v.Name, re)
		}
	}
	for _, v := range f.Records {
		r, err := Decode(vecBytes(t, v.Hex, v.Pad))
		if err != nil {
			t.Errorf("record %s: %v", v.Name, err)
			continue
		}
		if r.Type.String() != v.Type || r.Seq != v.Seq || r.Hash().String() != v.RecordHash {
			t.Errorf("record %s: got %s seq %d hash %s", v.Name, r.Type, r.Seq, r.Hash())
		}
	}
	for _, c := range f.Chains {
		ep, _ := ParseID(c.Epoch)
		w, _ := ParseID(c.WriterID)
		ch := NewChain(c.TargetID, ep, w)
		if ch.HeadHash.String() != c.Genesis {
			t.Errorf("chain %s: genesis %s", c.Name, ch.HeadHash)
		}
		for _, rv := range c.Records {
			r := vecRecord(t, rv.Hex)
			h, err := ch.Append(r)
			if err != nil || h.String() != rv.ChainHash || r.Hash().String() != rv.RecordHash || r.Type.String() != rv.Type || r.Seq != rv.Seq {
				t.Errorf("chain %s seq %d: chain hash %s (%v)", c.Name, rv.Seq, h, err)
			}
		}
	}
}

func TestVectorsRejection(t *testing.T) {
	var f struct {
		Vectors []struct {
			Name  string  `json:"name"`
			Hex   string  `json:"hex"`
			Pad   *vecPad `json:"pad"`
			Error string  `json:"error"`
		} `json:"vectors"`
	}
	loadVectors(t, "rejection.json", &f)
	if len(f.Vectors) == 0 {
		t.Fatal("no rejection vectors")
	}
	for _, v := range f.Vectors {
		_, err := Decode(vecBytes(t, v.Hex, v.Pad))
		if CodeOf(err) != v.Error {
			t.Errorf("%s: got %v, want %s", v.Name, err, v.Error)
		}
	}
}

func TestVectorsFold(t *testing.T) {
	var f struct {
		Vectors []struct {
			Name   string   `json:"name"`
			Prefix []string `json:"prefix"`
			Run    []string `json:"run"`
			Error  string   `json:"error"`
			Expect *struct {
				Span           [2]uint64   `json:"span"`
				RangeBody      string      `json:"range_body"`
				Ops            int         `json:"ops"`
				FindingSeqs    []uint64    `json:"finding_seqs"`
				Flags          uint64      `json:"flags"`
				Uncertain      [][2]uint64 `json:"uncertain"`
				StateBefore    string      `json:"state_before"`
				StateAfter     string      `json:"state_after"`
				RangeRecord    string      `json:"range_record"`
				RangeChainHash string      `json:"range_chain_hash"`
			} `json:"expect"`
		} `json:"vectors"`
	}
	loadVectors(t, "fold.json", &f)
	for _, v := range f.Vectors {
		run := vecRecords(t, v.Run)
		if v.Error != "" {
			if _, err := Fold(run); CodeOf(err) != v.Error {
				t.Errorf("%s: got %v, want %s", v.Name, err, v.Error)
			}
			continue
		}
		e := v.Expect
		prefix := vecRecords(t, v.Prefix)
		p := NewReplayer(prefix[0].TargetID, prefix[0].Epoch, prefix[0].Writer)
		for _, r := range prefix {
			if _, err := p.Apply(r); err != nil {
				t.Fatalf("%s: prefix: %v", v.Name, err)
			}
		}
		if p.State().Hash().String() != e.StateBefore {
			t.Errorf("%s: state before %s", v.Name, p.State().Hash())
		}
		head := p.Chain().HeadHash
		g, err := Fold(run)
		if err != nil {
			t.Errorf("%s: fold: %v", v.Name, err)
			continue
		}
		body, _ := Marshal(g.encode())
		if g.From != e.Span[0] || g.To != e.Span[1] || hex.EncodeToString(body) != e.RangeBody || len(g.Ops) != e.Ops || g.Flags != e.Flags {
			t.Errorf("%s: folded body %x span [%d,%d]", v.Name, body, g.From, g.To)
		}
		seqs := []uint64{}
		for _, fd := range g.Findings {
			seqs = append(seqs, fd.Seq)
		}
		unc := [][2]uint64{}
		for _, iv := range g.Uncertain {
			unc = append(unc, [2]uint64{iv.Start, iv.End})
		}
		if gs, _ := json.Marshal([]any{seqs, unc}); string(gs) != mustJSON(t, []any{e.FindingSeqs, e.Uncertain}) {
			t.Errorf("%s: findings and intervals %s", v.Name, gs)
		}
		st := p.State().Clone()
		if err := st.ApplyOps(g.Ops); err != nil || st.Hash().String() != e.StateAfter {
			t.Errorf("%s: folded ops give %s (%v)", v.Name, st.Hash(), err)
		}
		for _, r := range run {
			if _, err := p.Apply(r); err != nil {
				t.Fatalf("%s: run: %v", v.Name, err)
			}
		}
		if p.State().Hash().String() != e.StateAfter {
			t.Errorf("%s: state after %s", v.Name, p.State().Hash())
		}
		last := run[len(run)-1]
		rr, err := NewRangeRecord(last.Envelope, g, run[0].Parent, last.Base)
		if err != nil || hex.EncodeToString(rr.Bytes()) != e.RangeRecord || ChainHash(head, rr.Hash()).String() != e.RangeChainHash {
			t.Errorf("%s: range record %x (%v)", v.Name, rr.Bytes(), err)
		}
	}
}

func mustJSON(t *testing.T, v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestVectorsReconstruction(t *testing.T) {
	var f struct {
		Vectors []struct {
			Name    string   `json:"name"`
			Records []string `json:"records"`
			States  []struct {
				Seq       uint64 `json:"seq"`
				StateHash string `json:"state_hash"`
			} `json:"states"`
			ChainHashes []struct {
				Seq       uint64 `json:"seq"`
				ChainHash string `json:"chain_hash"`
			} `json:"chain_hashes"`
			Boundaries []struct {
				Seq      uint64 `json:"seq"`
				Expected string `json:"expected"`
				Got      string `json:"got"`
			} `json:"boundaries"`
			Unavailable [][2]uint64 `json:"unavailable"`
			Error       *struct {
				Index int    `json:"index"`
				Code  string `json:"code"`
			} `json:"error"`
		} `json:"vectors"`
	}
	loadVectors(t, "reconstruction.json", &f)
	for _, v := range f.Vectors {
		var p *Replayer
		var recs []*Record
		errIndex, errCode := -1, ""
		chainHashes := map[uint64]Hash{}
		for i, h := range v.Records {
			r, err := Decode(vecBytes(t, h, nil))
			if err == nil {
				if p == nil {
					p = NewReplayer(r.TargetID, r.Epoch, r.Writer)
				}
				var ch Hash
				if ch, err = p.Apply(r); err == nil {
					chainHashes[r.Seq] = ch
					recs = append(recs, r)
				}
			}
			if err != nil {
				errIndex, errCode = i, CodeOf(err)
				break
			}
		}
		if (v.Error == nil) != (errIndex < 0) || (v.Error != nil && (v.Error.Index != errIndex || v.Error.Code != errCode)) {
			t.Errorf("%s: error at %d %q, want %+v", v.Name, errIndex, errCode, v.Error)
		}
		head := uint64(0)
		if p != nil {
			head = p.Chain().Head
		}
		if uint64(len(v.States)) != head {
			t.Errorf("%s: %d states for head %d", v.Name, len(v.States), head)
		}
		for _, s := range v.States {
			h, err := p.StateHashAt(s.Seq)
			got := h.String()
			if CodeOf(err) == "unavailable" {
				got = "unavailable"
			} else if err != nil {
				got = err.Error()
			}
			if got != s.StateHash {
				t.Errorf("%s: seq %d state %s, want %s", v.Name, s.Seq, got, s.StateHash)
			}
			st, err := Reconstruct(recs, s.Seq)
			switch {
			case s.StateHash == "unavailable":
				if CodeOf(err) != "unavailable" {
					t.Errorf("%s: Reconstruct(%d) = %v, want unavailable", v.Name, s.Seq, err)
				}
			case err != nil || st.Hash().String() != s.StateHash:
				t.Errorf("%s: Reconstruct(%d) mismatch (%v)", v.Name, s.Seq, err)
			}
		}
		if len(chainHashes) != len(v.ChainHashes) {
			t.Errorf("%s: %d chain hashes", v.Name, len(chainHashes))
		}
		for _, c := range v.ChainHashes {
			if chainHashes[c.Seq].String() != c.ChainHash {
				t.Errorf("%s: chain hash at %d", v.Name, c.Seq)
			}
		}
		var bs [][3]string
		var us [][2]string
		if p != nil {
			for _, b := range p.Boundaries {
				bs = append(bs, [3]string{strconv.FormatUint(b.Seq, 10), b.Expected.String(), b.Got.String()})
			}
			for _, u := range p.Unavailable {
				us = append(us, [2]string{strconv.FormatUint(u.From, 10), strconv.FormatUint(u.To, 10)})
			}
		}
		var wb [][3]string
		var wu [][2]string
		for _, b := range v.Boundaries {
			wb = append(wb, [3]string{strconv.FormatUint(b.Seq, 10), b.Expected, b.Got})
		}
		for _, u := range v.Unavailable {
			wu = append(wu, [2]string{strconv.FormatUint(u[0], 10), strconv.FormatUint(u[1], 10)})
		}
		if mustJSON(t, bs) != mustJSON(t, wb) || mustJSON(t, us) != mustJSON(t, wu) {
			t.Errorf("%s: boundaries %v unavailable %v", v.Name, bs, us)
		}
	}
}

func TestVectorsIDs(t *testing.T) {
	var f struct {
		FindingIDs []struct {
			TargetID  string `json:"target_id"`
			DedupKey  string `json:"dedup_key"`
			FirstSeen uint64 `json:"first_seen"`
			FindingID string `json:"finding_id"`
		} `json:"finding_ids"`
		QueryHashes []struct {
			Language  string `json:"language"`
			Query     string `json:"query"`
			Source    string `json:"source"`
			QueryHash string `json:"query_hash"`
		} `json:"query_hashes"`
		Genesis []struct {
			TargetID string `json:"target_id"`
			Epoch    string `json:"epoch"`
			WriterID string `json:"writer_id"`
			Genesis  string `json:"genesis"`
		} `json:"genesis"`
		ChainLinks []struct {
			Prev       string `json:"prev"`
			RecordHash string `json:"record_hash"`
			ChainHash  string `json:"chain_hash"`
		} `json:"chain_links"`
		RecordHashes []struct {
			Hex        string `json:"hex"`
			RecordHash string `json:"record_hash"`
		} `json:"record_hashes"`
		StateHashes []struct {
			Name      string `json:"name"`
			StateHash string `json:"state_hash"`
		} `json:"state_hashes"`
	}
	loadVectors(t, "ids.json", &f)
	for _, c := range f.FindingIDs {
		if got := FindingID(c.TargetID, c.DedupKey, c.FirstSeen); got != c.FindingID {
			t.Errorf("finding id %q: %s", c.DedupKey, got)
		}
	}
	for _, c := range f.QueryHashes {
		if got := QueryHash(c.Language, c.Query, c.Source).String(); got != c.QueryHash {
			t.Errorf("query hash %q: %s", c.Query, got)
		}
	}
	for _, c := range f.Genesis {
		ep, _ := ParseID(c.Epoch)
		w, _ := ParseID(c.WriterID)
		if got := Genesis(c.TargetID, ep, w).String(); got != c.Genesis {
			t.Errorf("genesis %s: %s", c.TargetID, got)
		}
	}
	for _, c := range f.RecordHashes {
		if got := RecordHash(vecBytes(t, c.Hex, nil)).String(); got != c.RecordHash {
			t.Errorf("record hash %s: %s", c.Hex, got)
		}
	}
	for _, c := range f.ChainLinks {
		prev, _ := ParseHash(c.Prev)
		rh, _ := ParseHash(c.RecordHash)
		if got := ChainHash(prev, rh).String(); got != c.ChainHash {
			t.Errorf("chain link: %s", got)
		}
	}
	for _, c := range f.StateHashes {
		if c.Name != "empty" || NewState().Hash().String() != c.StateHash {
			t.Errorf("state hash %s", c.Name)
		}
	}
}

type vecPoint struct {
	Seq       uint64 `json:"seq"`
	ChainHash string `json:"chain_hash"`
}

func TestVectorsOwnership(t *testing.T) {
	var f struct {
		Vectors []struct {
			Name            string `json:"name"`
			CredentialValid bool   `json:"credential_valid"`
			State           struct {
				TargetType        string  `json:"target_type"`
				Revoked           bool    `json:"revoked"`
				Conflict          bool    `json:"conflict"`
				PendingBinding    bool    `json:"pending_binding"`
				EnrolledMachineID string  `json:"enrolled_machine_id"`
				OpenEpoch         *string `json:"open_epoch"`
				Epochs            []struct {
					ID          string     `json:"id"`
					Owner       string     `json:"owner"`
					Open        bool       `json:"open"`
					Head        vecPoint   `json:"head"`
					ChainHashes []vecPoint `json:"chain_hashes"`
				} `json:"epochs"`
				Retired            []string `json:"retired"`
				HighestIncarnation []struct {
					WriterID    string `json:"writer_id"`
					Incarnation uint64 `json:"incarnation"`
				} `json:"highest_incarnation"`
				Active *struct {
					SessionID   string  `json:"session_id"`
					WriterID    string  `json:"writer_id"`
					Incarnation uint64  `json:"incarnation"`
					Instance    *string `json:"instance"`
				} `json:"active"`
			} `json:"state"`
			Hello struct {
				WriterID    string `json:"writer_id"`
				Incarnation uint64 `json:"incarnation"`
				Epoch       string `json:"epoch"`
				EpochOpen   *struct {
					Reason    string  `json:"reason"`
					PrevEpoch *string `json:"prev_epoch"`
					PrevHead  *uint64 `json:"prev_head"`
				} `json:"epoch_open"`
				LastCommitted *vecPoint `json:"last_committed"`
				MachineID     string    `json:"machine_id"`
				Instance      *string   `json:"instance"`
			} `json:"hello"`
			Expect struct {
				Row          int     `json:"row"`
				Accept       bool    `json:"accept"`
				Code         string  `json:"code"`
				Outcome      string  `json:"outcome"`
				OpenEpoch    bool    `json:"open_epoch"`
				CloseEpoch   *string `json:"close_epoch"`
				RetireWriter *string `json:"retire_writer"`
				Supersede    bool    `json:"supersede"`
				SetConflict  bool    `json:"set_conflict"`
				ClearBinding bool    `json:"clear_binding"`
				Audit        bool    `json:"audit"`
				Alarm        bool    `json:"alarm"`
			} `json:"expect"`
		} `json:"vectors"`
	}
	loadVectors(t, "ownership.json", &f)
	id := func(s string) ID {
		v, err := ParseID(s)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	hash := func(s string) Hash {
		v, err := ParseHash(s)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	idStr := func(p *ID) *string {
		if p == nil {
			return nil
		}
		s := p.String()
		return &s
	}
	for _, v := range f.Vectors {
		s := v.State
		st := &OwnershipState{
			TargetType: s.TargetType, Revoked: s.Revoked, Conflict: s.Conflict, PendingBinding: s.PendingBinding,
			EnrolledMachineID: s.EnrolledMachineID, Epochs: map[EpochID]*EpochInfo{}, Retired: map[WriterID]bool{},
			HighestIncarnation: map[WriterID]uint64{},
		}
		if s.OpenEpoch != nil {
			e := id(*s.OpenEpoch)
			st.OpenEpoch = &e
		}
		chains := map[EpochID]map[uint64]Hash{}
		for _, e := range s.Epochs {
			eid := id(e.ID)
			st.Epochs[eid] = &EpochInfo{ID: eid, Owner: id(e.Owner), Open: e.Open, Head: ChainPoint{Seq: e.Head.Seq, ChainHash: hash(e.Head.ChainHash)}}
			chains[eid] = map[uint64]Hash{}
			for _, c := range e.ChainHashes {
				chains[eid][c.Seq] = hash(c.ChainHash)
			}
		}
		st.ChainHashAt = func(ep EpochID, seq uint64) (Hash, bool) {
			h, ok := chains[ep][seq]
			return h, ok
		}
		for _, w := range s.Retired {
			st.Retired[id(w)] = true
		}
		for _, h := range s.HighestIncarnation {
			st.HighestIncarnation[id(h.WriterID)] = h.Incarnation
		}
		if s.Active != nil {
			st.Active = &ActiveSession{SessionID: s.Active.SessionID, Writer: id(s.Active.WriterID), Incarnation: s.Active.Incarnation}
			if s.Active.Instance != nil {
				st.Active.Instance = id(*s.Active.Instance)
			}
		}
		h := &HelloParams{WriterID: id(v.Hello.WriterID), Incarnation: v.Hello.Incarnation, Epoch: id(v.Hello.Epoch), MachineID: v.Hello.MachineID}
		if v.Hello.Instance != nil {
			n := id(*v.Hello.Instance)
			h.Instance = &n
		}
		if eo := v.Hello.EpochOpen; eo != nil {
			h.EpochOpen = &EpochOpen{Reason: eo.Reason, PrevHead: eo.PrevHead}
			if eo.PrevEpoch != nil {
				pe := id(*eo.PrevEpoch)
				h.EpochOpen.PrevEpoch = &pe
			}
		}
		if lc := v.Hello.LastCommitted; lc != nil {
			h.LastCommitted = &ChainPoint{Seq: lc.Seq, ChainHash: hash(lc.ChainHash)}
		}
		d := Decide(st, h, v.CredentialValid)
		got := mustJSON(t, []any{d.Row, d.Accept, d.Code, d.Outcome, d.OpenEpoch, idStr(d.CloseEpoch), idStr(d.RetireWriter), d.Supersede, d.SetConflict, d.ClearBinding, d.Audit, d.Alarm})
		e := v.Expect
		want := mustJSON(t, []any{e.Row, e.Accept, e.Code, e.Outcome, e.OpenEpoch, e.CloseEpoch, e.RetireWriter, e.Supersede, e.SetConflict, e.ClearBinding, e.Audit, e.Alarm})
		if got != want {
			t.Errorf("%s: got %s, want %s", v.Name, got, want)
		}
	}
}
