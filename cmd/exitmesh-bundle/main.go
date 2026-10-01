// Command exitmesh-bundle builds, signs, verifies, and inspects rule bundles (docs/bundle-format.md).
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/cloud-exit/exitmesh-agent/internal/kv"
	"github.com/cloud-exit/exitmesh-agent/internal/rules/bundle"
	"github.com/cloud-exit/exitmesh-agent/internal/rules/validators"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

const usage = `usage: exitmesh-bundle <command> [flags]

commands:
  keygen    generate an ed25519 root or signing key
  roots     write a roots.json from public keys
  manifest  create and sign a key manifest
  build     pack a bundle directory into bundle.tar.gz
  sign      sign a bundle archive
  verify    verify an archive, signature, and key manifest against root keys
  inspect   print rules, targets, and engine requirements of an archive
`

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	cmds := map[string]func([]string, io.Writer) error{
		"keygen": keygen, "roots": roots, "manifest": manifest, "build": build,
		"sign": signCmd, "verify": verify, "inspect": inspect,
	}
	fn, ok := cmds[args[0]]
	if !ok {
		fmt.Fprint(stderr, usage)
		return 2
	}
	if err := fn(args[1:], stdout); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 2
		}
		fmt.Fprintf(stderr, "exitmesh-bundle %s: %v\n", args[0], err)
		return 1
	}
	return 0
}

type multi []string

func (m *multi) String() string     { return strings.Join(*m, " ") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

func newFlags(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs
}

func need(vals map[string]string) error {
	for name, v := range vals {
		if v == "" {
			return fmt.Errorf("-%s is required", name)
		}
	}
	return nil
}

func writeJSON(path string, v any, mode os.FileMode) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), mode)
}

func keygen(args []string, out io.Writer) error {
	fs := newFlags("keygen")
	id := fs.String("id", "", "key id")
	prefix := fs.String("out", "", "output prefix: writes PREFIX.key (private) and PREFIX.pub")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := need(map[string]string{"id": *id, "out": *prefix}); err != nil {
		return err
	}
	k, err := bundle.GenerateKey(*id)
	if err != nil {
		return err
	}
	if err := writeJSON(*prefix+".key", k, 0o600); err != nil {
		return err
	}
	if err := writeJSON(*prefix+".pub", k.Public(), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(out, "wrote %s.key and %s.pub for key %q\n", *prefix, *prefix, *id)
	return nil
}

func readPub(path string) (bundle.RootKey, error) {
	var k bundle.RootKey
	b, err := os.ReadFile(path)
	if err != nil {
		return k, err
	}
	if err := json.Unmarshal(b, &k); err != nil {
		return k, fmt.Errorf("%s: %w", path, err)
	}
	if k.ID == "" || len(k.PublicKey) != 32 {
		return k, fmt.Errorf("%s: not a public key file", path)
	}
	return k, nil
}

func readKey(path string) (bundle.SigningKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return bundle.SigningKey{}, err
	}
	return bundle.ParseSigningKey(b)
}

func roots(args []string, out io.Writer) error {
	fs := newFlags("roots")
	var pubs multi
	fs.Var(&pubs, "pub", "root public key file (repeatable)")
	threshold := fs.Int("threshold", 1, "distinct root signatures required")
	dst := fs.String("out", "", "roots.json to write")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := need(map[string]string{"out": *dst}); err != nil {
		return err
	}
	r, err := rootsFromPubs(pubs, *threshold)
	if err != nil {
		return err
	}
	if err := writeJSON(*dst, r, 0o644); err != nil {
		return err
	}
	fmt.Fprintf(out, "wrote %s with %d root key(s), threshold %d\n", *dst, len(r.Keys), r.Threshold)
	return nil
}

func rootsFromPubs(pubs []string, threshold int) (bundle.Roots, error) {
	r := bundle.Roots{Threshold: threshold}
	for _, p := range pubs {
		k, err := readPub(p)
		if err != nil {
			return r, err
		}
		r.Keys = append(r.Keys, k)
	}
	b, err := json.Marshal(r)
	if err != nil {
		return r, err
	}
	return bundle.ParseRoots(b)
}

func parseTime(s string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return t, fmt.Errorf("time %q: use RFC 3339", s)
	}
	return t.UTC(), nil
}

func manifest(args []string, out io.Writer) error {
	fs := newFlags("manifest")
	seq := fs.Uint64("seq", 0, "manifest sequence, strictly above every published manifest")
	issued := fs.String("issued-at", "", "issue time (RFC 3339, default now)")
	var keys, successors, rootKeys multi
	fs.Var(&keys, "key", "signing key: PUBFILE,NOT_BEFORE,NOT_AFTER[,REVOKED_AT] (repeatable)")
	fs.Var(&successors, "successor", "successor root: PUBFILE,NOT_BEFORE (repeatable)")
	fs.Var(&rootKeys, "root", "root private key file to sign with (repeatable)")
	dst := fs.String("out", "", "signed key manifest to write")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := need(map[string]string{"out": *dst}); err != nil {
		return err
	}
	at := time.Now().UTC()
	if *issued != "" {
		var err error
		if at, err = parseTime(*issued); err != nil {
			return err
		}
	}
	var mks []bundle.ManifestKey
	for _, spec := range keys {
		parts := strings.Split(spec, ",")
		if len(parts) != 3 && len(parts) != 4 {
			return fmt.Errorf("-key %q: want PUBFILE,NOT_BEFORE,NOT_AFTER[,REVOKED_AT]", spec)
		}
		pub, err := readPub(parts[0])
		if err != nil {
			return err
		}
		mk := bundle.ManifestKey{ID: pub.ID, PublicKey: pub.PublicKey}
		if mk.NotBefore, err = parseTime(parts[1]); err != nil {
			return err
		}
		if mk.NotAfter, err = parseTime(parts[2]); err != nil {
			return err
		}
		if len(parts) == 4 {
			r, err := parseTime(parts[3])
			if err != nil {
				return err
			}
			mk.RevokedAt = &r
		}
		mks = append(mks, mk)
	}
	var srs []bundle.SuccessorRoot
	for _, spec := range successors {
		parts := strings.Split(spec, ",")
		if len(parts) != 2 {
			return fmt.Errorf("-successor %q: want PUBFILE,NOT_BEFORE", spec)
		}
		pub, err := readPub(parts[0])
		if err != nil {
			return err
		}
		nb, err := parseTime(parts[1])
		if err != nil {
			return err
		}
		srs = append(srs, bundle.SuccessorRoot{ID: pub.ID, PublicKey: pub.PublicKey, NotBefore: nb})
	}
	var signers []bundle.SigningKey
	for _, p := range rootKeys {
		k, err := readKey(p)
		if err != nil {
			return err
		}
		signers = append(signers, k)
	}
	m, err := bundle.NewKeyManifest(*seq, at, mks, srs)
	if err != nil {
		return err
	}
	signed, err := bundle.SignManifest(m, signers...)
	if err != nil {
		return err
	}
	if err := os.WriteFile(*dst, append(signed, '\n'), 0o644); err != nil { //nolint:gosec // a signed key manifest is a public distribution artifact
		return err
	}
	fmt.Fprintf(out, "wrote key manifest sequence %d with %d signing key(s), %d successor root(s), %d signature(s)\n", m.Sequence, len(mks), len(srs), len(signers))
	return nil
}

func build(args []string, out io.Writer) error {
	fs := newFlags("build")
	dir := fs.String("dir", "", "bundle directory")
	dst := fs.String("out", "", "bundle.tar.gz to write")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := need(map[string]string{"dir": *dir, "out": *dst}); err != nil {
		return err
	}
	a, err := bundle.Build(*dir)
	if err != nil {
		return err
	}
	b, err := bundle.Parse(a)
	if err != nil {
		return err
	}
	if _, err := bundle.Validate(b, validators.For(b.Manifest.TargetType), bundle.DefaultPolicy()); err != nil {
		return err
	}
	if err := os.WriteFile(*dst, a, 0o644); err != nil { //nolint:gosec // a rule bundle is a public distribution artifact
		return err
	}
	fmt.Fprintf(out, "wrote %s: version %s, %d rule(s), sha256 %x\n", *dst, b.Manifest.Version, len(b.Manifest.Rules), b.Digest)
	return nil
}

func signCmd(args []string, out io.Writer) error {
	fs := newFlags("sign")
	src := fs.String("bundle", "", "bundle.tar.gz")
	key := fs.String("key", "", "signing private key file")
	dst := fs.String("out", "", "signature file to write")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := need(map[string]string{"bundle": *src, "key": *key, "out": *dst}); err != nil {
		return err
	}
	a, err := os.ReadFile(*src)
	if err != nil {
		return err
	}
	if _, err := bundle.Parse(a); err != nil {
		return err
	}
	k, err := readKey(*key)
	if err != nil {
		return err
	}
	sig, err := bundle.Sign(a, k)
	if err != nil {
		return err
	}
	if err := os.WriteFile(*dst, append(sig, '\n'), 0o644); err != nil { //nolint:gosec // a detached signature is a public distribution artifact
		return err
	}
	fmt.Fprintf(out, "wrote %s signed by %q\n", *dst, k.ID)
	return nil
}

func verify(args []string, out io.Writer) error {
	fs := newFlags("verify")
	dir := fs.String("dir", "", "air-gap delivery directory (bundle.tar.gz, bundle.sig, keymanifest.json)")
	src := fs.String("bundle", "", "bundle.tar.gz")
	sigPath := fs.String("sig", "", "bundle signature")
	manPath := fs.String("manifest", "", "signed key manifest")
	rootsPath := fs.String("roots", "", "roots.json with the trust root to verify against")
	var pubs multi
	fs.Var(&pubs, "root-pub", "root public key file instead of -roots (repeatable)")
	at := fs.String("at", "", "verification time (RFC 3339, default now)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	var r bundle.Roots
	var err error
	switch {
	case *rootsPath != "":
		b, err := os.ReadFile(*rootsPath)
		if err != nil {
			return err
		}
		if r, err = bundle.ParseRoots(b); err != nil {
			return err
		}
	case len(pubs) > 0:
		if r, err = rootsFromPubs(pubs, 1); err != nil {
			return err
		}
	default:
		return bundle.ErrNoRoots
	}
	v, err := bundle.NewVerifier(r, kv.NewMemory())
	if err != nil {
		return err
	}
	if *at != "" {
		t, err := parseTime(*at)
		if err != nil {
			return err
		}
		v.SetClock(func() time.Time { return t })
	}
	var archive, sig []byte
	if *dir != "" {
		if archive, sig, err = v.VerifyFiles(*dir); err != nil {
			return err
		}
	} else {
		if err := need(map[string]string{"bundle": *src, "sig": *sigPath, "manifest": *manPath}); err != nil {
			return err
		}
		man, err := os.ReadFile(*manPath)
		if err != nil {
			return err
		}
		if _, err := v.AcceptManifest(man); err != nil {
			return err
		}
		if archive, err = os.ReadFile(*src); err != nil {
			return err
		}
		if sig, err = os.ReadFile(*sigPath); err != nil {
			return err
		}
		if _, err := v.VerifyBundle(archive, sig); err != nil {
			return err
		}
	}
	s, err := bundle.ParseSignature(sig)
	if err != nil {
		return err
	}
	b, err := bundle.Parse(archive)
	if err != nil {
		return err
	}
	res, err := bundle.Validate(b, validators.For(b.Manifest.TargetType), bundle.DefaultPolicy())
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "OK: bundle %s (%s) signed by %q, key manifest sequence %d, %d active, %d unsupported, %d disabled\n",
		b.Manifest.Version, b.Manifest.TargetType, s.KeyID, v.Sequence(), len(res.Active), len(res.Unsupported), len(res.Disabled))
	return nil
}

func inspect(args []string, out io.Writer) error {
	fs := newFlags("inspect")
	src := fs.String("bundle", "", "bundle.tar.gz")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := need(map[string]string{"bundle": *src}); err != nil {
		return err
	}
	a, err := os.ReadFile(*src)
	if err != nil {
		return err
	}
	b, err := bundle.Parse(a)
	if err != nil {
		return err
	}
	res, verr := bundle.Validate(b, validators.For(b.Manifest.TargetType), bundle.DefaultPolicy())
	m := b.Manifest
	fmt.Fprintf(out, "version:        %s\ntarget_type:    %s\nengine_version: %d (this agent: %d)\nschema_version: %d\ncreated_at:     %s\nsha256:         %x\nrules:          %d\n\n",
		m.Version, m.TargetType, m.EngineVersion, bundle.EngineVersion, m.SchemaVersion, m.CreatedAt.Format(time.RFC3339), b.Digest, len(m.Rules))
	status := map[string]string{}
	for _, id := range res.Active {
		status[id] = "active"
	}
	for _, id := range res.Disabled {
		status[id] = "disabled"
	}
	for id, why := range res.Unsupported {
		status[id] = "unsupported: " + why
	}
	for id, why := range res.Rejected {
		status[id] = "rejected: " + why
	}
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tVERSION\tCLASS\tTARGET\tSCOPE\tMIN_ENGINE\tSOURCE\tSTATUS")
	for _, r := range m.Rules {
		src := r.File
		if r.Class != bundle.ClassState {
			src = fmt.Sprintf("%s#%s/%s", r.File, r.Group, r.Alert)
		}
		for _, s := range b.State {
			if s.ID == r.ID {
				src = "state: " + strings.Join(s.Kinds, ",")
			}
		}
		minEngine := r.MinEngine
		if minEngine == 0 {
			minEngine = 1
		}
		fmt.Fprintf(tw, "%s\t%d\t%s\t%s\t%s\t%d\t%s\t%s\n", r.ID, r.Version, r.Class, r.Target, r.Scope, minEngine, src, status[r.ID])
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	if verr != nil {
		fmt.Fprintf(out, "\nbundle is not valid for this agent: %v\n", verr)
	}
	return nil
}
