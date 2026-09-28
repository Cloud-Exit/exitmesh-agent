package protocol

// RecordHash is SHA-256("EMHPv1/record" || 0 || bytes).
func RecordHash(b []byte) Hash { return domainHash("EMHPv1/record", b) }

// Genesis is the chain hash of parent 0 for an epoch.
func Genesis(targetID string, epoch EpochID, writer WriterID) Hash {
	b, err := Marshal([]any{targetID, epoch[:], writer[:]})
	if err != nil {
		panic(err)
	}
	return domainHash("EMHPv1/genesis", b)
}

// ChainHash links a record hash to its predecessor's chain hash.
func ChainHash(prev, record Hash) Hash {
	return domainHash("EMHPv1/chain", prev[:], record[:])
}

func stateHash(res []Resource, edges []Edge, scopes map[string]ScopeStatus) Hash {
	ra := make([]any, len(res))
	for i, r := range res {
		ra[i] = resourceArray(r)
	}
	ea := make([]any, len(edges))
	for i, e := range edges {
		ea[i] = edgeArray(e)
	}
	b, err := Marshal([]any{ra, ea, scopesMap(scopes)})
	if err != nil {
		panic(err)
	}
	return domainHash("EMHPv1/state", b)
}
