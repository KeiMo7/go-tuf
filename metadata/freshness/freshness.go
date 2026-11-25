package freshness

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"
)

// SupportedSchemaVersion is the only persistence schema major version written
// by this implementation.
const SupportedSchemaVersion = 1

// Sentinel errors returned by fingerprint parsing and persistence.
var (
	// ErrFingerprint wraps failures while parsing metadata for a fingerprint.
	ErrFingerprint = errors.New("freshness: invalid metadata fingerprint")
	// ErrDegradedReadOnly is returned by Flush after the on-disk ledger was
	// found to be unreadable.
	ErrDegradedReadOnly = errors.New("freshness: ledger is degraded and read-only")
	// ErrSchemaTooNew is returned when loading a ledger written by a newer
	// schema version.
	ErrSchemaTooNew = errors.New("freshness: ledger schema version is too new")
)

// MetaRef is the audited subset of one entry in timestamp/snapshot Meta.
type MetaRef struct {
	Role    string `json:"role"`
	Version int64  `json:"version"`
	Length  int64  `json:"length"`
	SHA256  string `json:"sha256"`
}

// Fingerprint is the deterministic, reviewable subset of signed metadata.
type Fingerprint struct {
	Role    string    `json:"role"`
	Parent  string    `json:"parent"`
	Version int64     `json:"version"`
	Expires time.Time `json:"expires"`
	Meta    []MetaRef `json:"meta"`
}

// Verdict is one audit decision and the metadata fingerprints involved in it.
// Err is intentionally not serialized; callers can retain it in-process while
// the persisted Reason and code remain reviewable.
type Verdict struct {
	Code      Code
	Role      string
	Parent    string
	Prev      Fingerprint
	Seen      Fingerprint
	Stored    bool
	Divergent bool
	RefTime   time.Time
	Reason    string
	Err       error `json:"-"`
}

// Warning is a non-fatal ledger warning.
type Warning struct {
	Code Code
	Msg  string
	Err  error `json:"-"`
}

// fingerprintWire contains only the signed fields needed by FingerprintFrom.
// Missing fields naturally remain zero values.
type fingerprintWire struct {
	Signed struct {
		Version int64     `json:"version"`
		Expires time.Time `json:"expires"`
		Meta    map[string]struct {
			Version int64 `json:"version"`
			Length  int64 `json:"length"`
			Hashes  struct {
				SHA256 string `json:"sha256"`
			} `json:"hashes"`
		} `json:"meta"`
	} `json:"signed"`
}

// FingerprintFrom extracts Role, Parent, signed.version, signed.expires, and
// every signed.meta entry's version, length, and hashes.sha256. Meta is sorted
// by entry name. Missing fields remain zero values. Parse failures wrap
// ErrFingerprint.
func FingerprintFrom(role, parent string, data []byte) (Fingerprint, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return Fingerprint{}, fmt.Errorf("%w: empty metadata", ErrFingerprint)
	}

	var wire fingerprintWire
	if err := json.Unmarshal(data, &wire); err != nil {
		return Fingerprint{}, fmt.Errorf("%w: %v", ErrFingerprint, err)
	}

	fp := Fingerprint{
		Role:    role,
		Parent:  parent,
		Version: wire.Signed.Version,
		Expires: wire.Signed.Expires,
	}

	for name, entry := range wire.Signed.Meta {
		ref := MetaRef{
			Role:    name,
			Version: entry.Version,
			Length:  entry.Length,
			SHA256:  entry.Hashes.SHA256,
		}
		fp.Meta = append(fp.Meta, ref)
	}
	sort.Slice(fp.Meta, func(i, j int) bool { return fp.Meta[i].Role < fp.Meta[j].Role })

	return fp, nil
}

// cloneFingerprint returns a deep copy safe to hand to callers or snapshots.
func cloneFingerprint(in Fingerprint) Fingerprint {
	out := in
	if in.Meta != nil {
		out.Meta = append([]MetaRef(nil), in.Meta...)
		sort.Slice(out.Meta, func(i, j int) bool { return out.Meta[i].Role < out.Meta[j].Role })
	}
	return out
}

func cloneVerdict(in Verdict) Verdict {
	out := in
	out.Prev = cloneFingerprint(in.Prev)
	out.Seen = cloneFingerprint(in.Seen)
	return out
}

// fingerprintsEqual compares all audit-relevant scalar and Meta fields.
func fingerprintsEqual(a, b Fingerprint) bool {
	if a.Role != b.Role || a.Parent != b.Parent || a.Version != b.Version || !a.Expires.Equal(b.Expires) {
		return false
	}
	if len(a.Meta) != len(b.Meta) {
		return false
	}
	am := metaRefMap(a.Meta)
	bm := metaRefMap(b.Meta)
	if len(am) != len(bm) {
		return false
	}
	for name, ar := range am {
		br, ok := bm[name]
		if !ok || ar != br {
			return false
		}
	}
	return true
}

// metaEqual compares Meta entries independent of their sorted slice order.
func metaEqual(a, b []MetaRef) bool {
	am := metaRefMap(a)
	bm := metaRefMap(b)
	if len(am) != len(bm) {
		return false
	}
	for name, ar := range am {
		br, ok := bm[name]
		if !ok || ar != br {
			return false
		}
	}
	return true
}

func metaRefMap(refs []MetaRef) map[string]MetaRef {
	out := make(map[string]MetaRef, len(refs))
	for _, ref := range refs {
		cp := ref
		cp.Role = ""
		out[ref.Role] = cp
	}
	return out
}

// missingMetaRefs returns sorted Meta entry names present in prev but absent
// from seen. It derives removal solely from fingerprint differences.
func missingMetaRefs(prev, seen Fingerprint) []string {
	seenNames := make(map[string]struct{}, len(seen.Meta))
	for _, ref := range seen.Meta {
		seenNames[ref.Role] = struct{}{}
	}
	var missing []string
	for _, ref := range prev.Meta {
		if _, ok := seenNames[ref.Role]; !ok {
			missing = append(missing, ref.Role)
		}
	}
	sort.Strings(missing)
	return missing
}

// fingerprintRegression reports whether a version decreased either for the
// role itself or for any same-named Meta entry.
func fingerprintRegression(prev, seen Fingerprint) bool {
	if prev.Version != 0 && seen.Version < prev.Version {
		return true
	}
	prevMeta := metaRefMap(prev.Meta)
	seenMeta := metaRefMap(seen.Meta)
	for name, oldRef := range prevMeta {
		if newRef, ok := seenMeta[name]; ok && newRef.Version < oldRef.Version {
			return true
		}
	}
	return false
}

func violationCode(code Code) bool {
	switch code {
	case CodeAccept, CodeEqual:
		return false
	default:
		return true
	}
}

func sortVerdicts(values []Verdict) {
	sort.SliceStable(values, func(i, j int) bool {
		a, b := values[i], values[j]
		if a.Role != b.Role {
			return a.Role < b.Role
		}
		if a.Parent != b.Parent {
			return a.Parent < b.Parent
		}
		if a.Code != b.Code {
			return a.Code < b.Code
		}
		if a.Prev.Version != b.Prev.Version {
			return a.Prev.Version < b.Prev.Version
		}
		if a.Seen.Version != b.Seen.Version {
			return a.Seen.Version < b.Seen.Version
		}
		if a.Reason != b.Reason {
			return a.Reason < b.Reason
		}
		return stableFingerprintString(a.Seen) < stableFingerprintString(b.Seen)
	})
}

func stableFingerprintString(fp Fingerprint) string {
	b, _ := json.Marshal(fp)
	return string(b)
}
