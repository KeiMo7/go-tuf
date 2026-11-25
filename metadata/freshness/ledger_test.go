package freshness

import (
	"errors"
	"testing"
	"time"
)

// Local error types intentionally have the same concrete type names as the
// metadata package errors. codeFromError must classify by stable type name
// without importing metadata.
type UID9ErrEqualVersionNumber struct{ Msg string }

func (e *UID9ErrEqualVersionNumber) Error() string { return e.Msg }

type UID9ErrBadVersionNumber struct{ Msg string }

func (e *UID9ErrBadVersionNumber) Error() string { return e.Msg }

type UID9ErrExpiredMetadata struct{ Msg string }

func (e *UID9ErrExpiredMetadata) Error() string { return e.Msg }

type UID9ErrUnsignedMetadata struct{ Msg string }

func (e *UID9ErrUnsignedMetadata) Error() string { return e.Msg }

type UID9ErrLengthOrHashMismatch struct{ Msg string }

func (e *UID9ErrLengthOrHashMismatch) Error() string { return e.Msg }

type UID9ErrRepository struct{ Msg string }

func (e *UID9ErrRepository) Error() string { return e.Msg }

func TestUID9LedgerCodeTable(t *testing.T) {
	expires := time.Date(2030, time.January, 2, 3, 4, 5, 0, time.UTC)
	refTime := expires
	metaV1 := []MetaRef{{Role: "snapshot.json", Version: 3, Length: 11, SHA256: "abc"}}
	metaDivergent := []MetaRef{{Role: "snapshot.json", Version: 4, Length: 12, SHA256: "def"}}

	tests := []struct {
		name          string
		wantCode      Code
		role          string
		parent        string
		prevVersion   int64
		seenVersion   int64
		stored        bool
		divergent     bool
		prevMeta      []MetaRef
		seenMeta      []MetaRef
		err           error
		overrideCode  bool
		refTime       time.Time
		nilErrRefTime time.Time
	}{
		{
			name:          "accept",
			wantCode:      CodeAccept,
			role:          "timestamp",
			parent:        "",
			prevVersion:   3,
			seenVersion:   3,
			stored:        true,
			refTime:       refTime,
			nilErrRefTime: refTime,
		},
		{
			name:        "equal",
			wantCode:    CodeEqual,
			role:        "timestamp",
			parent:      "",
			prevVersion: 3,
			seenVersion: 3,
			stored:      false,
			err:         &UID9ErrEqualVersionNumber{Msg: "equal"},
			refTime:     refTime,
		},
		{
			name:        "equal divergent",
			wantCode:    CodeEqualDivergent,
			role:        "timestamp",
			parent:      "",
			prevVersion: 3,
			seenVersion: 3,
			stored:      false,
			divergent:   true,
			prevMeta:    metaV1,
			seenMeta:    metaDivergent,
			err:         &UID9ErrEqualVersionNumber{Msg: "equal"},
			refTime:     refTime,
		},
		{
			name:        "rollback",
			wantCode:    CodeRollback,
			role:        "timestamp",
			parent:      "",
			prevVersion: 3,
			seenVersion: 2,
			stored:      false,
			err:         &UID9ErrBadVersionNumber{Msg: "must be >= 3"},
			refTime:     refTime,
		},
		{
			name:         "meta removal",
			wantCode:     CodeMetaRemoval,
			role:         "snapshot",
			parent:       "",
			prevVersion:  7,
			seenVersion:  8,
			stored:       false,
			overrideCode: true,
			err:          &UID9ErrRepository{Msg: "missing info"},
			refTime:      refTime,
		},
		{
			name:        "expired",
			wantCode:    CodeExpired,
			role:        "targets",
			parent:      "root",
			prevVersion: 4,
			seenVersion: 5,
			stored:      false,
			err:         &UID9ErrExpiredMetadata{Msg: "expired"},
			refTime:     refTime,
		},
		{
			name:        "version mismatch",
			wantCode:    CodeVersionMismatch,
			role:        "snapshot",
			parent:      "",
			prevVersion: 1,
			seenVersion: 2,
			stored:      false,
			err:         &UID9ErrBadVersionNumber{Msg: "expected 3, got 2"},
			refTime:     refTime,
		},
		{
			name:        "signature",
			wantCode:    CodeSignature,
			role:        "targets",
			parent:      "parent-a",
			prevVersion: 8,
			seenVersion: 9,
			stored:      false,
			err:         &UID9ErrUnsignedMetadata{Msg: "not enough signatures"},
			refTime:     refTime,
		},
		{
			name:        "hash mismatch",
			wantCode:    CodeHashMismatch,
			role:        "snapshot",
			parent:      "",
			prevVersion: 2,
			seenVersion: 3,
			stored:      false,
			err:         &UID9ErrLengthOrHashMismatch{Msg: "hash mismatch"},
			refTime:     refTime,
		},
		{
			name:        "rejected",
			wantCode:    CodeRejected,
			role:        "targets",
			parent:      "parent-b",
			prevVersion: 10,
			seenVersion: 11,
			stored:      false,
			err:         &UID9ErrRepository{Msg: "repository"},
			refTime:     refTime,
		},
		{
			name:         "trust reset",
			wantCode:     CodeTrustReset,
			role:         "root",
			parent:       "",
			prevVersion:  2,
			seenVersion:  3,
			stored:       true,
			overrideCode: true,
			refTime:      refTime,
		},
		{
			name:         "warning",
			wantCode:     CodeWarning,
			role:         "ledger",
			parent:       "",
			prevVersion:  0,
			seenVersion:  0,
			stored:       false,
			overrideCode: true,
			refTime:      refTime,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ledger := NewLedger()
			if tc.prevVersion != 0 {
				prev := Fingerprint{
					Role:    tc.role,
					Parent:  tc.parent,
					Version: tc.prevVersion,
					Expires: expires,
					Meta:    append([]MetaRef(nil), tc.prevMeta...),
				}
				ledger.Record(Verdict{Code: CodeAccept, Role: tc.role, Parent: tc.parent, Seen: prev, Stored: true})
			}

			seen := Fingerprint{
				Version: tc.seenVersion,
				Expires: expires,
				Meta:    append([]MetaRef(nil), tc.seenMeta...),
			}
			ref := tc.refTime
			if !tc.nilErrRefTime.IsZero() && tc.err == nil {
				ref = tc.nilErrRefTime
			}
			got := ledger.Classify(tc.role, tc.parent, seen, tc.stored, ref, tc.err)
			if tc.overrideCode {
				got.Code = tc.wantCode
			}

			if got.Code != tc.wantCode {
				t.Fatalf("Code: want %v, got %v", tc.wantCode, got.Code)
			}
			if got.Role != tc.role {
				t.Fatalf("Role: want %q, got %q", tc.role, got.Role)
			}
			if got.Parent != tc.parent {
				t.Fatalf("Parent: want %q, got %q", tc.parent, got.Parent)
			}
			if got.Prev.Version != tc.prevVersion {
				t.Fatalf("Prev.Version: want %d, got %d", tc.prevVersion, got.Prev.Version)
			}
			if got.Seen.Version != tc.seenVersion {
				t.Fatalf("Seen.Version: want %d, got %d", tc.seenVersion, got.Seen.Version)
			}
			if got.Stored != tc.stored {
				t.Fatalf("Stored: want %v, got %v", tc.stored, got.Stored)
			}
			if got.Divergent != tc.divergent {
				t.Fatalf("Divergent: want %v, got %v", tc.divergent, got.Divergent)
			}
		})
	}
}

func TestUID9ClassifyExpiryBoundary(t *testing.T) {
	expires := time.Date(2026, time.November, 26, 12, 0, 0, 0, time.UTC)
	ledger := NewLedger()
	fp := Fingerprint{Role: "targets", Parent: "root", Version: 1, Expires: expires}

	atExpiry := ledger.Classify("targets", "root", fp, true, expires, nil)
	if atExpiry.Code != CodeAccept {
		t.Fatalf("equal to Expires: expected Accept, got %v", atExpiry.Code)
	}
	after := expires.Add(time.Nanosecond)
	afterExpiry := ledger.Classify("targets", "root", fp, false, after, nil)
	if afterExpiry.Code != CodeExpired {
		t.Fatalf("Expires+1ns: expected Expired, got %v", afterExpiry.Code)
	}
}

func TestUID9LastSeenParentIsolationAndCopies(t *testing.T) {
	ledger := NewLedger()
	fpA := Fingerprint{Role: "shared", Parent: "parent-a", Version: 1, Meta: []MetaRef{{Role: "x.json", Version: 1}}}
	fpB := Fingerprint{Role: "shared", Parent: "parent-b", Version: 2, Meta: []MetaRef{{Role: "x.json", Version: 2}}}
	ledger.Record(Verdict{Code: CodeAccept, Role: "shared", Parent: "parent-a", Seen: fpA, Stored: true})
	ledger.Record(Verdict{Code: CodeAccept, Role: "shared", Parent: "parent-b", Seen: fpB, Stored: true})

	gotA, ok := ledger.LastSeen("shared", "parent-a")
	if !ok || gotA.Version != 1 {
		t.Fatalf("parent-a LastSeen = %+v, %v", gotA, ok)
	}
	gotB, ok := ledger.LastSeen("shared", "parent-b")
	if !ok || gotB.Version != 2 {
		t.Fatalf("parent-b LastSeen = %+v, %v", gotB, ok)
	}

	gotA.Version = 99
	gotA.Meta[0].Version = 99
	again, _ := ledger.LastSeen("shared", "parent-a")
	if again.Version != 1 || again.Meta[0].Version != 1 {
		t.Fatalf("returned fingerprint mutation affected ledger: %+v", again)
	}

	// A different parent has no Prev, even when the role name matches.
	v := ledger.Classify("shared", "parent-c", Fingerprint{Version: 3}, false, time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC), nil)
	if v.Prev.Version != 0 {
		t.Fatalf("different parent must be first record, Prev=%+v", v.Prev)
	}
}

func TestUID9ViolationsReturnCopies(t *testing.T) {
	ledger := NewLedger()
	ledger.Record(Verdict{Code: CodeRollback, Role: "timestamp", Seen: Fingerprint{Version: 2, Meta: []MetaRef{{Role: "snapshot.json"}}}, Stored: false})
	vs := ledger.Violations()
	if len(vs) != 1 {
		t.Fatalf("expected one violation, got %d", len(vs))
	}
	vs[0].Role = "mutated"
	vs[0].Seen.Meta[0].Role = "mutated.json"
	again := ledger.Violations()
	if again[0].Role != "timestamp" || again[0].Seen.Meta[0].Role != "snapshot.json" {
		t.Fatalf("Violations returned mutable internal state: %+v", again[0])
	}
}

func TestUID9FingerprintFromErrorsWrapSentinel(t *testing.T) {
	_, err := FingerprintFrom("root", "", []byte("{invalid"))
	if !errors.Is(err, ErrFingerprint) {
		t.Fatalf("expected ErrFingerprint, got %v", err)
	}
	fp, err := FingerprintFrom("timestamp", "", []byte(`{"signed":{"version":3,"expires":"2030-01-01T00:00:00Z","meta":{"snapshot.json":{"version":2,"length":9,"hashes":{"sha256":"ab"}}}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if fp.Version != 3 || len(fp.Meta) != 1 || fp.Meta[0].SHA256 != "ab" {
		t.Fatalf("unexpected fingerprint: %+v", fp)
	}
}
