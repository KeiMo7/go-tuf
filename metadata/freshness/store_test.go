package freshness

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestUID9StoreRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "freshness.json")
	ref := time.Date(2026, time.November, 26, 12, 0, 0, 123, time.UTC)

	ledger := NewLedger(WithPath(path), WithMaxViolations(128))
	prev := Fingerprint{Role: "timestamp", Version: 3, Expires: ref, Meta: []MetaRef{{Role: "snapshot.json", Version: 3}}}
	seen := Fingerprint{Role: "timestamp", Version: 2, Expires: ref, Meta: []MetaRef{{Role: "snapshot.json", Version: 2}}}
	ledger.Record(Verdict{Code: CodeAccept, Role: "timestamp", Seen: prev, Stored: true, RefTime: ref})
	ledger.Record(Verdict{Code: CodeRollback, Role: "timestamp", Prev: prev, Seen: seen, Stored: false, RefTime: ref, Reason: "rollback"})
	ledger.appendWarningLocked(Warning{Code: CodeWarning, Msg: "unit warning"})

	if err := ledger.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("ledger mode = %o, want 0600", perm)
	}

	loaded := NewLedger(WithPath(path))
	if loaded.Degraded() {
		t.Fatal("loaded ledger should not be degraded")
	}
	vs := loaded.Violations()
	if len(vs) != 1 || vs[0].Code != CodeRollback || vs[0].Prev.Version != 3 || vs[0].Seen.Version != 2 {
		t.Fatalf("unexpected loaded violations: %+v", vs)
	}
	fp, ok := loaded.LastSeen("timestamp", "")
	if !ok || fp.Version != 3 {
		t.Fatalf("unexpected loaded LastSeen: %+v %v", fp, ok)
	}
	if ws := loaded.Warnings(); len(ws) != 1 || ws[0].Msg != "unit warning" {
		t.Fatalf("unexpected loaded warnings: %+v", ws)
	}
}

func TestUID9StoreCorruptJSONDegradesReadOnly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ledger.json")
	original := []byte(`{"schemaVersion":1,"violations":bad}`)
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}

	ledger := NewLedger(WithPath(path))
	if !ledger.Degraded() {
		t.Fatal("corrupt ledger should be degraded")
	}
	ws := ledger.Warnings()
	if len(ws) == 0 || ws[0].Msg != "ledger unreadable" || ws[0].Err == nil {
		t.Fatalf("expected ledger unreadable warning with cause, got %+v", ws)
	}
	if err := ledger.Flush(); !errors.Is(err, ErrDegradedReadOnly) {
		t.Fatalf("Flush error = %v, want ErrDegradedReadOnly", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(original) {
		t.Fatalf("corrupt file was overwritten:\n%s", after)
	}
}

func TestUID9StoreSchemaTooNew(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ledger.json")
	original := []byte(`{"schemaVersion":2}`)
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}

	ledger := NewLedger(WithPath(path))
	if !ledger.Degraded() {
		t.Fatal("newer schema should be read-only/degraded")
	}
	if err := ledger.Flush(); !errors.Is(err, ErrSchemaTooNew) {
		t.Fatalf("first Flush = %v, want ErrSchemaTooNew", err)
	}
	if err := ledger.Flush(); !errors.Is(err, ErrSchemaTooNew) {
		t.Fatalf("second Flush = %v, want ErrSchemaTooNew", err)
	}
	if ws := ledger.Warnings(); len(ws) != 1 {
		t.Fatalf("too-new warning should be recorded once, got %d: %+v", len(ws), ws)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(original) {
		t.Fatalf("newer schema file was rewritten:\n%s", after)
	}
}

func TestUID9StoreReadOnlyDirectory(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory permission bits")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	path := filepath.Join(dir, "freshness.json")
	ledger := NewLedger(WithPath(path))
	err := ledger.Flush()
	if err == nil {
		t.Fatal("expected permission error")
	}
	if !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("error type = %T %v, want fs.ErrPermission", err, err)
	}
	if ledger.Degraded() {
		t.Fatal("transient flush/permission failure should not permanently degrade ledger")
	}
	ws := ledger.Warnings()
	if len(ws) == 0 || ws[len(ws)-1].Err == nil {
		t.Fatalf("expected warning retaining OS error, got %+v", ws)
	}
}

func TestUID9StoreConcurrentRecordAndFlush(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shared.json")
	ledger := NewLedger(WithPath(path))
	const goroutines = 8
	const recordsPerGoroutine = 200

	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < recordsPerGoroutine; i++ {
				role := fmt.Sprintf("role-%02d-%03d", g, i)
				ledger.Record(Verdict{
					Code: uid9RoleCode(i),
					Role: role,
					Prev: Fingerprint{Version: int64(i)},
					Seen: Fingerprint{Version: int64(i + 1)},
				})
				if err := ledger.Flush(); err != nil {
					t.Errorf("Flush: %v", err)
					return
				}
			}
		}(g)
	}
	wg.Wait()

	vs := ledger.Violations()
	want := goroutines * recordsPerGoroutine
	if len(vs) != want {
		t.Fatalf("Violations count = %d, want %d", len(vs), want)
	}
	seen := make(map[string]struct{}, want)
	for _, v := range vs {
		if _, ok := seen[v.Role]; ok {
			t.Fatalf("duplicate violation role %q", v.Role)
		}
		seen[v.Role] = struct{}{}
	}
}

// RoleCodeForTest keeps the concurrency fixture obviously violation-valued
// while leaving a small test seam if the code set changes.
func uid9RoleCode(i int) Code {
	_ = i
	return CodeRollback
}

func TestUID9StoreDeterministicBytes(t *testing.T) {
	ref := time.Date(2026, time.November, 26, 12, 0, 0, 1, time.UTC)
	dir := t.TempDir()

	build := func(path string, reverse bool) error {
		l := NewLedger(WithPath(path))
		names := make([]int, 64)
		for i := range names {
			if reverse {
				names[i] = 63 - i
			} else {
				names[i] = i
			}
		}
		for _, i := range names {
			role := fmt.Sprintf("role-%02d", i)
			fp := Fingerprint{Role: role, Parent: "parent", Version: int64(i + 1), Expires: ref}
			l.Record(Verdict{Code: CodeAccept, Role: role, Parent: "parent", Seen: fp, Stored: true, RefTime: ref})
			l.Record(Verdict{
				Code: CodeRollback, Role: role, Parent: "parent",
				Prev: Fingerprint{Version: int64(i + 1)},
				Seen: Fingerprint{Version: int64(i)}, RefTime: ref,
			})
		}
		return l.Flush()
	}

	var firstHash [32]byte
	for repeat := 0; repeat < 100; repeat++ {
		path := filepath.Join(dir, fmt.Sprintf("deterministic-%03d.json", repeat))
		if err := build(path, false); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		hash := sha256.Sum256(data)
		if repeat == 0 {
			firstHash = hash
		} else if hash != firstHash {
			t.Fatalf("repeat %d produced different bytes", repeat)
		}
	}

	for _, reverse := range []bool{false, true} {
		path := filepath.Join(dir, fmt.Sprintf("order-%v.json", reverse))
		if err := build(path, reverse); err != nil {
			t.Fatal(err)
		}
	}
	forward, err := os.ReadFile(filepath.Join(dir, "order-false.json"))
	if err != nil {
		t.Fatal(err)
	}
	reverseBytes, err := os.ReadFile(filepath.Join(dir, "order-true.json"))
	if err != nil {
		t.Fatal(err)
	}
	if sha256.Sum256(forward) != sha256.Sum256(reverseBytes) {
		t.Fatal("output depends on insertion order")
	}
}
