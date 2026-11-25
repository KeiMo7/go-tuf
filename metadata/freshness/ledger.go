package freshness

import (
	"sync"
	"time"
)

type ledgerKey struct {
	Role   string
	Parent string
}

// Option configures a Ledger.
type Option func(*Ledger)

// Ledger is a concurrency-safe in-memory audit ledger with optional atomic
// JSON persistence. A zero Ledger must not be used directly; use NewLedger.
type Ledger struct {
	mu sync.Mutex

	path         string
	maxRecords   int
	maxWarnings  int
	degraded     bool
	flushErr     error
	tooNewWarned bool

	lastSeen map[ledgerKey]Fingerprint
	records  []Verdict
	warnings []Warning
}

// NewLedger creates a ledger. When WithPath names an existing file, that file
// is loaded immediately; a missing file starts empty.
func NewLedger(opts ...Option) *Ledger {
	l := &Ledger{
		maxRecords:  4096,
		maxWarnings: 256,
		lastSeen:    make(map[ledgerKey]Fingerprint),
	}
	for _, opt := range opts {
		if opt != nil {
			opt(l)
		}
	}
	if l.lastSeen == nil {
		l.lastSeen = make(map[ledgerKey]Fingerprint)
	}

	if l.path != "" {
		l.loadFromConfiguredPath()
	}
	return l
}

// WithPath configures the JSON file used by Flush.
func WithPath(path string) Option {
	return func(l *Ledger) { l.path = path }
}

// WithMaxViolations configures the soft cap for retained verdict records.
// Violation verdicts are never evicted; when the cap is exceeded the oldest
// non-violation records are discarded first.
func WithMaxViolations(n int) Option {
	return func(l *Ledger) { l.maxRecords = n }
}

// Classify builds a Verdict for seen using the LastSeen fingerprint for the
// same (role, parent) pair as Prev. It does not mutate the ledger.
func (l *Ledger) Classify(role, parent string, seen Fingerprint, stored bool, refTime time.Time, err error) Verdict {
	var prev Fingerprint
	havePrev := false
	if l != nil {
		prev, havePrev = l.LastSeen(role, parent)
	}

	seen.Role = role
	seen.Parent = parent
	if !seen.Expires.IsZero() {
		seen.Expires = seen.Expires.UTC()
	}

	code := codeFromError(err)
	// UpdateRoot intentionally does not check expiry: an expired intermediate
	// root can still validate the next root. Final-root expiry is reported by
	// UpdateTimestamp and arrives here as *metadata.ErrExpiredMetadata. For
	// other roles, callers may also ask Classify to evaluate the boundary
	// directly when no metadata error is present.
	if err == nil && role != "root" && !refTime.IsZero() && !seen.Expires.IsZero() && refTime.After(seen.Expires) {
		code = CodeExpired
	}

	divergent := false
	if code == CodeEqual && havePrev && !metaEqual(prev.Meta, seen.Meta) {
		code = CodeEqualDivergent
		divergent = true
	}

	if isBadVersionError(err) {
		// Root's consecutive-version check reports both a skipped rotation and
		// a rollback through ErrBadVersionNumber. A regression against the
		// last seen root is rollback; root path/version mismatches are also
		// rollback attempts in the audit model. Other roles with a newer seen
		// version but mismatch against pinned metadata are version mismatches.
		if role == "root" || fingerprintRegression(prev, seen) {
			code = CodeRollback
		} else {
			code = CodeVersionMismatch
		}
	}

	reason := ""
	if err != nil {
		reason = err.Error()
	}

	v := Verdict{
		Code:      code,
		Role:      role,
		Parent:    parent,
		Seen:      cloneFingerprint(seen),
		Stored:    stored,
		Divergent: divergent,
		RefTime:   refTime.UTC(),
		Reason:    reason,
		Err:       err,
	}
	if havePrev {
		v.Prev = cloneFingerprint(prev)
	}
	return v
}

// Record stores a verdict and advances LastSeen exactly when v.Stored is true.
// CodeTrustReset additionally removes timestamp and snapshot LastSeen entries.
func (l *Ledger) Record(v Verdict) {
	if l == nil {
		return
	}

	v = cloneVerdict(v)
	v.RefTime = v.RefTime.UTC()
	l.mu.Lock()
	defer l.mu.Unlock()

	if v.Code == CodeTrustReset {
		for key := range l.lastSeen {
			if key.Role == "timestamp" || key.Role == "snapshot" {
				delete(l.lastSeen, key)
			}
		}
	}

	if v.Stored {
		l.lastSeen[ledgerKey{Role: v.Role, Parent: v.Parent}] = cloneFingerprint(v.Seen)
	}

	l.records = append(l.records, v)
	l.enforceRecordLimitLocked()
}

// LastSeen returns a copy of the stored fingerprint for (role, parent).
func (l *Ledger) LastSeen(role, parent string) (Fingerprint, bool) {
	if l == nil {
		return Fingerprint{}, false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	fp, ok := l.lastSeen[ledgerKey{Role: role, Parent: parent}]
	if !ok {
		return Fingerprint{}, false
	}
	return cloneFingerprint(fp), true
}

// Violations returns sorted deep copies of all violation verdicts.
func (l *Ledger) Violations() []Verdict {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	out := make([]Verdict, 0, len(l.records))
	for _, v := range l.records {
		if violationCode(v.Code) {
			out = append(out, cloneVerdict(v))
		}
	}
	l.mu.Unlock()
	sortVerdicts(out)
	return out
}

// Warnings returns copies of all ledger warnings.
func (l *Ledger) Warnings() []Warning {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]Warning, len(l.warnings))
	copy(out, l.warnings)
	return out
}

// Degraded reports whether the ledger is permanently read-only in this process.
func (l *Ledger) Degraded() bool {
	if l == nil {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.degraded
}

func (l *Ledger) appendWarningLocked(w Warning) {
	if w.Code == CodeAccept {
		w.Code = CodeWarning
	}
	if l.maxWarnings > 0 && len(l.warnings) >= l.maxWarnings {
		l.warnings = append(l.warnings[1:], w)
		return
	}
	l.warnings = append(l.warnings, w)
}

func (l *Ledger) enforceRecordLimitLocked() {
	if l.maxRecords <= 0 {
		return
	}
	truncated := false
	for len(l.records) > l.maxRecords {
		oldestNonViolation := -1
		for i, v := range l.records {
			if !violationCode(v.Code) {
				oldestNonViolation = i
				break
			}
		}
		if oldestNonViolation == -1 {
			// Violations are never truncated.
			return
		}
		l.records = append(l.records[:oldestNonViolation], l.records[oldestNonViolation+1:]...)
		truncated = true
	}
	if truncated {
		l.appendWarningLocked(Warning{Code: CodeWarning, Msg: "ledger truncated"})
	}
}
