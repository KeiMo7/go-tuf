package freshness

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

type verdictDTO struct {
	Code      Code        `json:"code"`
	Role      string      `json:"role"`
	Parent    string      `json:"parent"`
	Prev      Fingerprint `json:"prev"`
	Seen      Fingerprint `json:"seen"`
	Stored    bool        `json:"stored"`
	Divergent bool        `json:"divergent"`
	RefTime   time.Time   `json:"ref_time"`
	Reason    string      `json:"reason"`
}

type warningDTO struct {
	Code Code   `json:"code"`
	Msg  string `json:"msg"`
}

type ledgerFileDTO struct {
	SchemaVersion int           `json:"schemaVersion"`
	LastSeen      []Fingerprint `json:"lastSeen"`
	Violations    []verdictDTO  `json:"violations"`
	Warnings      []warningDTO  `json:"warnings"`
}

// Load reads a JSON ledger. Corruption and unsupported schema versions put the
// ledger into its documented read-only degradation mode; the returned error
// also describes the failure.
func (l *Ledger) Load(reader io.Reader) error {
	if l == nil {
		return nil
	}
	data, err := io.ReadAll(reader)
	if err != nil {
		l.markCorrupt(err)
		return err
	}
	if len(data) == 0 {
		l.mu.Lock()
		l.resetStateLocked()
		l.mu.Unlock()
		return nil
	}

	var doc ledgerFileDTO
	if err := json.Unmarshal(data, &doc); err != nil {
		l.markCorrupt(err)
		return err
	}
	if doc.SchemaVersion > SupportedSchemaVersion {
		err := fmt.Errorf("%w: %d", ErrSchemaTooNew, doc.SchemaVersion)
		l.markSchemaTooNew(doc.SchemaVersion, err)
		return err
	}
	if doc.SchemaVersion == 0 {
		err := fmt.Errorf("freshness: schemaVersion is missing or zero in non-empty ledger")
		l.markCorrupt(err)
		return err
	}
	if doc.SchemaVersion != SupportedSchemaVersion {
		err := fmt.Errorf("freshness: unsupported schemaVersion %d", doc.SchemaVersion)
		l.markCorrupt(err)
		return err
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	// A previously degraded process-wide ledger remains read-only, but Load
	// can still expose the readable document supplied by the caller.
	l.resetStateLocked()
	for _, fp := range doc.LastSeen {
		fp = cloneFingerprint(fp)
		if !fp.Expires.IsZero() {
			fp.Expires = fp.Expires.UTC()
		}
		l.lastSeen[ledgerKey{Role: fp.Role, Parent: fp.Parent}] = fp
	}
	for _, vd := range doc.Violations {
		v := Verdict{
			Code:      vd.Code,
			Role:      vd.Role,
			Parent:    vd.Parent,
			Prev:      cloneFingerprint(vd.Prev),
			Seen:      cloneFingerprint(vd.Seen),
			Stored:    vd.Stored,
			Divergent: vd.Divergent,
			RefTime:   vd.RefTime.UTC(),
			Reason:    vd.Reason,
		}
		l.records = append(l.records, v)
		if v.Stored {
			l.lastSeen[ledgerKey{Role: v.Role, Parent: v.Parent}] = cloneFingerprint(v.Seen)
		}
	}
	for _, wd := range doc.Warnings {
		l.warnings = append(l.warnings, Warning{Code: wd.Code, Msg: wd.Msg})
	}
	return nil
}

// Flush atomically writes a deterministic JSON snapshot. It never blocks
// Classify/Record while performing filesystem I/O.
func (l *Ledger) Flush() error {
	if l == nil || l.path == "" {
		return nil
	}

	l.mu.Lock()
	if l.flushErr != nil {
		flushErr := l.flushErr
		l.mu.Unlock()
		if errors.Is(flushErr, ErrSchemaTooNew) {
			return ErrSchemaTooNew
		}
		return ErrDegradedReadOnly
	}
	doc := l.snapshotLocked()
	path := l.path
	l.mu.Unlock()

	payload, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		l.addFlushWarning(err)
		return err
	}
	payload = append(payload, '\n')

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		l.addFlushWarning(err)
		return err
	}

	tmp, err := os.CreateTemp(dir, ".freshness-ledger-*.tmp")
	if err != nil {
		l.addFlushWarning(err)
		return err
	}
	tmpName := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}

	if err := tmp.Chmod(0o600); err != nil {
		cleanup()
		l.addFlushWarning(err)
		return err
	}
	if _, err := tmp.Write(payload); err != nil {
		cleanup()
		l.addFlushWarning(err)
		return err
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		l.addFlushWarning(err)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		l.addFlushWarning(err)
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		l.addFlushWarning(err)
		return err
	}
	return nil
}

func (l *Ledger) snapshotLocked() ledgerFileDTO {
	keys := make([]ledgerKey, 0, len(l.lastSeen))
	for key := range l.lastSeen {
		keys = append(keys, key)
	}
	sortKeys(keys)

	lastSeen := make([]Fingerprint, 0, len(keys))
	for _, key := range keys {
		fp := cloneFingerprint(l.lastSeen[key])
		if !fp.Expires.IsZero() {
			fp.Expires = fp.Expires.UTC()
		}
		lastSeen = append(lastSeen, fp)
	}

	violations := make([]Verdict, 0, len(l.records))
	for _, v := range l.records {
		if violationCode(v.Code) {
			violations = append(violations, cloneVerdict(v))
		}
	}
	sortVerdicts(violations)

	violationDTOs := make([]verdictDTO, 0, len(violations))
	for _, v := range violations {
		vd := verdictDTO{
			Code:      v.Code,
			Role:      v.Role,
			Parent:    v.Parent,
			Prev:      cloneFingerprint(v.Prev),
			Seen:      cloneFingerprint(v.Seen),
			Stored:    v.Stored,
			Divergent: v.Divergent,
			RefTime:   v.RefTime.UTC(),
			Reason:    v.Reason,
		}
		if !vd.Prev.Expires.IsZero() {
			vd.Prev.Expires = vd.Prev.Expires.UTC()
		}
		if !vd.Seen.Expires.IsZero() {
			vd.Seen.Expires = vd.Seen.Expires.UTC()
		}
		violationDTOs = append(violationDTOs, vd)
	}

	warnings := make([]warningDTO, 0, len(l.warnings))
	for _, w := range l.warnings {
		warnings = append(warnings, warningDTO{Code: w.Code, Msg: w.Msg})
	}

	return ledgerFileDTO{
		SchemaVersion: SupportedSchemaVersion,
		LastSeen:      lastSeen,
		Violations:    violationDTOs,
		Warnings:      warnings,
	}
}

func sortKeys(keys []ledgerKey) {
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keyLess(keys[j], keys[j-1]); j-- {
			keys[j], keys[j-1] = keys[j-1], keys[j]
		}
	}
}

func keyLess(a, b ledgerKey) bool {
	if a.Role != b.Role {
		return a.Role < b.Role
	}
	return a.Parent < b.Parent
}

func (l *Ledger) resetStateLocked() {
	l.lastSeen = make(map[ledgerKey]Fingerprint)
	l.records = nil
	l.warnings = nil
}

func (l *Ledger) markCorrupt(err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.resetStateLocked()
	l.degraded = true
	l.flushErr = ErrDegradedReadOnly
	l.appendWarningLocked(Warning{Code: CodeWarning, Msg: "ledger unreadable", Err: err})
}

func (l *Ledger) markSchemaTooNew(version int, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.degraded = true
	if l.flushErr == nil {
		l.flushErr = ErrSchemaTooNew
	} else if !errors.Is(l.flushErr, ErrDegradedReadOnly) {
		l.flushErr = ErrSchemaTooNew
	}
	if !l.tooNewWarned {
		l.tooNewWarned = true
		l.appendWarningLocked(Warning{
			Code: CodeWarning,
			Msg:  fmt.Sprintf("ledger schemaVersion %d is newer than supported version %d", version, SupportedSchemaVersion),
			Err:  err,
		})
	}
}

func (l *Ledger) addFlushWarning(err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.appendWarningLocked(Warning{Code: CodeWarning, Msg: "ledger flush failed", Err: err})
}

func (l *Ledger) loadFromConfiguredPath() {
	file, err := os.Open(l.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return
		}
		l.mu.Lock()
		l.appendWarningLocked(Warning{Code: CodeWarning, Msg: "ledger open failed", Err: err})
		l.mu.Unlock()
		return
	}
	defer file.Close()
	_ = l.Load(file)
}
