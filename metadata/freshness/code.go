package freshness

import (
	"reflect"
	"strings"
)

// Code identifies the deterministic audit classification of one metadata
// verification attempt.
type Code int

const (
	CodeAccept Code = iota
	CodeEqual
	CodeEqualDivergent
	CodeRollback
	CodeMetaRemoval
	CodeExpired
	CodeVersionMismatch
	CodeSignature
	CodeHashMismatch
	CodeRejected
	CodeTrustReset
	CodeWarning
)

// String returns the stable symbolic name of a code.
func (c Code) String() string {
	switch c {
	case CodeAccept:
		return "Accept"
	case CodeEqual:
		return "Equal"
	case CodeEqualDivergent:
		return "EqualDivergent"
	case CodeRollback:
		return "Rollback"
	case CodeMetaRemoval:
		return "MetaRemoval"
	case CodeExpired:
		return "Expired"
	case CodeVersionMismatch:
		return "VersionMismatch"
	case CodeSignature:
		return "Signature"
	case CodeHashMismatch:
		return "HashMismatch"
	case CodeRejected:
		return "Rejected"
	case CodeTrustReset:
		return "TrustReset"
	case CodeWarning:
		return "Warning"
	default:
		return "Unknown"
	}
}

// codeFromError classifies errors without importing github.com/theupdateframework/go-tuf/v2/metadata.
// The metadata package's exported error type names are part of its stable
// surface, so their concrete reflect type names provide the mapping while
// errors.As-style unwrapping preserves wrapped errors.
func codeFromError(err error) Code {
	if err == nil {
		return CodeAccept
	}

	visited := make(map[error]struct{})
	var classify func(error) Code
	classify = func(e error) Code {
		if e == nil {
			return CodeAccept
		}
		if _, ok := visited[e]; ok {
			return CodeRejected
		}
		visited[e] = struct{}{}

		name := concreteErrorTypeName(e)
		switch {
		case errorTypeNameIs(name, "ErrEqualVersionNumber"):
			return CodeEqual
		case errorTypeNameIs(name, "ErrExpiredMetadata"):
			return CodeExpired
		case errorTypeNameIs(name, "ErrUnsignedMetadata"):
			return CodeSignature
		case errorTypeNameIs(name, "ErrLengthOrHashMismatch"), errorTypeNameIs(name, "ErrDownloadLengthMismatch"):
			return CodeHashMismatch
		case errorTypeNameIs(name, "ErrBadVersionNumber"):
			return CodeRollback
		case errorTypeNameIs(name, "ErrRepository"):
			return CodeRejected
		}

		switch unwrapped := e.(type) {
		case interface{ Unwrap() error }:
			if cause := unwrapped.Unwrap(); cause != nil {
				if code := classify(cause); code != CodeAccept {
					return code
				}
			}
		case interface{ Unwrap() []error }:
			for _, cause := range unwrapped.Unwrap() {
				if code := classify(cause); code != CodeAccept {
					return code
				}
			}
		}
		return CodeRejected
	}

	return classify(err)
}

func concreteErrorTypeName(err error) string {
	t := reflect.TypeOf(err)
	if t == nil {
		return ""
	}
	for t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	return t.Name()
}

func errorTypeNameIs(name, want string) bool {
	return name == want || strings.HasSuffix(name, want)
}

func isBadVersionError(err error) bool {
	return codeFromError(err) == CodeRollback && containsErrorTypeName(err, "ErrBadVersionNumber")
}

func containsErrorTypeName(err error, want string) bool {
	visited := make(map[error]struct{})
	var walk func(error) bool
	walk = func(e error) bool {
		if e == nil {
			return false
		}
		if _, ok := visited[e]; ok {
			return false
		}
		visited[e] = struct{}{}
		if errorTypeNameIs(concreteErrorTypeName(e), want) {
			return true
		}
		if u, ok := e.(interface{ Unwrap() error }); ok {
			return walk(u.Unwrap())
		}
		if u, ok := e.(interface{ Unwrap() []error }); ok {
			for _, child := range u.Unwrap() {
				if walk(child) {
					return true
				}
			}
		}
		return false
	}
	return walk(err)
}
