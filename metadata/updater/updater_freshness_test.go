package updater

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/theupdateframework/go-tuf/v2/internal/testutils/simulator"
	"github.com/theupdateframework/go-tuf/v2/metadata"
	"github.com/theupdateframework/go-tuf/v2/metadata/freshness"
)

func uid9FreshUpdater(t *testing.T, repo *simulator.TestRepository, ledger *freshness.Ledger) *Updater {
	t.Helper()
	cfg, err := repo.GetUpdaterConfig()
	require.NoError(t, err)
	cfg.Freshness = ledger
	up, err := New(cfg)
	require.NoError(t, err)
	return up
}

func uid9Ledger(t *testing.T) *freshness.Ledger {
	return freshness.NewLedger(freshness.WithPath(filepath.Join(t.TempDir(), "freshness.json")))
}

func uid9Codes(ledger *freshness.Ledger, code freshness.Code) []freshness.Verdict {
	var out []freshness.Verdict
	for _, v := range ledger.Violations() {
		if v.Code == code {
			out = append(out, v)
		}
	}
	return out
}

func TestUID9FreshnessTimestampRollback(t *testing.T) {
	repo := simulator.NewTestRepository(t)
	ledger := uid9Ledger(t)
	repo.SetVersion(metadata.TIMESTAMP, 3)

	up := uid9FreshUpdater(t, repo, ledger)
	require.NoError(t, up.Refresh())
	trusted, ok := ledger.LastSeen(metadata.TIMESTAMP, "")
	require.True(t, ok)
	require.EqualValues(t, 3, trusted.Version)

	repo.SetVersion(metadata.TIMESTAMP, 2)
	up2 := uid9FreshUpdater(t, repo, ledger)
	err := up2.Refresh()
	require.Error(t, err)
	assert.ErrorIs(t, err, &metadata.ErrBadVersionNumber{})
	assert.ErrorContains(t, err, "new timestamp version 2 must be >= 3")

	rollbacks := uid9Codes(ledger, freshness.CodeRollback)
	require.Len(t, rollbacks, 1)
	v := rollbacks[0]
	assert.Equal(t, metadata.TIMESTAMP, v.Role)
	assert.EqualValues(t, 3, v.Prev.Version)
	assert.EqualValues(t, 2, v.Seen.Version)
	assert.False(t, v.Stored)

	last, ok := ledger.LastSeen(metadata.TIMESTAMP, "")
	require.True(t, ok)
	assert.EqualValues(t, 3, last.Version)
	assert.EqualValues(t, 3, up2.GetTrustedMetadataSet().Timestamp.Signed.Version)
}

func TestUID9FreshnessTimestampEqualAndDivergent(t *testing.T) {
	t.Run("equal", func(t *testing.T) {
		repo := simulator.NewTestRepository(t)
		ledger := uid9Ledger(t)
		repo.SetVersion(metadata.TIMESTAMP, 3)
		require.NoError(t, uid9FreshUpdater(t, repo, ledger).Refresh())

		require.NoError(t, uid9FreshUpdater(t, repo, ledger).Refresh())
		assert.Empty(t, ledger.Violations())
		last, ok := ledger.LastSeen(metadata.TIMESTAMP, "")
		require.True(t, ok)
		assert.EqualValues(t, 3, last.Version)
	})

	t.Run("equal divergent snapshot meta", func(t *testing.T) {
		repo := simulator.NewTestRepository(t)
		ledger := uid9Ledger(t)
		repo.SetVersion(metadata.TIMESTAMP, 3)
		require.NoError(t, uid9FreshUpdater(t, repo, ledger).Refresh())

		meta := repo.Simulator.MDTimestamp.Signed.Meta["snapshot.json"]
		require.NotNil(t, meta)
		meta.Version = 2
		meta.Length = 1234
		meta.Hashes = metadata.Hashes{"sha256": []byte("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")}

		require.NoError(t, uid9FreshUpdater(t, repo, ledger).Refresh())
		divergent := uid9Codes(ledger, freshness.CodeEqualDivergent)
		require.Len(t, divergent, 1)
		assert.True(t, divergent[0].Divergent)
		assert.EqualValues(t, 3, divergent[0].Seen.Version)
		require.Len(t, divergent[0].Prev.Meta, 1)
		require.Len(t, divergent[0].Seen.Meta, 1)
		assert.EqualValues(t, 2, divergent[0].Seen.Meta[0].Version)
		assert.EqualValues(t, 1234, divergent[0].Seen.Meta[0].Length)
		assert.Len(t, ledger.Violations(), 1)
	})
}

func TestUID9FreshnessTimestampSnapshotMetaRollback(t *testing.T) {
	repo := simulator.NewTestRepository(t)
	ledger := uid9Ledger(t)

	repo.SetVersion(metadata.SNAPSHOT, 3)
	repo.SetTimestampSnapshotMeta(3)
	repo.SetVersion(metadata.TIMESTAMP, 3)
	require.NoError(t, uid9FreshUpdater(t, repo, ledger).Refresh())

	repo.SetVersion(metadata.TIMESTAMP, 4)
	repo.SetTimestampSnapshotMeta(2)

	up := uid9FreshUpdater(t, repo, ledger)
	err := up.Refresh()
	require.Error(t, err)
	assert.ErrorIs(t, err, &metadata.ErrBadVersionNumber{})
	assert.ErrorContains(t, err, "new snapshot version 2 must be >= 3")

	rollbacks := uid9Codes(ledger, freshness.CodeRollback)
	require.Len(t, rollbacks, 1)
	v := rollbacks[0]
	assert.Equal(t, metadata.TIMESTAMP, v.Role)
	assert.False(t, v.Stored)
	require.NotEmpty(t, v.Prev.Meta)
	require.NotEmpty(t, v.Seen.Meta)
	assert.EqualValues(t, 3, v.Prev.Meta[0].Version)
	assert.EqualValues(t, 2, v.Seen.Meta[0].Version)
	assert.EqualValues(t, 3, up.GetTrustedMetadataSet().Timestamp.Signed.Version)
}

func TestUID9FreshnessSnapshotMetaRemoval(t *testing.T) {
	repo := simulator.NewTestRepository(t)
	ledger := uid9Ledger(t)

	// Add deterministic extra entries to the initial snapshot so the attack
	// can remove two names and verify lexicographic per-entry records.
	repo.Simulator.MDSnapshot.Signed.Meta["a-role.json"] = &metadata.MetaFiles{Version: 1}
	require.NoError(t, uid9FreshUpdater(t, repo, ledger).Refresh())

	repo.UpdateSnapshot()
	delete(repo.Simulator.MDSnapshot.Signed.Meta, "a-role.json")
	delete(repo.Simulator.MDSnapshot.Signed.Meta, "targets.json")

	up := uid9FreshUpdater(t, repo, ledger)
	err := up.Refresh()
	require.Error(t, err)
	assert.ErrorIs(t, err, &metadata.ErrRepository{})

	removals := uid9Codes(ledger, freshness.CodeMetaRemoval)
	require.Len(t, removals, 2)
	assert.Equal(t, "a-role.json", removals[0].Reason)
	assert.Equal(t, "targets.json", removals[1].Reason)
	for _, v := range removals {
		assert.Equal(t, metadata.SNAPSHOT, v.Role)
		assert.False(t, v.Stored)
		assert.EqualValues(t, 1, v.Prev.Version)
		assert.EqualValues(t, 2, v.Seen.Version)
	}
	assert.EqualValues(t, 1, up.GetTrustedMetadataSet().Snapshot.Signed.Version)
}

func TestUID9FreshnessRootPathVersionMismatchRollback(t *testing.T) {
	repo := simulator.NewTestRepository(t)
	ledger := uid9Ledger(t)
	for range 4 {
		repo.BumpVersion(metadata.ROOT)
	}
	require.Len(t, repo.Simulator.SignedRoots, 5)
	require.NoError(t, uid9FreshUpdater(t, repo, ledger).Refresh())
	rootFP, ok := ledger.LastSeen(metadata.ROOT, "")
	require.True(t, ok)
	assert.EqualValues(t, 5, rootFP.Version)

	// Requested 6.root.json maps to index 5; serve the previously published
	// root version 3 at that path.
	repo.Simulator.SignedRoots = append(repo.Simulator.SignedRoots, repo.Simulator.SignedRoots[2])

	up := uid9FreshUpdater(t, repo, ledger)
	err := up.Refresh()
	require.Error(t, err)
	assert.ErrorIs(t, err, &metadata.ErrBadVersionNumber{})

	rollbacks := uid9Codes(ledger, freshness.CodeRollback)
	require.Len(t, rollbacks, 1)
	v := rollbacks[0]
	assert.Equal(t, metadata.ROOT, v.Role)
	assert.EqualValues(t, 5, v.Prev.Version)
	assert.EqualValues(t, 3, v.Seen.Version)
	assert.False(t, v.Stored)
}

func TestUID9FreshnessRoot404WritesNoVerdict(t *testing.T) {
	repo := simulator.NewTestRepository(t)
	ledger := uid9Ledger(t)
	up := uid9FreshUpdater(t, repo, ledger)
	require.NoError(t, up.Refresh())

	for _, v := range ledger.Violations() {
		assert.NotEqual(t, metadata.ROOT, v.Role)
	}
}

func TestUID9FreshnessFinalRootExpired(t *testing.T) {
	repo := simulator.NewTestRepository(t)
	ledger := uid9Ledger(t)

	repo.BumpVersion(metadata.ROOT) // root version 2
	repo.SetExpired(metadata.ROOT)
	repo.PublishRoot() // temporarily append expired v2
	roots := repo.Simulator.SignedRoots
	roots[1] = roots[len(roots)-1]
	repo.Simulator.SignedRoots = roots[:2]
	require.NoError(t, repo.WriteRoot(2))

	up := uid9FreshUpdater(t, repo, ledger)
	err := up.Refresh()
	require.Error(t, err)
	assert.ErrorIs(t, err, &metadata.ErrExpiredMetadata{})
	assert.ErrorContains(t, err, "final root.json is expired")

	expired := uid9Codes(ledger, freshness.CodeExpired)
	require.Len(t, expired, 1)
	v := expired[0]
	assert.Equal(t, metadata.ROOT, v.Role)
	assert.EqualValues(t, 2, v.Seen.Version)
	assert.False(t, v.Stored)
	assert.False(t, v.Seen.Expires.IsZero())
	for _, candidate := range ledger.Violations() {
		assert.NotEqual(t, metadata.TIMESTAMP, candidate.Role)
	}
}

func TestUID9FreshnessIntermediateExpiredRootAccepts(t *testing.T) {
	repo := simulator.NewTestRepository(t)
	ledger := uid9Ledger(t)

	repo.BumpVersion(metadata.ROOT) // v2
	repo.SetExpired(metadata.ROOT)
	repo.PublishRoot() // expired v2 temporary last entry
	roots := repo.Simulator.SignedRoots
	roots[1] = roots[len(roots)-1]
	repo.Simulator.SignedRoots = roots[:2]

	repo.Simulator.MDRoot.Signed.Version = 3
	repo.SetExpiresAt(metadata.ROOT, repo.Simulator.SafeExpiry)
	repo.PublishRoot()

	up := uid9FreshUpdater(t, repo, ledger)
	err := up.Refresh()
	require.NoError(t, err)
	assert.EqualValues(t, 3, up.GetTrustedMetadataSet().Root.Signed.Version)
	assert.Empty(t, uid9Codes(ledger, freshness.CodeExpired))
}

func TestUID9FreshnessExpiredTimestampStoredThenRecover(t *testing.T) {
	repo := simulator.NewTestRepository(t)
	ledger := uid9Ledger(t)
	require.NoError(t, uid9FreshUpdater(t, repo, ledger).Refresh())

	repo.SetVersion(metadata.TIMESTAMP, 2)
	repo.SetExpired(metadata.TIMESTAMP)
	err := uid9FreshUpdater(t, repo, ledger).Refresh()
	require.Error(t, err)
	assert.ErrorIs(t, err, &metadata.ErrExpiredMetadata{})

	expired := uid9Codes(ledger, freshness.CodeExpired)
	require.Len(t, expired, 1)
	assert.Equal(t, metadata.TIMESTAMP, expired[0].Role)
	assert.True(t, expired[0].Stored)
	last, ok := ledger.LastSeen(metadata.TIMESTAMP, "")
	require.True(t, ok)
	assert.EqualValues(t, 2, last.Version)

	repo.SetVersion(metadata.TIMESTAMP, 3)
	repo.SetExpiresAt(metadata.TIMESTAMP, repo.Simulator.SafeExpiry)
	up := uid9FreshUpdater(t, repo, ledger)
	require.NoError(t, up.Refresh())
	assert.EqualValues(t, 3, up.GetTrustedMetadataSet().Timestamp.Signed.Version)
	last, ok = ledger.LastSeen(metadata.TIMESTAMP, "")
	require.True(t, ok)
	assert.EqualValues(t, 3, last.Version)
	require.Len(t, uid9Codes(ledger, freshness.CodeExpired), 1)
}

func TestUID9FreshnessExpiredTargetsNotStored(t *testing.T) {
	repo := simulator.NewTestRepository(t)
	ledger := uid9Ledger(t)
	require.NoError(t, uid9FreshUpdater(t, repo, ledger).Refresh())

	// Advance the remote targets and snapshot pins so the stale local copy is
	// bypassed; then expire the new candidate before it enters the trusted set.
	repo.BumpVersion(metadata.TARGETS)
	repo.UpdateSnapshot()
	repo.SetExpired(metadata.TARGETS)
	up := uid9FreshUpdater(t, repo, ledger)
	err := up.Refresh()
	require.Error(t, err)
	assert.ErrorIs(t, err, &metadata.ErrExpiredMetadata{})

	expired := uid9Codes(ledger, freshness.CodeExpired)
	require.Len(t, expired, 1)
	v := expired[0]
	assert.Equal(t, metadata.TARGETS, v.Role)
	assert.Equal(t, metadata.ROOT, v.Parent)
	assert.False(t, v.Stored)
	last, ok := ledger.LastSeen(metadata.TARGETS, metadata.ROOT)
	require.True(t, ok)
	assert.EqualValues(t, 1, last.Version)
}

func TestUID9FreshnessExpiredDelegatedRoleNotStored(t *testing.T) {
	repo := simulator.NewTestRepository(t)
	ledger := uid9Ledger(t)
	delegate(repo, metadata.TARGETS, "parent-a", "x/*")
	repo.AddTarget("parent-a", []byte("data"), "x/file")
	repo.UpdateSnapshot()

	up := uid9FreshUpdater(t, repo, ledger)
	require.NoError(t, up.Refresh())
	info, err := up.GetTargetInfo("x/file")
	require.NoError(t, err)
	require.NotNil(t, info)
	fp, ok := ledger.LastSeen("parent-a", metadata.TARGETS)
	require.True(t, ok)
	assert.EqualValues(t, 1, fp.Version)

	delegatedMD := repo.Simulator.MDDelegates["parent-a"]
	delegatedMD.Signed.Version = 2
	repo.Simulator.MDDelegates["parent-a"] = delegatedMD
	repo.UpdateSnapshot()
	delegatedMD = repo.Simulator.MDDelegates["parent-a"]
	delegatedMD.Signed.Expires = repo.PastTime()
	repo.Simulator.MDDelegates["parent-a"] = delegatedMD

	up2 := uid9FreshUpdater(t, repo, ledger)
	require.NoError(t, up2.Refresh())
	_, err = up2.GetTargetInfo("x/file")
	require.Error(t, err)
	assert.ErrorIs(t, err, &metadata.ErrExpiredMetadata{})

	expired := uid9Codes(ledger, freshness.CodeExpired)
	var delegated []freshness.Verdict
	for _, v := range expired {
		if v.Role == "parent-a" && v.Parent == metadata.TARGETS {
			delegated = append(delegated, v)
		}
	}
	require.Len(t, delegated, 1)
	assert.False(t, delegated[0].Stored)
	fp, ok = ledger.LastSeen("parent-a", metadata.TARGETS)
	require.True(t, ok)
	assert.EqualValues(t, 1, fp.Version)
}

func TestUID9FreshnessSharedRoleParentKeys(t *testing.T) {
	repo, _, _ := setupSharedRole(t)
	ledger := uid9Ledger(t)
	repo.AddTarget("shared", []byte("a"), "a/file")
	repo.AddTarget("shared", []byte("b"), "b/file")
	repo.UpdateSnapshot()

	up := uid9FreshUpdater(t, repo, ledger)
	require.NoError(t, up.Refresh())
	_, err := up.GetTargetInfo("a/file")
	require.NoError(t, err)
	_, err = up.GetTargetInfo("b/file")
	require.NoError(t, err)

	fpA, okA := ledger.LastSeen("shared", "parent-a")
	fpB, okB := ledger.LastSeen("shared", "parent-b")
	require.True(t, okA)
	require.True(t, okB)
	assert.EqualValues(t, 1, fpA.Version)
	assert.EqualValues(t, 1, fpB.Version)

	// A later rejection under parent-a must classify against parent-a's Prev,
	// not parent-b's state.
	rejected := ledger.Classify(
		"shared", "parent-a",
		freshness.Fingerprint{Version: 0},
		false, up.trusted.RefTime,
		&metadata.ErrBadVersionNumber{Msg: "test rollback"},
	)
	assert.Equal(t, freshness.CodeRollback, rejected.Code)
	assert.EqualValues(t, 1, rejected.Prev.Version)
}

func TestUID9FreshnessDisabledLocalCacheDoesNotFlush(t *testing.T) {
	repo := simulator.NewTestRepository(t)
	path := filepath.Join(t.TempDir(), "freshness.json")
	ledger := freshness.NewLedger(freshness.WithPath(path))
	cfg, err := repo.GetUpdaterConfig()
	require.NoError(t, err)
	cfg.Freshness = ledger
	cfg.DisableLocalCache = true
	up, err := New(cfg)
	require.NoError(t, err)
	require.NoError(t, up.Refresh())
	_, statErr := os.Stat(path)
	assert.ErrorIs(t, statErr, os.ErrNotExist)
}

func TestUID9FreshnessRefTimeBoundaryThroughUpdater(t *testing.T) {
	expires := time.Date(2027, time.January, 1, 0, 0, 0, 0, time.UTC)
	prepareRoot := func(t *testing.T, repo *simulator.TestRepository) {
		t.Helper()
		later := expires.Add(time.Hour)
		repo.SetExpiresAt(metadata.ROOT, later)
		repo.SetExpiresAt(metadata.SNAPSHOT, later)
		repo.SetExpiresAt(metadata.TARGETS, later)
		repo.PublishRoot()
		roots := repo.Simulator.SignedRoots
		roots[0] = roots[len(roots)-1]
		repo.Simulator.SignedRoots = roots[:1]
		require.NoError(t, os.WriteFile(filepath.Join(repo.MetadataDir, "root.json"), roots[0], 0o644))
	}

	t.Run("equal is not expired", func(t *testing.T) {
		repo := simulator.NewTestRepository(t)
		ledger := uid9Ledger(t)
		prepareRoot(t, repo)
		repo.SetExpiresAt(metadata.TIMESTAMP, expires)
		up := uid9FreshUpdater(t, repo, ledger)
		up.UnsafeSetRefTime(expires)
		require.NoError(t, up.Refresh())
		assert.Empty(t, uid9Codes(ledger, freshness.CodeExpired))
	})

	t.Run("one nanosecond after is expired", func(t *testing.T) {
		repo := simulator.NewTestRepository(t)
		ledger := uid9Ledger(t)
		prepareRoot(t, repo)
		repo.SetVersion(metadata.TIMESTAMP, 2)
		repo.SetExpiresAt(metadata.TIMESTAMP, expires)
		up := uid9FreshUpdater(t, repo, ledger)
		up.UnsafeSetRefTime(expires.Add(time.Nanosecond))
		err := up.Refresh()
		require.Error(t, err)
		assert.ErrorIs(t, err, &metadata.ErrExpiredMetadata{})
		expired := uid9Codes(ledger, freshness.CodeExpired)
		require.Len(t, expired, 1)
		assert.Equal(t, metadata.TIMESTAMP, expired[0].Role)
	})
}

func TestUID9FreshnessTrustResetOnRootAdvance(t *testing.T) {
	repo := simulator.NewTestRepository(t)
	ledger := uid9Ledger(t)
	repo.Simulator.MDTimestamp.Signed.Version = 99999
	require.NoError(t, uid9FreshUpdater(t, repo, ledger).Refresh())
	_, ok := ledger.LastSeen(metadata.TIMESTAMP, "")
	require.True(t, ok)

	repo.RotateKeys(metadata.TIMESTAMP)
	repo.BumpVersion(metadata.ROOT) // root v2
	repo.Simulator.MDTimestamp.Signed.Version = 1

	up := uid9FreshUpdater(t, repo, ledger)
	require.NoError(t, up.Refresh())
	assert.EqualValues(t, 1, up.GetTrustedMetadataSet().Timestamp.Signed.Version)

	resets := uid9Codes(ledger, freshness.CodeTrustReset)
	require.Len(t, resets, 1)
	reset := resets[0]
	assert.True(t, reset.Stored)
	assert.Contains(t, reset.Reason, "1")
	assert.Contains(t, reset.Reason, "2")
	_, ok = ledger.LastSeen(metadata.TIMESTAMP, "")
	require.True(t, ok)
	ts, _ := ledger.LastSeen(metadata.TIMESTAMP, "")
	assert.EqualValues(t, 1, ts.Version)
}

func TestUID9FreshnessNoRootAdvanceKeepsRollback(t *testing.T) {
	repo := simulator.NewTestRepository(t)
	ledger := uid9Ledger(t)
	repo.Simulator.MDTimestamp.Signed.Version = 99999
	require.NoError(t, uid9FreshUpdater(t, repo, ledger).Refresh())

	repo.Simulator.MDTimestamp.Signed.Version = 1
	up := uid9FreshUpdater(t, repo, ledger)
	err := up.Refresh()
	require.Error(t, err)
	assert.ErrorIs(t, err, &metadata.ErrBadVersionNumber{})
	assert.Empty(t, uid9Codes(ledger, freshness.CodeTrustReset))
	require.NotEmpty(t, uid9Codes(ledger, freshness.CodeRollback))
}
