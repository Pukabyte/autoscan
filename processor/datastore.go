package processor

import (
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"time"

	"github.com/saltydk/autoscan"
	"github.com/saltydk/autoscan/migrate"

	// sqlite3 driver
	_ "modernc.org/sqlite"
)

type datastore struct {
	*sql.DB
}

var (
	//go:embed migrations
	migrations embed.FS
)

func newDatastore(db *sql.DB, mg *migrate.Migrator) (*datastore, error) {
	// migrations
	if err := mg.Migrate(&migrations, "processor"); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}

	return &datastore{db}, nil
}

const sqlUpsert = `
INSERT INTO scan (folder, priority, time)
VALUES (?, ?, ?)
ON CONFLICT (folder) DO UPDATE SET
	priority = MAX(excluded.priority, scan.priority),
	time = excluded.time
`

func (store *datastore) upsert(tx *sql.Tx, scan autoscan.Scan) error {
	_, err := tx.Exec(sqlUpsert, scan.Folder, scan.Priority, scan.Time)
	return err
}

func (store *datastore) Upsert(scans []autoscan.Scan) error {
	tx, err := store.Begin()
	if err != nil {
		return err
	}

	for _, scan := range scans {
		if err = store.upsert(tx, scan); err != nil {
			if rollbackErr := tx.Rollback(); rollbackErr != nil {
				panic(rollbackErr)
			}

			return err
		}
	}

	return tx.Commit()
}

const sqlGetScansRemaining = `SELECT COUNT(folder) FROM scan`

func (store *datastore) GetScansRemaining() (int, error) {
	row := store.QueryRow(sqlGetScansRemaining)

	remaining := 0
	err := row.Scan(&remaining)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return remaining, nil
	case err != nil:
		return remaining, fmt.Errorf("get remaining scans: %v: %w", err, autoscan.ErrFatal)
	}

	return remaining, nil
}

const sqlGetAvailableScan = `
SELECT folder, priority, time FROM scan
WHERE time < ?
ORDER BY priority DESC, time ASC
LIMIT 1
`

func (store *datastore) GetAvailableScan(minAge time.Duration) (autoscan.Scan, error) {
	row := store.QueryRow(sqlGetAvailableScan, now().Add(-1*minAge))

	scan := autoscan.Scan{}
	err := row.Scan(&scan.Folder, &scan.Priority, &scan.Time)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return scan, autoscan.ErrNoScans
	case err != nil:
		return scan, fmt.Errorf("get matching: %s: %w", err, autoscan.ErrFatal)
	}

	return scan, nil
}

const sqlGetAll = `
SELECT folder, priority, time FROM scan
`

func (store *datastore) GetAll() (scans []autoscan.Scan, err error) {
	rows, err := store.Query(sqlGetAll)
	if err != nil {
		return scans, err
	}

	defer rows.Close()
	for rows.Next() {
		scan := autoscan.Scan{}
		err = rows.Scan(&scan.Folder, &scan.Priority, &scan.Time)
		if err != nil {
			return scans, err
		}

		scans = append(scans, scan)
	}

	return scans, rows.Err()
}

const sqlDelete = `
DELETE FROM scan WHERE folder=?
`

const sqlDeleteScanTargets = `
DELETE FROM scan_target WHERE folder=?
`

const sqlInsertScanTarget = `
INSERT OR IGNORE INTO scan_target (folder, target_id) VALUES (?, ?)
`

const sqlGetPendingTargetIDs = `
SELECT target_id FROM scan_target WHERE folder = ?
`

const sqlCompleteScanTarget = `
DELETE FROM scan_target WHERE folder = ? AND target_id = ?
`

func (store *datastore) Delete(scan autoscan.Scan) error {
	tx, err := store.Begin()
	if err != nil {
		return fmt.Errorf("delete begin: %s: %w", err, autoscan.ErrFatal)
	}

	if _, err := tx.Exec(sqlDeleteScanTargets, scan.Folder); err != nil {
		tx.Rollback()
		return fmt.Errorf("delete scan_targets: %s: %w", err, autoscan.ErrFatal)
	}

	if _, err := tx.Exec(sqlDelete, scan.Folder); err != nil {
		tx.Rollback()
		return fmt.Errorf("delete scan: %s: %w", err, autoscan.ErrFatal)
	}

	return tx.Commit()
}

func (store *datastore) InsertScanTargets(folder string, targetIDs []string) error {
	for _, id := range targetIDs {
		if _, err := store.Exec(sqlInsertScanTarget, folder, id); err != nil {
			return fmt.Errorf("insert scan_target: %s: %w", err, autoscan.ErrFatal)
		}
	}
	return nil
}

func (store *datastore) GetPendingTargetIDs(folder string) ([]string, error) {
	rows, err := store.Query(sqlGetPendingTargetIDs, folder)
	if err != nil {
		return nil, fmt.Errorf("get pending targets: %s: %w", err, autoscan.ErrFatal)
	}
	defer rows.Close()

	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan pending target: %s: %w", err, autoscan.ErrFatal)
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func (store *datastore) CompleteScanTarget(folder, targetID string) error {
	_, err := store.Exec(sqlCompleteScanTarget, folder, targetID)
	if err != nil {
		return fmt.Errorf("complete scan_target: %s: %w", err, autoscan.ErrFatal)
	}
	return nil
}

const sqlPushScanToBack = `UPDATE scan SET time = ? WHERE folder = ?`

// PushScanToBack resets a scan's time to now so it re-enters the minimum-age
// queue, allowing other scans to advance when all targets for this scan fail.
func (store *datastore) PushScanToBack(folder string) error {
	_, err := store.Exec(sqlPushScanToBack, now(), folder)
	if err != nil {
		return fmt.Errorf("push scan to back: %s: %w", err, autoscan.ErrFatal)
	}
	return nil
}

const sqlEnsureTargetInAllScans = `
INSERT OR IGNORE INTO scan_target (folder, target_id)
SELECT folder, ? FROM scan
`

// EnsureTargetInAllScans inserts a pending scan_target row for the given target
// across all existing scans that don't already have one.
func (store *datastore) EnsureTargetInAllScans(targetID string) error {
	_, err := store.Exec(sqlEnsureTargetInAllScans, targetID)
	if err != nil {
		return fmt.Errorf("ensure target in all scans: %s: %w", err, autoscan.ErrFatal)
	}
	return nil
}

var now = time.Now
