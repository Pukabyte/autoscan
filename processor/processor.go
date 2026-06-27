package processor

import (
	"database/sql"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/saltydk/autoscan"
	"github.com/saltydk/autoscan/migrate"
)

type Config struct {
	Anchors    []string
	MinimumAge time.Duration

	Db *sql.DB
	Mg *migrate.Migrator
}

// RegisteredTarget wraps a Target with a stable ID used to track per-target scan completion.
type RegisteredTarget struct {
	ID     string
	Target autoscan.Target
}

func New(c Config) (*Processor, error) {
	store, err := newDatastore(c.Db, c.Mg)
	if err != nil {
		return nil, err
	}

	return &Processor{
		anchors:    c.Anchors,
		minimumAge: c.MinimumAge,
		store:      store,
	}, nil
}

type Processor struct {
	anchors    []string
	minimumAge time.Duration
	store      *datastore
	processed  int64

	mu      sync.RWMutex
	targets []RegisteredTarget
}

// Register sets the targets the processor will dispatch scans to.
// Must be called before triggers start adding scans.
func (p *Processor) Register(targets []RegisteredTarget) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.targets = targets
}

func (p *Processor) targetIDs() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	ids := make([]string, len(p.targets))
	for i, t := range p.targets {
		ids[i] = t.ID
	}
	return ids
}

func (p *Processor) Add(scans ...autoscan.Scan) error {
	if err := p.store.Upsert(scans); err != nil {
		return err
	}
	ids := p.targetIDs()
	if len(ids) == 0 {
		return nil
	}
	for _, scan := range scans {
		if err := p.store.InsertScanTargets(scan.Folder, ids); err != nil {
			return err
		}
	}
	return nil
}

// ScansRemaining returns the amount of scans remaining.
func (p *Processor) ScansRemaining() (int, error) {
	return p.store.GetScansRemaining()
}

// ScansProcessed returns the amount of scans processed.
func (p *Processor) ScansProcessed() int64 {
	return atomic.LoadInt64(&p.processed)
}

// CheckAvailability returns nil if at least one registered target is reachable.
func (p *Processor) CheckAvailability() error {
	p.mu.RLock()
	targets := p.targets
	p.mu.RUnlock()

	var lastErr error
	for _, t := range targets {
		if err := t.Target.Available(); err == nil {
			return nil
		} else {
			lastErr = err
		}
	}
	return lastErr
}

func (p *Processor) Process() error {
	scan, err := p.store.GetAvailableScan(p.minimumAge)
	if err != nil {
		return err
	}

	for _, anchor := range p.anchors {
		if !fileExists(anchor) {
			return fmt.Errorf("%s: %w", anchor, autoscan.ErrAnchorUnavailable)
		}
	}

	pendingIDs, err := p.store.GetPendingTargetIDs(scan.Folder)
	if err != nil {
		return err
	}

	p.mu.RLock()
	targets := p.targets
	p.mu.RUnlock()

	// Populate scan_target rows for scans that arrived before Register() or legacy scans.
	if len(pendingIDs) == 0 {
		if len(targets) == 0 {
			return p.store.Delete(scan)
		}
		ids := make([]string, len(targets))
		for i, t := range targets {
			ids[i] = t.ID
		}
		if err := p.store.InsertScanTargets(scan.Folder, ids); err != nil {
			return err
		}
		pendingIDs = ids
	}

	pendingSet := make(map[string]struct{}, len(pendingIDs))
	for _, id := range pendingIDs {
		pendingSet[id] = struct{}{}
	}

	anySuccess := false
	anyFailure := false

	for _, rt := range targets {
		if _, pending := pendingSet[rt.ID]; !pending {
			continue
		}
		if err := rt.Target.Scan(scan); err != nil {
			log.Error().
				Err(err).
				Str("target", rt.ID).
				Str("folder", scan.Folder).
				Msg("Target scan failed, will retry")
			anyFailure = true
		} else {
			if err := p.store.CompleteScanTarget(scan.Folder, rt.ID); err != nil {
				return err
			}
			anySuccess = true
		}
	}

	remaining, err := p.store.GetPendingTargetIDs(scan.Folder)
	if err != nil {
		return err
	}

	if len(remaining) == 0 {
		if err := p.store.Delete(scan); err != nil {
			return err
		}
		atomic.AddInt64(&p.processed, 1)
	}

	if !anySuccess && anyFailure {
		return fmt.Errorf("all pending targets failed for %s: %w", scan.Folder, autoscan.ErrTargetUnavailable)
	}

	return nil
}

var fileExists = func(fileName string) bool {
	info, err := os.Stat(fileName)
	if err != nil {
		return false
	}
	return !info.IsDir()
}
