// Copyright 2026 flannel authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package lease

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

const fileStateVersion = 1

type persistedState struct {
	Version int      `json:"version"`
	Records []Record `json:"records"`
}

// FileStore atomically persists allocation records as JSON.
type FileStore struct {
	path string
}

// NewFileStore creates a Store backed by path.
func NewFileStore(path string) *FileStore {
	return &FileStore{path: path}
}

// Path returns the configured state file path.
func (s *FileStore) Path() string { return s.path }

// Load reads records. A missing file is treated as an empty state.
func (s *FileStore) Load(ctx context.Context) ([]Record, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return []Record{}, nil
		}
		return nil, fmt.Errorf("read %s: %w", s.path, err)
	}
	if len(data) == 0 {
		return []Record{}, nil
	}

	var state persistedState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("parse %s: %w", s.path, err)
	}
	return state.Records, nil
}

// Save writes to a temp file in the same directory, fsyncs it and renames it
// over path so a crash cannot leave a partially written allocation record.
func (s *FileStore) Save(ctx context.Context, records []Record) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.path == "" {
		return errors.New("lease file store path is empty")
	}

	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create state directory %s: %w", dir, err)
	}

	state := persistedState{Version: fileStateVersion, Records: records}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}

	tmp, err := os.CreateTemp(dir, ".lease-state-*.json.tmp")
	if err != nil {
		return fmt.Errorf("create temp state file: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp state file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync temp state file: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temp state file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp state file: %w", err)
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		return fmt.Errorf("rename state file into place: %w", err)
	}
	cleanup = false

	// Best-effort directory fsync makes the rename durable across power loss.
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// MemoryStore is a concurrency-safe in-memory Store, useful in tests. Its zero
// value is ready to use.
type MemoryStore struct {
	mu      sync.Mutex
	records []Record
}

// NewMemoryStore creates an empty in-memory Store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{}
}

// Load returns a copy of stored records.
func (s *MemoryStore) Load(context.Context) ([]Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Record, len(s.records))
	copy(out, s.records)
	return out, nil
}

// Save replaces stored records.
func (s *MemoryStore) Save(_ context.Context, records []Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records = make([]Record, len(records))
	copy(s.records, records)
	return nil
}
