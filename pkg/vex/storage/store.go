package storage

import (
	"sync"

	"github.com/kubescape/kubevuln/pkg/vex/parser"
)

// VEXStore is a thread-safe in-memory store for ingested VEX statements.
type VEXStore struct {
	mu         sync.RWMutex
	statements map[string][]parser.VEXStatement // sourceKey (e.g. namespace/name) -> statements
}

// NewVEXStore creates a new VEXStore instance.
func NewVEXStore() *VEXStore {
	return &VEXStore{
		statements: make(map[string][]parser.VEXStatement),
	}
}

// SetStatements updates the VEX statements for a given source key.
func (s *VEXStore) SetStatements(sourceKey string, statements []parser.VEXStatement) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.statements[sourceKey] = statements
}

// DeleteStatements removes statements for a deleted VEXSource.
func (s *VEXStore) DeleteStatements(sourceKey string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.statements, sourceKey)
}

// GetAllStatements aggregates all stored VEX statements across all active sources.
func (s *VEXStore) GetAllStatements() []parser.VEXStatement {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var all []parser.VEXStatement
	for _, stmts := range s.statements {
		all = append(all, stmts...)
	}
	return all
}
