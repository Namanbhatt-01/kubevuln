package storage

import (
	"testing"

	"github.com/kubescape/kubevuln/pkg/vex/parser"
	"github.com/stretchr/testify/assert"
)

func TestVEXStore_ThreadSafeOperations(t *testing.T) {
	store := NewVEXStore()

	stmts1 := []parser.VEXStatement{
		{CVE: "CVE-2026-0001", Status: "not_affected"},
	}
	stmts2 := []parser.VEXStatement{
		{CVE: "CVE-2026-0002", Status: "fixed"},
	}

	store.SetStatements("ns/source-1", stmts1)
	store.SetStatements("ns/source-2", stmts2)

	all := store.GetAllStatements()
	assert.Len(t, all, 2)

	// Update source-1
	store.SetStatements("ns/source-1", []parser.VEXStatement{})
	allAfterUpdate := store.GetAllStatements()
	assert.Len(t, allAfterUpdate, 1)
	assert.Equal(t, "CVE-2026-0002", allAfterUpdate[0].CVE)

	// Delete source-2
	store.DeleteStatements("ns/source-2")
	assert.Empty(t, store.GetAllStatements())
}
