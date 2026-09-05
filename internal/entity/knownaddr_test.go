package entity

import (
	"math"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDisasmCandidatesRespectEnclosingSymbolsAndBounds(t *testing.T) {
	store := NewStore()
	store.Sections["data"] = &Section{Addr: 100, Size: 1000, FileSize: 1000, ContentType: SectionContentData}
	store.BuildCache()
	known := NewKnownAddr(store)
	known.InsertSymbol(NewSymbol("outer", 100, 200, AddrTypeData), nil)
	known.InsertSymbol(NewSymbol("inner", 150, 10, AddrTypeData), nil)
	known.BuildSymbolCoverage()
	for _, tc := range []struct {
		name       string
		addr, size uint64
		accepted   bool
	}{
		{"inside enclosing symbol after alias", 200, 8, false},
		{"overlaps enclosing symbol tail", 299, 2, false},
		{"starts after enclosing symbol", 300, 8, true},
		{"empty", 400, 0, false},
		{"address overflow", 400, math.MaxUint64, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fn := &Function{}
			fn.Init()
			known.InsertDisasm(tc.addr, tc.size, fn)
			require.Equal(t, tc.accepted, len(fn.disasm) != 0)
		})
	}
}
