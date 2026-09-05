package wrapper

import (
	"bytes"
	"debug/elf"
	"debug/pe"
	"math"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNativeAddressReadsRejectWrappingRanges(t *testing.T) {
	data := []byte{1, 2, 3, 4}
	elfFile := &ElfWrapper{file: &elf.File{Progs: []*elf.Prog{{ProgHeader: elf.ProgHeader{Type: elf.PT_LOAD, Vaddr: 100, Filesz: 4}, ReaderAt: bytes.NewReader(data)}}}}
	peFile := &PeWrapper{imageBase: 0, file: &pe.File{Sections: []*pe.Section{{SectionHeader: pe.SectionHeader{VirtualAddress: 100, Size: 4}, ReaderAt: bytes.NewReader(data)}}}}
	for name, read := range map[string]func(uint64, uint64) ([]byte, error){"ELF": elfFile.ReadAddr, "PE": peFile.ReadAddr} {
		t.Run(name, func(t *testing.T) {
			got, err := read(101, 2)
			require.NoError(t, err)
			require.Equal(t, []byte{2, 3}, got)
			require.NotPanics(t, func() {
				_, err = read(101, math.MaxUint64)
				require.ErrorIs(t, err, ErrAddrNotFound)
			})
			_, err = read(104, 1)
			require.ErrorIs(t, err, ErrAddrNotFound)
		})
	}
}
