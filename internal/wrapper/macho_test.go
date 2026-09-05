package wrapper

import (
	"testing"

	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"

	"github.com/Zxilly/go-size-analyzer/internal/entity"
	"github.com/stretchr/testify/assert"
)

func TestMachoCompilerDataSectionsRemainFileBacked(t *testing.T) {
	for _, name := range []string{"__go_type", "__go_module", "__go_func", "__gopclntab", "__gosymtab", "__const"} {
		s := &types.Section{SectionHeader: types.SectionHeader{Name: name, Seg: "__DATA_CONST", Offset: 4096, Size: 64}}
		assert.Equal(t, entity.SectionContentData, machoSectionType(s), name)
		assert.False(t, machoSectionShouldIgnore(s), name)
	}
	for _, flag := range []types.SectionFlag{2, 3, 4, 5, 6, 7, 14, 16, 17} {
		s := &types.Section{SectionHeader: types.SectionHeader{Name: "literal", Seg: "__DATA", Offset: 4096, Size: 64, Flags: flag}}
		assert.False(t, machoSectionShouldIgnore(s), "section type %d has file contents", flag)
	}
}

func TestGoArchReturnsCorrectArchitectureString(t *testing.T) {
	tests := []struct {
		cpu      types.CPU
		expected string
	}{
		{types.CPUI386, "386"},
		{types.CPUAmd64, "amd64"},
		{types.CPUArm, "arm"},
		{types.CPUArm64, "arm64"},
		{types.CPUPpc64, "ppc64"},
		{types.CPU(0), ""}, // Unsupported CPU type
	}

	for _, test := range tests {
		m := MachoWrapper{file: &macho.File{FileTOC: macho.FileTOC{FileHeader: types.FileHeader{CPU: test.cpu}}}}
		result := m.GoArch()
		assert.Equal(t, test.expected, result)
	}
}
