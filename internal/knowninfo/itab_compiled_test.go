//go:build !js && !wasm

package knowninfo_test

import (
	"debug/elf"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"

	"github.com/Zxilly/go-size-analyzer/internal/entity"
	"github.com/Zxilly/go-size-analyzer/internal/wrapper"

	"github.com/Zxilly/go-size-analyzer/internal"
	"github.com/Zxilly/go-size-analyzer/internal/utils"
	"github.com/stretchr/testify/require"
)

func TestInterfaceTableMatchesLinkerSize(t *testing.T) {
	const source = `package main
type iface interface{first()int;second()int}
type item int
func(i item)first()int{return int(i)}
func(i item)second()int{return int(i)+1}
var Value iface=item(3)
func main(){println(Value.first(),Value.second())}
`
	for _, arch := range []string{"amd64", "386", "mips"} {
		t.Run(arch, func(t *testing.T) {
			dir := t.TempDir()
			src, bin := filepath.Join(dir, "main.go"), filepath.Join(dir, "binary")
			require.NoError(t, os.WriteFile(src, []byte(source), 0o600))
			cmd := exec.CommandContext(t.Context(), "go", "build", "-gcflags=-S", "-o", bin, src)
			cmd.Dir = dir
			cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+arch, "CGO_ENABLED=0")
			out, err := cmd.CombinedOutput()
			require.NoError(t, err, "%s", out)
			ef, err := elf.Open(bin)
			require.NoError(t, err)
			defer ef.Close()
			syms, err := ef.Symbols()
			require.NoError(t, err)
			var value elf.Symbol
			for _, s := range syms {
				if s.Name == "main.Value" {
					value = s
				}
			}
			require.Positive(t, value.Size)
			match := regexp.MustCompile(`(?m)^go:itab.main.item,main.iface SRODATA[^\r\n]* size=(\d+)`).FindSubmatch(out)
			require.Len(t, match, 2)
			expectedSize, err := strconv.ParseUint(string(match[1]), 10, 64)
			require.NoError(t, err)
			width := uint64(8)
			if ef.Class == elf.ELFCLASS32 {
				width = 4
			}
			data, err := wrapper.NewWrapper(ef).ReadAddr(value.Value, width)
			require.NoError(t, err)
			expectedAddr := uint64(ef.ByteOrder.Uint32(data))
			if width == 8 {
				expectedAddr = ef.ByteOrder.Uint64(data)
			}
			f, err := utils.OpenBinary(bin)
			require.NoError(t, err)
			defer f.Close()
			r, err := internal.Analyze(bin, f, uint64(f.Len()), internal.Options{SkipDisasm: true, SkipDwarf: true, SkipSymbol: true})
			require.NoError(t, err)
			found := false
			var check func(entity.PackageMap)
			check = func(pkgs entity.PackageMap) {
				for _, pkg := range pkgs {
					for _, s := range pkg.Symbols {
						if s.Addr == expectedAddr {
							require.Equal(t, expectedSize, s.Size)
							found = true
						}
					}
					check(pkg.SubPackages)
				}
			}
			check(r.Packages)
			require.True(t, found, "missing interface table from type analysis")
		})
	}
}
