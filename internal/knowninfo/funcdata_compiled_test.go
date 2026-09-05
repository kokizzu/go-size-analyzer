//go:build !js && !wasm

package knowninfo_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"

	"github.com/Zxilly/go-size-analyzer/internal"
	"github.com/Zxilly/go-size-analyzer/internal/entity"
	"github.com/Zxilly/go-size-analyzer/internal/utils"
	"github.com/stretchr/testify/require"
)

func TestCompilerFunctionDataSurvivesStripping(t *testing.T) {
	const source = `package main
type payload struct { P *int; N int }
//go:noinline
func observe(p *payload) int { return *p.P + p.N }
func inline(x int) int { return observe(&payload{&x,3}) }
func cleanup(x int) { println(x) }
//go:noinline
func work(x int) int {
 a:=payload{&x,x}
 defer cleanup(x)
 return observe(&a)+inline(x)
}
func main() { println(work(4)) }
`
	for _, arch := range []string{"amd64", "s390x"} {
		t.Run(arch, func(t *testing.T) {
			dir := t.TempDir()
			src, bin := filepath.Join(dir, "main.go"), filepath.Join(dir, "binary")
			require.NoError(t, os.WriteFile(src, []byte(source), 0o600))
			cmd := exec.CommandContext(t.Context(), "go", "build", "-gcflags=-S", "-ldflags=-s -w", "-o", bin, src)
			cmd.Dir = dir
			cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+arch, "CGO_ENABLED=0")
			assembly, err := cmd.CombinedOutput()
			require.NoError(t, err, "%s", assembly)
			f, err := utils.OpenBinary(bin)
			require.NoError(t, err)
			defer f.Close()
			r, err := internal.Analyze(bin, f, uint64(f.Len()), internal.Options{SkipDisasm: true})
			require.NoError(t, err)
			mainPkg := r.Packages["main"]
			require.NotNil(t, mainPkg)
			functions := map[string]*entity.Function{}
			for fn := range mainPkg.Functions {
				functions[fn.Name] = fn
			}
			work := functions["work"]
			require.NotNil(t, work)
			for suffix, kind := range map[string]string{"stkobj": "stack_objects", "opendefer": "open_defer", "arginfo[01]": "arg_info"} {
				pattern := regexp.MustCompile(`(?m)^main\.work\.` + suffix + ` SRODATA[^\r\n]* size=(\d+)`)
				match := pattern.FindSubmatch(assembly)
				require.Len(t, match, 2, "compiler did not emit %s", suffix)
				size, err := strconv.ParseUint(string(match[1]), 10, 64)
				require.NoError(t, err)
				require.Equal(t, size, work.PclnSize.AuxData[kind], kind)
			}
			require.GreaterOrEqual(t, work.PclnSize.AuxData["inline_tree"], uint64(16))
			var wrappers uint64
			for _, fn := range functions {
				wrappers += fn.PclnSize.AuxData["wrapper_info"]
			}
			require.Positive(t, wrappers)
		})
	}
}
