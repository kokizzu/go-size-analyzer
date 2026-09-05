package knowninfo

import (
	"encoding/binary"
	"testing"

	"github.com/Zxilly/go-size-analyzer/internal/entity"
	"github.com/stretchr/testify/require"
)

func TestFunctionDataUsesEncodedBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name  string
		index uint64
		data  []byte
		size  uint64
	}{
		{"two defer varints", 4, []byte{0x81, 1, 0x82, 1, 0xaa}, 4},
		{"truncated defer", 4, []byte{1, 0x80}, 0},
		{"overflowing defer", 4, []byte{0xff, 0xff, 0xff, 0xff, 0x7f, 1}, 0},
		{"argument sequence terminator", 5, []byte{0xfe, 0, 8, 0xfd, 0xff, 0xaa}, 5},
		{"unterminated arguments", 5, []byte{0, 8}, 0},
		{"unbalanced arguments", 5, []byte{0xfe, 0xff}, 0},
		{"unknown argument opcode", 5, []byte{0xf1, 0xff}, 0},
		{"wrapper reference", 7, []byte{1, 2, 3, 4, 5}, 4},
		{"truncated wrapper reference", 7, []byte{1, 2, 3}, 0},
		{"unknown funcdata", 9, []byte{1, 2, 3, 4}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := testFunctionDataReader(tc.data, binary.LittleEndian)
			spans := r.ranges(tc.index, 0, 0, -1)
			if tc.size == 0 {
				require.Empty(t, spans)
			} else {
				require.Equal(t, []entity.AddrPos{{Addr: 4096, Size: tc.size, Type: entity.AddrTypeData}}, spans)
			}
		})
	}
}

func TestStackObjectRecordsRejectImpossiblePointerSizes(t *testing.T) {
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		data := make([]byte, 32)
		order.PutUint64(data, 1)
		order.PutUint32(data[12:], 8)
		order.PutUint32(data[16:], 8)
		r := testFunctionDataReader(data, order)
		require.Equal(t, []entity.AddrPos{{Addr: 4096, Size: 24, Type: entity.AddrTypeData}}, r.ranges(2, 0, 0, -1))
		order.PutUint32(data[16:], 9)
		r = testFunctionDataReader(data, order)
		require.Empty(t, r.ranges(2, 0, 0, -1))
		order.PutUint64(data, ^uint64(0))
		r = testFunctionDataReader(data, order)
		require.Empty(t, r.ranges(2, 0, 0, -1))
	}
}

func testFunctionDataReader(data []byte, order binary.ByteOrder) *functionDataReader {
	return &functionDataReader{
		p: &pclnSpans{ptr: 8, order: order}, base: 4096, limit: uint64(len(data)),
		cache: map[functionDataKey][]entity.AddrPos{},
		valid: func(addr, size uint64) bool {
			return addr >= 4096 && addr-4096 <= uint64(len(data)) && size <= uint64(len(data))-(addr-4096)
		},
		read: func(addr, size uint64) ([]byte, error) { return data[addr-4096 : addr-4096+size], nil },
	}
}

func TestPCProgramsCannotConsumeFollowingFunctionTable(t *testing.T) {
	p := &pclnSpans{version: 120, funcs: 3, data: []byte{0, 2, 1, 0}, pcSizes: map[uint32]uint64{}, pcMax: map[uint32]int64{}}
	_, err := p.pcSize(1)
	require.ErrorContains(t, err, "unterminated")
	_, err = p.pcSize(3)
	require.ErrorContains(t, err, "outside pctab")
}
