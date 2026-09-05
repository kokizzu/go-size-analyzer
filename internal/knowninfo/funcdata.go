package knowninfo

import (
	"bytes"
	"encoding/binary"
	"unicode/utf8"

	"github.com/Zxilly/go-size-analyzer/internal/entity"
)

// These layouts follow Go 1.20+ runtime and compiler FUNCDATA encodings.
// Each object must be explicitly referenced by _func; no section-wide scan
// or distance-to-next-symbol estimate is used to determine its length.
type functionDataReader struct {
	p           *pclnSpans
	read        func(uint64, uint64) ([]byte, error)
	valid       func(uint64, uint64) bool
	limit, base uint64
	cache       map[functionDataKey][]entity.AddrPos
}

type functionDataKey struct {
	index, addr uint64
	maximum     int64
}

func funcDataKind(index uint64) string {
	switch index {
	case 2:
		return "stack_objects"
	case 3:
		return "inline_tree"
	case 4:
		return "open_defer"
	case 5:
		return "arg_info"
	case 7:
		return "wrapper_info"
	default:
		return "unknown"
	}
}

func (r *functionDataReader) data(addr, size uint64) []byte {
	if size == 0 || size > r.limit || size > ^uint64(0)-addr || !r.valid(addr, size) {
		return nil
	}
	b, err := r.read(addr, size)
	if err != nil || uint64(len(b)) != size {
		return nil
	}
	return b
}

func (r *functionDataReader) ranges(index, value, _ uint64, maximum int64) []entity.AddrPos {
	if r.base == 0 || value == 0xffffffff || value > ^uint64(0)-r.base || funcDataKind(index) == "unknown" {
		return nil
	}
	addr := r.base + value
	key := functionDataKey{index: index, addr: addr, maximum: maximum}
	if ranges, ok := r.cache[key]; ok {
		return ranges
	}
	r.cache[key] = nil
	var size uint64
	var extra []entity.AddrPos
	switch index {
	case 2:
		h := r.data(addr, r.p.ptr)
		if h == nil {
			return nil
		}
		count := uint64(r.p.order.Uint32(h))
		if r.p.ptr == 8 {
			count = r.p.order.Uint64(h)
		}
		if r.limit < r.p.ptr || count > (r.limit-r.p.ptr)/16 {
			return nil
		}
		size = r.p.ptr + count*16
		data := r.data(addr, size)
		if data == nil {
			return nil
		}
		for off := r.p.ptr; off < size; off += 16 {
			objectSize := int64(int32(r.p.order.Uint32(data[off+4:])))
			pointerBytes := int64(int32(r.p.order.Uint32(data[off+8:])))
			if objectSize < 0 || pointerBytes > objectSize || -pointerBytes > objectSize {
				return nil
			}
		}
	case 3:
		if maximum < 0 || uint64(maximum) >= r.limit/16 {
			return nil
		}
		size = (uint64(maximum) + 1) * 16
		data := r.data(addr, size)
		if data == nil {
			return nil
		}
		// pcHeader.cutabOffset terminates funcnametab in this format.
		at := uint64(8) + 4*r.p.ptr
		nameEnd := uint64(r.p.order.Uint32(r.p.data[at:]))
		if r.p.ptr == 8 {
			nameEnd = r.p.order.Uint64(r.p.data[at:])
		}
		if nameEnd < r.p.names || nameEnd > uint64(len(r.p.data)) {
			return nil
		}
		for off := uint64(0); off < size; off += 16 {
			if data[off+1] != 0 || data[off+2] != 0 || data[off+3] != 0 {
				return nil
			}
			nameOff := r.p.names + uint64(r.p.order.Uint32(data[off+4:]))
			if nameOff >= nameEnd {
				return nil
			}
			name := r.p.data[nameOff:nameEnd]
			n := bytes.IndexByte(name, 0)
			if n <= 0 || !utf8.Valid(name[:n]) {
				return nil
			}
			span, err := r.p.span(nameOff, uint64(n+1))
			if err != nil {
				return nil
			}
			extra = append(extra, span)
		}
	case 4:
		// ssagen.emitOpenDeferInfo emits exactly two uint32 varints.
		for range 2 {
			var encoded [5]byte
			complete := false
			for i := range encoded {
				b := r.data(addr+size, 1)
				if b == nil {
					return nil
				}
				encoded[i] = b[0]
				size++
				if b[0]&0x80 == 0 {
					value, n := binary.Uvarint(encoded[:i+1])
					if n <= 0 || value > 1<<31-1 {
						return nil
					}
					complete = true
					break
				}
			}
			if !complete {
				return nil
			}
		}
	case 5:
		size = r.argInfoSize(addr)
	case 7:
		size = 4 // ssagen.emitWrappedFuncInfo: one text-relative uint32
	default:
	}
	if r.data(addr, size) == nil {
		return nil
	}
	ranges := append([]entity.AddrPos{{Addr: addr, Size: size, Type: entity.AddrTypeData}}, extra...)
	r.cache[key] = ranges
	return ranges
}

func (r *functionDataReader) argInfoSize(addr uint64) uint64 {
	depth := 0
	for i := uint64(0); i < 171; i++ { // internal/abi.TraceArgsMaxLen
		b := r.data(addr+i, 1)
		if b == nil {
			return 0
		}
		switch b[0] {
		case 0xff: // EndSeq
			if depth == 0 {
				return i + 1
			}
			return 0
		case 0xfe: // StartAgg
			depth++
			if depth > 5 {
				return 0
			}
		case 0xfd: // EndAgg
			depth--
			if depth < 0 {
				return 0
			}
		case 0xfc, 0xfb: // Dotdotdot, OffsetTooLarge
		default:
			if b[0] >= 0xf0 || i+1 >= 171 {
				return 0
			}
			i++ // scalar offset is followed by its byte size
			if r.data(addr+i, 1) == nil {
				return 0
			}
		}
	}
	return 0
}
