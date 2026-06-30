package attestation

import (
	"errors"
	"fmt"
)

// A minimal, dependency-free CBOR (RFC 8949) codec — just the subset AWS Nitro's
// COSE_Sign1 attestation uses: unsigned/negative ints, byte/text strings,
// arrays, maps, tags, and null. Enough to parse the document and to re-encode
// the COSE Sig_structure for signature verification.

type cborReader struct {
	b   []byte
	pos int
}

func (r *cborReader) readByte() (byte, error) {
	if r.pos >= len(r.b) {
		return 0, errors.New("cbor: unexpected end")
	}
	c := r.b[r.pos]
	r.pos++
	return c, nil
}

func (r *cborReader) readN(n int) ([]byte, error) {
	if n < 0 || r.pos+n > len(r.b) {
		return nil, errors.New("cbor: length out of range")
	}
	out := r.b[r.pos : r.pos+n]
	r.pos += n
	return out, nil
}

// argument reads the additional-info argument for a major type.
func (r *cborReader) argument(ai byte) (uint64, error) {
	switch {
	case ai < 24:
		return uint64(ai), nil
	case ai == 24:
		c, err := r.readByte()
		return uint64(c), err
	case ai == 25:
		b, err := r.readN(2)
		if err != nil {
			return 0, err
		}
		return uint64(b[0])<<8 | uint64(b[1]), nil
	case ai == 26:
		b, err := r.readN(4)
		if err != nil {
			return 0, err
		}
		return uint64(b[0])<<24 | uint64(b[1])<<16 | uint64(b[2])<<8 | uint64(b[3]), nil
	case ai == 27:
		b, err := r.readN(8)
		if err != nil {
			return 0, err
		}
		var v uint64
		for _, x := range b {
			v = v<<8 | uint64(x)
		}
		return v, nil
	}
	return 0, fmt.Errorf("cbor: unsupported additional info %d", ai)
}

// decodeValue decodes one CBOR data item into a Go value:
// uint64, int64, []byte, string, []any, map[any]any, or nil.
func (r *cborReader) decodeValue() (any, error) {
	c, err := r.readByte()
	if err != nil {
		return nil, err
	}
	major := c >> 5
	arg, err := r.argument(c & 0x1f)
	if err != nil {
		return nil, err
	}
	switch major {
	case 0: // unsigned int
		return arg, nil
	case 1: // negative int
		return -1 - int64(arg), nil
	case 2: // byte string
		b, err := r.readN(int(arg))
		if err != nil {
			return nil, err
		}
		return append([]byte(nil), b...), nil
	case 3: // text string
		b, err := r.readN(int(arg))
		if err != nil {
			return nil, err
		}
		return string(b), nil
	case 4: // array
		out := make([]any, 0, arg)
		for i := uint64(0); i < arg; i++ {
			v, err := r.decodeValue()
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	case 5: // map
		out := make(map[any]any, arg)
		for i := uint64(0); i < arg; i++ {
			k, err := r.decodeValue()
			if err != nil {
				return nil, err
			}
			v, err := r.decodeValue()
			if err != nil {
				return nil, err
			}
			out[mapKey(k)] = v
		}
		return out, nil
	case 6: // tag — decode and return the tagged content
		return r.decodeValue()
	case 7: // simple/float
		switch arg {
		case 22: // null
			return nil, nil
		case 20:
			return false, nil
		case 21:
			return true, nil
		}
		return nil, nil
	}
	return nil, fmt.Errorf("cbor: unsupported major type %d", major)
}

// mapKey normalizes map keys so int and uint keys compare predictably.
func mapKey(k any) any {
	switch v := k.(type) {
	case uint64:
		return int64(v)
	case int64:
		return v
	default:
		return k
	}
}

func cborDecode(b []byte) (any, error) {
	r := &cborReader{b: b}
	return r.decodeValue()
}

// --- minimal encoder (only what the COSE Sig_structure needs) ---

func cborHead(major byte, arg uint64) []byte {
	mt := major << 5
	switch {
	case arg < 24:
		return []byte{mt | byte(arg)}
	case arg < 1<<8:
		return []byte{mt | 24, byte(arg)}
	case arg < 1<<16:
		return []byte{mt | 25, byte(arg >> 8), byte(arg)}
	case arg < 1<<32:
		return []byte{mt | 26, byte(arg >> 24), byte(arg >> 16), byte(arg >> 8), byte(arg)}
	default:
		out := []byte{mt | 27}
		for i := 7; i >= 0; i-- {
			out = append(out, byte(arg>>(uint(i)*8)))
		}
		return out
	}
}

func cborBytes(b []byte) []byte { return append(cborHead(2, uint64(len(b))), b...) }
func cborText(s string) []byte  { return append(cborHead(3, uint64(len(s))), s...) }
func cborArray(n int) []byte    { return cborHead(4, uint64(n)) }
func cborUint(v uint64) []byte  { return cborHead(0, v) }
func cborNegInt(v int64) []byte { return cborHead(1, uint64(-1-v)) }
func cborMap(n int) []byte      { return cborHead(5, uint64(n)) }
