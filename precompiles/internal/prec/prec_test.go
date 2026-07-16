package prec

import (
	"bytes"
	"testing"
)

func TestStringArg(t *testing.T) {
	if v, err := StringArg([]interface{}{"x"}, 0, "a"); err != nil || v != "x" {
		t.Errorf("valid: %v %v", v, err)
	}
	if _, err := StringArg(nil, 0, "a"); err == nil {
		t.Error("missing must error")
	}
	if _, err := StringArg([]interface{}{7}, 0, "a"); err == nil {
		t.Error("wrong type must error")
	}
}

func TestStringSliceArg(t *testing.T) {
	if v, err := StringSliceArg([]interface{}{[]string{"x"}}, 0, "a"); err != nil || len(v) != 1 {
		t.Errorf("valid: %v %v", v, err)
	}
	if _, err := StringSliceArg(nil, 0, "a"); err == nil {
		t.Error("missing must error")
	}
	if _, err := StringSliceArg([]interface{}{7}, 0, "a"); err == nil {
		t.Error("wrong type must error")
	}
}

func TestBoolArg(t *testing.T) {
	if v, err := BoolArg([]interface{}{true}, 0, "a"); err != nil || !v {
		t.Errorf("valid: %v %v", v, err)
	}
	if _, err := BoolArg(nil, 0, "a"); err == nil {
		t.Error("missing must error")
	}
	if _, err := BoolArg([]interface{}{"x"}, 0, "a"); err == nil {
		t.Error("wrong type must error")
	}
}

func TestBytes32Arg(t *testing.T) {
	var in [32]byte
	in[0], in[31] = 0xAA, 0xBB
	v, err := Bytes32Arg([]interface{}{in}, 0, "a")
	if err != nil || len(v) != 32 || v[0] != 0xAA || v[31] != 0xBB {
		t.Errorf("valid: %x %v", v, err)
	}
	if _, err := Bytes32Arg(nil, 0, "a"); err == nil {
		t.Error("missing must error")
	}
	if _, err := Bytes32Arg([]interface{}{"x"}, 0, "a"); err == nil {
		t.Error("wrong type must error")
	}
}

func TestToBytes32AndNonNilBytes(t *testing.T) {
	got := ToBytes32([]byte{1, 2, 3})
	if got[0] != 1 || got[2] != 3 || got[31] != 0 {
		t.Errorf("pad: %x", got)
	}
	// Longer than 32 truncates deterministically.
	long := bytes.Repeat([]byte{0xFF}, 40)
	if g := ToBytes32(long); g[31] != 0xFF {
		t.Errorf("truncate: %x", g)
	}
	if NonNilBytes(nil) == nil || len(NonNilBytes(nil)) != 0 {
		t.Error("nil must map to empty")
	}
	if v := NonNilBytes([]byte{1}); len(v) != 1 {
		t.Error("non-nil must pass through")
	}
}
