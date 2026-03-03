package crypto

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSHA256Hex_KnownVector(t *testing.T) {
	t.Parallel()

	got := SHA256Hex([]byte("abc"))
	require.Equal(t, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", got)
}

func TestHexRoundTrip(t *testing.T) {
	t.Parallel()

	orig := []byte{0x00, 0x01, 0x02, 0xfe, 0xff}
	hexStr := ToHex(orig)

	decoded, err := FromHex(hexStr)
	require.NoError(t, err)
	require.Equal(t, orig, decoded)
}

func TestSHA256_Returns32Bytes(t *testing.T) {
	t.Parallel()

	digest := SHA256([]byte("aethelred"))
	require.Len(t, digest, 32)
}

func TestSHA256AndSHA256Hex_Agree(t *testing.T) {
	t.Parallel()

	raw := SHA256([]byte("sdk-test"))
	hexStr := SHA256Hex([]byte("sdk-test"))
	require.Equal(t, ToHex(raw), hexStr)
}

func TestFromHex_InvalidInputReturnsError(t *testing.T) {
	t.Parallel()

	_, err := FromHex("zz")
	require.Error(t, err)
}

func TestToHex_EmptySlice(t *testing.T) {
	t.Parallel()

	require.Equal(t, "", ToHex(nil))
	require.Equal(t, "", ToHex([]byte{}))
}
