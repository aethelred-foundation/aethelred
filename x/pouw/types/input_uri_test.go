package types

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

func TestValidateInputDataURIValid(t *testing.T) {
	t.Parallel()

	inline := InlineInputDataURIPrefix + base64.StdEncoding.EncodeToString([]byte("small input"))
	valid := []string{
		"https://inputs.example.com/jobs/job-1.bin",
		"https://unresolvable.invalid/input.bin?version=2",
		inline,
	}

	for _, inputURI := range valid {
		inputURI := inputURI
		t.Run(inputURI, func(t *testing.T) {
			t.Parallel()
			if err := ValidateInputDataURI(inputURI); err != nil {
				t.Fatalf("expected valid input URI, got %v", err)
			}
		})
	}
}

func TestValidateInputDataURIRejectsUnsupportedOrUnboundedValues(t *testing.T) {
	t.Parallel()

	invalid := []string{
		"",
		" https://inputs.example.com/input.bin",
		"http://inputs.example.com/input.bin",
		"ipfs://QmInput",
		"file:///etc/passwd",
		"https://localhost/input.bin",
		"https://127.0.0.1/input.bin",
		"https://10.0.0.1/input.bin",
		"https://169.254.169.254/latest/meta-data",
		"https://user:secret@inputs.example.com/input.bin",
		"https://inputs.example.com/input.bin#fragment",
		"data:text/plain;base64,aW5wdXQ=",
		InlineInputDataURIPrefix,
		InlineInputDataURIPrefix + "not!base64",
		"https://inputs.example.com/" + strings.Repeat("x", MaxInputDataURILength),
	}

	for _, inputURI := range invalid {
		inputURI := inputURI
		t.Run(inputURI, func(t *testing.T) {
			t.Parallel()
			if err := ValidateInputDataURI(inputURI); err == nil {
				t.Fatalf("expected invalid input URI %q to be rejected", inputURI)
			}
		})
	}
}

func TestMsgSubmitJobValidateBasicRequiresResolvableInputURI(t *testing.T) {
	t.Parallel()

	modelHash := sha256.Sum256([]byte("model"))
	inputHash := sha256.Sum256([]byte("input"))
	msg := &MsgSubmitJob{
		Creator:      sdk.AccAddress(make([]byte, 20)).String(),
		ModelHash:    modelHash[:],
		InputHash:    inputHash[:],
		InputDataUri: "https://inputs.example.com/input.bin",
		ProofType:    ProofTypeTEE,
		Purpose:      "test",
	}

	if err := msg.ValidateBasic(); err != nil {
		t.Fatalf("valid message rejected: %v", err)
	}
	msg.InputDataUri = ""
	if err := msg.ValidateBasic(); err == nil {
		t.Fatal("message with empty input URI must be rejected")
	}
}
