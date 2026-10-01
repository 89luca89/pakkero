package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestCopyOutputPreservesLongLines(t *testing.T) {
	input := strings.Repeat("x", 256*1024)
	var output bytes.Buffer

	if err := obCopyOutput(&output, strings.NewReader(input)); err != nil {
		t.Fatalf("copy output: %v", err)
	}
	if got := output.String(); got != input {
		t.Fatalf("copied output length = %d, want %d", len(got), len(input))
	}
}
