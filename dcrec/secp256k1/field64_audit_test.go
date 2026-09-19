package secp256k1

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"testing"
)

func auditFieldPair(t *testing.T, tag string, b [32]byte) (*FieldVal, *FieldVal64) {
	t.Helper()
	b[0] &= 0x7f // keep the input strictly below the field prime
	var old FieldVal
	var modern FieldVal64
	if got := old.SetBytes(&b); got != 0 {
		t.Fatalf("%s: unexpected FieldVal overflow", tag)
	}
	if got := modern.SetBytes(&b); got != 0 {
		t.Fatalf("%s: unexpected FieldVal64 overflow", tag)
	}
	return &old, &modern
}

func auditCompareFields(t *testing.T, tag string, old *FieldVal, modern *FieldVal64) {
	t.Helper()
	old.Normalize()
	if !bytes.Equal(old.Bytes()[:], modern.Bytes()[:]) {
		t.Fatalf("%s: mismatch: old=%x field64=%x", tag, old.Bytes(), modern.Bytes())
	}
}

func TestAuditField64Differential(t *testing.T) {
	cases := make([][32]byte, 128)
	cases[0][31] = 1
	for i := 1; i < len(cases); i++ {
		cases[i] = sha256.Sum256([]byte(fmt.Sprintf("dcrd-field64-audit-%d", i)))
		cases[i][0] &= 0x7f
	}

	for i, aBytes := range cases {
		a, a64 := auditFieldPair(t, fmt.Sprintf("a[%d]", i), aBytes)

		var got, got64 FieldVal
		var gotModern FieldVal64

		bBytes := cases[(i*37+11)%len(cases)]
		b, b64 := auditFieldPair(t, fmt.Sprintf("b[%d]", i), bBytes)

		got.Mul2(a, b).Normalize()
		gotModern.Mul2(a64, b64)
		auditCompareFields(t, fmt.Sprintf("mul[%d]", i), &got, &gotModern)

		got.Add2(a, b).Normalize()
		gotModern.Add2(a64, b64)
		auditCompareFields(t, fmt.Sprintf("add[%d]", i), &got, &gotModern)

		got.Mul2(a, a).Normalize()
		gotModern.Mul2(a64, a64)
		auditCompareFields(t, fmt.Sprintf("square[%d]", i), &got, &gotModern)

		got.Set(a).Negate(1).Normalize()
		gotModern.Set(a64).Negate(0)
		auditCompareFields(t, fmt.Sprintf("negate[%d]", i), &got, &gotModern)

		got.Set(a).Inverse().Normalize()
		gotModern.Set(a64).Inverse()
		auditCompareFields(t, fmt.Sprintf("inverse[%d]", i), &got, &gotModern)
	}
}
