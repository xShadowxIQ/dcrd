package secp256k1

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"testing"
)

func auditFieldPair(t *testing.T, tag string, b [32]byte) (*FieldVal, *FieldVal64) {
	t.Helper()
	b[0] &= 0x7f
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
		var got FieldVal
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

		got.Set(a).Negate(31).Normalize()
		gotModern.Set(a64).Negate(0)
		auditCompareFields(t, fmt.Sprintf("negate[%d]", i), &got, &gotModern)

		got.Set(a).Inverse().Normalize()
		gotModern.Set(a64).Inverse()
		auditCompareFields(t, fmt.Sprintf("inverse[%d]", i), &got, &gotModern)
	}
}

func TestAuditField64AMD64VsGeneric(t *testing.T) {
	if !field64UseADX {
		t.Skip("CPU lacks BMI2/ADX")
	}
	cases := make([][32]byte, 256)
	for i := range cases {
		cases[i] = sha256.Sum256([]byte(fmt.Sprintf("dcrd-field64-adx-audit-%d", i)))
		cases[i][0] &= 0x7f
		var a, b FieldVal64
		a.SetBytes(&cases[i])
		j := (i*73 + 19) % len(cases)
		b.SetBytes(&cases[j])

		var adxMul, genericMul, adxSq, genericSq [4]uint64
		field64Mul(&adxMul, &a.n, &b.n)
		field64MulGeneric(&genericMul, &a.n, &b.n)
		if adxMul != genericMul {
			t.Fatalf("mul mismatch at %d: adx=%x generic=%x", i, adxMul, genericMul)
		}

		field64Square(&adxSq, &a.n)
		field64SquareGeneric(&genericSq, &a.n)
		if adxSq != genericSq {
			t.Fatalf("square mismatch at %d: adx=%x generic=%x", i, adxSq, genericSq)
		}
	}
}
