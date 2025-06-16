// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509

import (
	"crypto/elliptic"
	"github.com/google/certificate-transparency-go/x509/ecdsaext"
	"math/big"
	"sync"
)

// This file holds ECC curves that are not supported by the main Go crypto/elliptic
// library, but which have been observed in certificates in the wild.

var initonce sync.Once
var p192r1 *elliptic.CurveParams
var p256k1 *ecdsaext.CurveParams

func initAllCurves() {
	initSECP192R1()
	initSecp256k1()
}

func initSECP192R1() {
	// See SEC-2, section 2.2.2
	p192r1 = &elliptic.CurveParams{Name: "P-192"}
	p192r1.P, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF", 16)
	p192r1.N, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831", 16)
	p192r1.B, _ = new(big.Int).SetString("64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1", 16)
	p192r1.Gx, _ = new(big.Int).SetString("188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012", 16)
	p192r1.Gy, _ = new(big.Int).SetString("07192B95FFC8DA78631011ED6B24CDD573F977A11E794811", 16)
	p192r1.BitSize = 192
}

func secp192r1() elliptic.Curve {
	initonce.Do(initAllCurves)
	return p192r1
}

func initSecp256k1() {
	gop256k1 := elliptic.CurveParams{Name: "P-256k1"}
	gop256k1.P, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
	gop256k1.N, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
	gop256k1.B = big.NewInt(7)
	gop256k1.Gx, _ = new(big.Int).SetString("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16)
	gop256k1.Gy, _ = new(big.Int).SetString("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)
	gop256k1.BitSize = 256

	p256k1 = &ecdsaext.CurveParams{
		CurveParams: gop256k1,
		A:           new(big.Int),
	}
}

func secp256k1() elliptic.Curve {
	initonce.Do(initAllCurves)
	return p256k1
}
