// Copyright 2015 Google LLC. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ct

import (
	"crypto"
	"crypto/dsa" //nolint:staticcheck
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	mrand "math/rand"
	"testing"

	"github.com/OlegBabkin/certificate-transparency-go/tls"
)

const (
	sigTestDERCertString = "308202ca30820233a003020102020102300d06092a864886f70d01010505003055310b300" +
		"906035504061302474231243022060355040a131b4365727469666963617465205472616e" +
		"73706172656e6379204341310e300c0603550408130557616c65733110300e06035504071" +
		"3074572772057656e301e170d3132303630313030303030305a170d323230363031303030" +
		"3030305a3052310b30090603550406130247423121301f060355040a13184365727469666" +
		"963617465205472616e73706172656e6379310e300c0603550408130557616c6573311030" +
		"0e060355040713074572772057656e30819f300d06092a864886f70d010101050003818d0" +
		"030818902818100b8742267898b99ba6bfd6e6f7ada8e54337f58feb7227c46248437ba5f" +
		"89b007cbe1ecb4545b38ed23fddbf6b9742cafb638157f68184776a1b38ab39318ddd7344" +
		"89b4d750117cd83a220a7b52f295d1e18571469a581c23c68c57d973761d9787a091fb586" +
		"4936b166535e21b427e3c6d690b2e91a87f36b7ec26f59ce53b50203010001a381ac3081a" +
		"9301d0603551d0e041604141184e1187c87956dffc31dd0521ff564efbeae8d307d060355" +
		"1d23047630748014a3b8d89ba2690dfb48bbbf87c1039ddce56256c6a159a4573055310b3" +
		"00906035504061302474231243022060355040a131b436572746966696361746520547261" +
		"6e73706172656e6379204341310e300c0603550408130557616c65733110300e060355040" +
		"713074572772057656e82010030090603551d1304023000300d06092a864886f70d010105" +
		"050003818100292ecf6e46c7a0bcd69051739277710385363341c0a9049637279707ae23c" +
		"c5128a4bdea0d480ed0206b39e3a77a2b0c49b0271f4140ab75c1de57aba498e09459b479" +
		"cf92a4d5d5dd5cbe3f0a11e25f04078df88fc388b61b867a8de46216c0e17c31fc7d8003e" +
		"cc37be22292f84242ab87fb08bd4dfa3c1b9ce4d3ee6667da"

	sigTestSCTTimestamp = 1348589665525

	sigTestCertSCTSignatureEC = "0403" + "0048" +
		"3046022100d3f7690e7ee80d9988a54a3821056393e9eb0c686ad67fbae3686c888fb1a3c" +
		"e022100f9a51c6065bbba7ad7116a31bea1c31dbed6a921e1df02e4b403757fae3254ae"

	sigTestEC256PublicKeyPEM = "-----BEGIN PUBLIC KEY-----\n" +
		"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAES0AfBkjr7b8b19p5Gk8plSAN16wW\n" +
		"XZyhYsH6FMCEUK60t7pem/ckoPX8hupuaiJzJS0ZQ0SEoJGlFxkUFwft5g==\n" +
		"-----END PUBLIC KEY-----\n"

	sigTestEC256PublicKey2PEM = "-----BEGIN PUBLIC KEY-----\n" +
		"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfahLEimAoz2t01p3uMziiLOl/fHT\n" +
		"DM0YDOhBRuiBARsV4UvxG2LdNgoIGLrtCzWE0J5APC2em4JlvR8EEEFMoA==\n" +
		"-----END PUBLIC KEY-----\n"

	sigTestRSAPublicKeyPEM = "-----BEGIN PUBLIC KEY-----\n" +
		"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxy7llbig9kL0wo5AyV1F\n" +
		"hmJLvWTWxzAMwGdhG1h1CqQpaWutXGI9WKRDJSZ/9dr9vgvqdRX2QsnUdJbJ3cz5\n" +
		"Z1ie/RdT/mSVO7ZEqvJS93PIHnquFZXxNnIerGnQ7guC+Zm9BlQ2DIhYpnvVRRVy\n" +
		"D/D8KT92R7qOu3JACduoMrF1synknL8rb8lZvCej8tbhJ38yibMWTmkxsFS+a29X\n" +
		"qk8pkhgwIwvUZqcMaqZo+4/iCuKLbVc85V98SvbcnmsX3gqeQnyRtxlctlclcbvH\n" +
		"mJt5U+3yF1UtcuiyZf1gjcAqnOgvZZYzsodXi0KGV7NRQhTPvwH0C8In2qL+v4qW\n" +
		"AQIDAQAB\n" +
		"-----END PUBLIC KEY-----\n"

	sigTestCertSCTSignatureRSA = "0401" + "0100" +
		"6bc1fecfe9052036e31278cd7eded90d000b127f2b657831baf5ecb31ee3" +
		"c17497abd9562df6319928a36df0ab1a1a917b3f4530e1ca0000ae6c4a0c" +
		"0efada7df83beb95da8eea98f1a27c70afa1ccaa7a0245e1db785b1c0d9f" +
		"ee307e926e14bed1eac0d01c34939e659360432a9552c02b89c3ef3c44aa" +
		"22fc31f2444522975ee83989dd7af1ab05b91bbf0985ca4d04245b68a683" +
		"01d300f0c976ce13d58618dad1b49c0ec5cdc4352016823fc88c479ef214" +
		"76c5f19923af207dbb1b2cff72d4e1e5ee77dd420b85d0f9dcc30a0f617c" +
		"2d3c916eb77f167323500d1b53dc4253321a106e441af343cf2f68630873" +
		"abd43ca52629c586107eb7eb85f2c3ee"

	sigTestCertSCTSignatureUnsupportedSignatureAlgorithm = "0402" + "0000"

	sigTestCertSCTSignatureUnsupportedHashAlgorithm = "0303" + "0000"

	// Some time in September 2012.
	sigTestDefaultSTHTimestamp = 1348589667204

	sigTestDefaultTreeSize = 42

	// *Some* hash that we pretend is a valid root hash.
	sigTestDefaultRootHash = "18041bd4665083001fba8c5411d2d748e8abbfdcdfd9218cb02b68a78e7d4c23"

	sigTestDefaultSTHSignature = "0403" + "0048" +
		"3046022100befd8060563763a5e49ba53e6443c13f7624fd6403178113736e16012aca983" +
		"e022100f572568dbfe9a86490eb915c4ee16ad5ecd708fed35ed4e5cd1b2c3f087b4130"

	sigTestKeyIDEC = "b69d879e3f2c4402556dcda2f6b2e02ff6b6df4789c53000e14f4b125ae847aa"
)

func mustDehex(t *testing.T, h string) []byte {
	t.Helper()
	r, err := hex.DecodeString(h)
	if err != nil {
		t.Fatalf("Failed to decode hex string (%s): %v", h, err)
	}
	return r
}

func sigTestSCTWithSignature(t *testing.T, sig, keyID string) SignedCertificateTimestamp {
	t.Helper()
	var ds DigitallySigned
	if _, err := tls.Unmarshal(mustDehex(t, sig), &ds); err != nil {
		t.Fatalf("Failed to unmarshal sigTestCertSCTSignatureEC: %v", err)
	}
	var id LogID
	copy(id.KeyID[:], mustDehex(t, keyID))
	return SignedCertificateTimestamp{
		SCTVersion: V1,
		LogID:      id,
		Timestamp:  sigTestSCTTimestamp,
		Signature:  ds,
	}
}

func sigTestSCTEC(t *testing.T) SignedCertificateTimestamp {
	t.Helper()
	return sigTestSCTWithSignature(t, sigTestCertSCTSignatureEC, sigTestKeyIDEC)
}

func sigTestSCTRSA(t *testing.T) SignedCertificateTimestamp {
	t.Helper()
	return sigTestSCTWithSignature(t, sigTestCertSCTSignatureRSA, sigTestKeyIDEC)
}

func sigTestECPublicKey(t *testing.T) crypto.PublicKey {
	t.Helper()
	pk, _, _, err := PublicKeyFromPEM([]byte(sigTestEC256PublicKeyPEM))
	if err != nil {
		t.Fatalf("Failed to parse sigTestEC256PublicKey: %v", err)
	}
	return pk
}

func sigTestECPublicKey2(t *testing.T) crypto.PublicKey {
	t.Helper()
	pk, _, _, err := PublicKeyFromPEM([]byte(sigTestEC256PublicKey2PEM))
	if err != nil {
		t.Fatalf("Failed to parse sigTestEC256PublicKey2: %v", err)
	}
	return pk
}

func sigTestRSAPublicKey(t *testing.T) crypto.PublicKey {
	t.Helper()
	pk, _, _, err := PublicKeyFromPEM([]byte(sigTestRSAPublicKeyPEM))
	if err != nil {
		t.Fatalf("Failed to parse sigTestRSAPublicKey: %v", err)
	}
	return pk
}

func sigTestCertLogEntry(t *testing.T) LogEntry {
	t.Helper()
	return LogEntry{
		Index: 0,
		Leaf: MerkleTreeLeaf{
			Version:  V1,
			LeafType: TimestampedEntryLeafType,
			TimestampedEntry: &TimestampedEntry{
				Timestamp: sigTestSCTTimestamp,
				EntryType: X509LogEntryType,
				X509Entry: &ASN1Cert{Data: mustDehex(t, sigTestDERCertString)},
			},
		},
	}
}

func sigTestDefaultSTH(t *testing.T) SignedTreeHead {
	t.Helper()
	var ds DigitallySigned
	if _, err := tls.Unmarshal(mustDehex(t, sigTestDefaultSTHSignature), &ds); err != nil {
		t.Fatalf("Failed to unmarshal sigTestCertSCTSignatureEC: %v", err)
	}
	var rootHash SHA256Hash
	copy(rootHash[:], mustDehex(t, sigTestDefaultRootHash))
	return SignedTreeHead{
		Version:           V1,
		Timestamp:         sigTestDefaultSTHTimestamp,
		TreeSize:          sigTestDefaultTreeSize,
		SHA256RootHash:    rootHash,
		TreeHeadSignature: ds,
	}
}

func mustCreateSignatureVerifier(t *testing.T, pk crypto.PublicKey) SignatureVerifier {
	t.Helper()
	sv, err := NewSignatureVerifier(pk)
	if err != nil {
		t.Fatalf("Failed to create SignatureVerifier: %v", err)
	}
	return *sv
}

func corruptByteAt(b []byte, pos int) {
	b[pos] ^= byte(mrand.Intn(255) + 1)
}

func corruptBytes(b []byte) {
	corruptByteAt(b, mrand.Intn(len(b)))
}

func expectVerifySCTToFail(t *testing.T, sv SignatureVerifier, sct SignedCertificateTimestamp, msg string) {
	t.Helper()
	if err := sv.VerifySCTSignature(sct, sigTestCertLogEntry(t)); err == nil {
		t.Fatal(msg)
	}
}

func TestVerifySCTSignatureEC(t *testing.T) {
	v := mustCreateSignatureVerifier(t, sigTestECPublicKey(t))
	if err := v.VerifySCTSignature(sigTestSCTEC(t), sigTestCertLogEntry(t)); err != nil {
		t.Fatalf("Failed to verify signature on SCT: %v", err)
	}

}

func TestVerifySCTSignatureRSA(t *testing.T) {
	v := mustCreateSignatureVerifier(t, sigTestRSAPublicKey(t))
	if err := v.VerifySCTSignature(sigTestSCTRSA(t), sigTestCertLogEntry(t)); err != nil {
		t.Fatalf("Failed to verify signature on SCT: %v", err)
	}

}

func TestVerifySCTSignatureFailsForMismatchedSignatureAlgorithm(t *testing.T) {
	v := mustCreateSignatureVerifier(t, sigTestECPublicKey(t))
	expectVerifySCTToFail(t, v, sigTestSCTRSA(t), "Successfully verified with mismatched signature algorithm")
}

func TestVerifySCTSignatureFailsForUnknownSignatureAlgorithm(t *testing.T) {
	v := mustCreateSignatureVerifier(t, sigTestECPublicKey(t))
	expectVerifySCTToFail(t, v, sigTestSCTWithSignature(t, sigTestCertSCTSignatureUnsupportedSignatureAlgorithm, sigTestKeyIDEC),
		"Successfully verified signature with unsupported signature algorithm")
}

func TestVerifySCTSignatureFailsForUnknownHashAlgorithm(t *testing.T) {
	v := mustCreateSignatureVerifier(t, sigTestECPublicKey(t))
	expectVerifySCTToFail(t, v, sigTestSCTWithSignature(t, sigTestCertSCTSignatureUnsupportedHashAlgorithm, sigTestKeyIDEC),
		"Successfully verified signature with unsupported hash algorithm")
}

func testVerifySCTSignatureFailsForIncorrectLeafBytes(t *testing.T, sct SignedCertificateTimestamp, sv SignatureVerifier) {
	t.Helper()
	entry := sigTestCertLogEntry(t)
	for i := range entry.Leaf.TimestampedEntry.X509Entry.Data {
		old := entry.Leaf.TimestampedEntry.X509Entry.Data[i]
		corruptByteAt(entry.Leaf.TimestampedEntry.X509Entry.Data, i)
		if err := sv.VerifySCTSignature(sct, entry); err == nil {
			t.Fatalf("Incorrectly verified signature over corrupted leaf data, uncovered byte at %d?", i)
		}
		entry.Leaf.TimestampedEntry.X509Entry.Data[i] = old
	}
	// Ensure we were only corrupting one byte at a time, should be correct again now.
	if err := sv.VerifySCTSignature(sct, entry); err != nil {
		t.Fatalf("Input data appears to still be corrupt, bug? %v", err)
	}
}

func testVerifySCTSignatureFailsForIncorrectSignature(t *testing.T, sct SignedCertificateTimestamp, sv SignatureVerifier) {
	t.Helper()
	corruptBytes(sct.Signature.Signature)
	expectVerifySCTToFail(t, sv, sct, "Incorrectly verified corrupt signature")
}

func TestVerifySCTSignatureECFailsForIncorrectLeafBytes(t *testing.T) {
	v := mustCreateSignatureVerifier(t, sigTestECPublicKey(t))
	testVerifySCTSignatureFailsForIncorrectLeafBytes(t, sigTestSCTEC(t), v)
}

func TestVerifySCTSignatureECFailsForIncorrectTimestamp(t *testing.T) {
	v := mustCreateSignatureVerifier(t, sigTestECPublicKey(t))
	sct := sigTestSCTEC(t)
	sct.Timestamp++
	expectVerifySCTToFail(t, v, sct, "Incorrectly verified signature with incorrect SCT timestamp.")
}

func TestVerifySCTSignatureECFailsForIncorrectVersion(t *testing.T) {
	v := mustCreateSignatureVerifier(t, sigTestECPublicKey(t))
	sct := sigTestSCTEC(t)
	sct.SCTVersion++
	expectVerifySCTToFail(t, v, sct, "Incorrectly verified signature with incorrect SCT Version.")
}

func TestVerifySCTSignatureECFailsForIncorrectSignature(t *testing.T) {
	v := mustCreateSignatureVerifier(t, sigTestECPublicKey(t))
	testVerifySCTSignatureFailsForIncorrectSignature(t, sigTestSCTEC(t), v)
}

func TestVerifySCTSignatureRSAFailsForIncorrectLeafBytes(t *testing.T) {
	v := mustCreateSignatureVerifier(t, sigTestRSAPublicKey(t))
	testVerifySCTSignatureFailsForIncorrectLeafBytes(t, sigTestSCTRSA(t), v)
}

func TestVerifySCTSignatureRSAFailsForIncorrectSignature(t *testing.T) {
	v := mustCreateSignatureVerifier(t, sigTestRSAPublicKey(t))
	testVerifySCTSignatureFailsForIncorrectSignature(t, sigTestSCTRSA(t), v)
}

func TestVerifySCTSignatureFailsForSignatureCreatedWithDifferentAlgorithm(t *testing.T) {
	v := mustCreateSignatureVerifier(t, sigTestRSAPublicKey(t))
	testVerifySCTSignatureFailsForIncorrectSignature(t, sigTestSCTEC(t), v)
}

func TestVerifySCTSignatureFailsForSignatureCreatedWithDifferentKey(t *testing.T) {
	v := mustCreateSignatureVerifier(t, sigTestECPublicKey2(t))
	testVerifySCTSignatureFailsForIncorrectSignature(t, sigTestSCTEC(t), v)
}

func expectVerifySTHToPass(t *testing.T, v SignatureVerifier, sth SignedTreeHead) {
	t.Helper()
	if err := v.VerifySTHSignature(sth); err != nil {
		t.Fatalf("Incorrectly failed to verify STH signature: %v", err)
	}
}

func expectVerifySTHToFail(t *testing.T, v SignatureVerifier, sth SignedTreeHead) {
	t.Helper()
	if err := v.VerifySTHSignature(sth); err == nil {
		t.Fatal("Incorrectly verified STH signature")
	}
}

func TestVerifyValidSTH(t *testing.T) {
	v := mustCreateSignatureVerifier(t, sigTestECPublicKey(t))
	sth := sigTestDefaultSTH(t)
	expectVerifySTHToPass(t, v, sth)
}

func TestVerifySTHCatchesCorruptSignature(t *testing.T) {
	v := mustCreateSignatureVerifier(t, sigTestECPublicKey(t))
	sth := sigTestDefaultSTH(t)
	corruptBytes(sth.TreeHeadSignature.Signature)
	expectVerifySTHToFail(t, v, sth)
}

func TestVerifySTHCatchesCorruptRootHash(t *testing.T) {
	v := mustCreateSignatureVerifier(t, sigTestECPublicKey(t))
	sth := sigTestDefaultSTH(t)
	for i := range sth.SHA256RootHash {
		old := sth.SHA256RootHash[i]
		corruptByteAt(sth.SHA256RootHash[:], i)
		expectVerifySTHToFail(t, v, sth)
		sth.SHA256RootHash[i] = old
	}
	// ensure we were only testing one corrupt byte at a time - should be correct again now.
	expectVerifySTHToPass(t, v, sth)
}

func TestVerifySTHCatchesCorruptTimestamp(t *testing.T) {
	v := mustCreateSignatureVerifier(t, sigTestECPublicKey(t))
	sth := sigTestDefaultSTH(t)
	sth.Timestamp++
	expectVerifySTHToFail(t, v, sth)
}

func TestVerifySTHCatchesCorruptVersion(t *testing.T) {
	v := mustCreateSignatureVerifier(t, sigTestECPublicKey(t))
	sth := sigTestDefaultSTH(t)
	sth.Version++
	expectVerifySTHToFail(t, v, sth)
}

func TestVerifySTHCatchesCorruptTreeSize(t *testing.T) {
	v := mustCreateSignatureVerifier(t, sigTestECPublicKey(t))
	sth := sigTestDefaultSTH(t)
	sth.TreeSize++
	expectVerifySTHToFail(t, v, sth)
}

func TestVerifySTHFailsToVerifyForKeyWithDifferentAlgorithm(t *testing.T) {
	v := mustCreateSignatureVerifier(t, sigTestRSAPublicKey(t))
	sth := sigTestDefaultSTH(t)
	expectVerifySTHToFail(t, v, sth)
}

func TestVerifySTHFailsToVerifyForDifferentKey(t *testing.T) {
	v := mustCreateSignatureVerifier(t, sigTestECPublicKey2(t))
	sth := sigTestDefaultSTH(t)
	expectVerifySTHToFail(t, v, sth)
}

func TestNewSignatureVerifierFailsWithUnsupportedKeyType(t *testing.T) {
	var k dsa.PrivateKey
	if err := dsa.GenerateParameters(&k.Parameters, rand.Reader, dsa.L1024N160); err != nil {
		t.Fatalf("Failed to generate DSA key parameters: %v", err)
	}
	if err := dsa.GenerateKey(&k, rand.Reader); err != nil {
		t.Fatalf("Failed to generate DSA key: %v", err)
	}
	if _, err := NewSignatureVerifier(k); err == nil {
		t.Fatal("Creating a SignatureVerifier with a DSA key unexpectedly succeeded")
	}
}

func TestNewSignatureVerifierFailsWithBadKeyParametersForEC(t *testing.T) {
	k, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key on P224: %v", err)
	}
	if _, err := NewSignatureVerifier(k); err == nil {
		t.Fatal("Incorrectly created new SignatureVerifier with EC P224 key.")
	}
}

func TestNewSignatureVerifierFailsWithBadKeyParametersForRSA(t *testing.T) {
	k, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("Failed to generate 1024 bit RSA key: %v", err)
	}
	if _, err := NewSignatureVerifier(k); err == nil {
		t.Fatal("Incorrectly created new SignatureVerifier with 1024 bit RSA key.")
	}
}

func TestWillAllowNonCompliantECKeyWithOverride(t *testing.T) {
	AllowVerificationWithNonCompliantKeys = true
	k, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate EC key on P224: %v", err)
	}
	if _, err := NewSignatureVerifier(k.Public()); err != nil {
		t.Fatalf("Incorrectly disallowed P224 EC key with override set: %v", err)
	}
}

func TestWillAllowNonCompliantRSAKeyWithOverride(t *testing.T) {
	AllowVerificationWithNonCompliantKeys = true
	k, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("Failed to generate 1024 bit RSA key: %v", err)
	}
	if _, err := NewSignatureVerifier(k.Public()); err != nil {
		t.Fatalf("Incorrectly disallowed 1024 bit RSA key with override set: %v", err)
	}
}
