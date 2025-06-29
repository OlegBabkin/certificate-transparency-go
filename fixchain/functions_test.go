// Copyright 2016 Google LLC. All Rights Reserved.
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

package fixchain

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"testing"

	"github.com/OlegBabkin/certificate-transparency-go/x509"
	"github.com/OlegBabkin/certificate-transparency-go/x509/pkix"
	"github.com/OlegBabkin/certificate-transparency-go/x509util"
)

type nilLimiter struct{}

func (l *nilLimiter) Wait(ctx context.Context) error {
	return nil
}

func newNilLimiter() *nilLimiter {
	return &nilLimiter{}
}

type bytesReadCloser struct {
	*bytes.Reader
}

func (rc bytesReadCloser) Close() error {
	return nil
}

// GetTestCertificateFromPEM returns an x509.Certificate from a certificate in
// PEM format for testing purposes.  Any errors in the PEM decoding process are
// reported to the testing framework.
func GetTestCertificateFromPEM(t *testing.T, pemBytes string) *x509.Certificate {
	cert, err := x509util.CertificateFromPEM([]byte(pemBytes))
	if x509.IsFatal(err) {
		t.Errorf("Failed to parse leaf: %s", err)
	}
	return cert
}

func nameToKey(name *pkix.Name) string {
	return fmt.Sprintf("%s/%s/%s/%s", strings.Join(name.Country, ","),
		strings.Join(name.Organization, ","),
		strings.Join(name.OrganizationalUnit, ","), name.CommonName)
}

func chainToDebugString(chain []*x509.Certificate) string {
	var chainStr string
	for _, cert := range chain {
		if len(chainStr) > 0 {
			chainStr += " -> "
		}
		chainStr += nameToKey(&cert.Subject)
	}
	return chainStr
}

func matchTestChainList(t *testing.T, i int, want [][]string, got [][]*x509.Certificate) {
	if len(want) != len(got) {
		t.Errorf("#%d: Wanted %d chains, got back %d", i, len(want), len(got))
	}

	seen := make([]bool, len(want))
NextOutputChain:
	for _, chain := range got {
	TryNextExpected:
		for j, expChain := range want {
			if seen[j] {
				continue
			}
			if len(chain) != len(expChain) {
				continue
			}
			for k, cert := range chain {
				if !strings.Contains(nameToKey(&cert.Subject), expChain[k]) {
					continue TryNextExpected
				}
			}
			seen[j] = true
			continue NextOutputChain
		}
		t.Errorf("#%d: No expected chain matched output chain %s", i,
			chainToDebugString(chain))
	}

	for j, val := range seen {
		if !val {
			t.Errorf("#%d: No output chain matched expected chain %s", i,
				strings.Join(want[j], " -> "))
		}
	}
}

func matchTestErrorList(t *testing.T, i int, want []errorType, got []*FixError) {
	if len(want) != len(got) {
		t.Errorf("#%d: Wanted %d errors, got back %d", i, len(want), len(got))
	}

	seen := make([]bool, len(want))
NextOutputErr:
	for _, err := range got {
		for j, expErr := range want {
			if seen[j] {
				continue
			}
			if err.Type == expErr {
				seen[j] = true
				continue NextOutputErr
			}
		}
		t.Errorf("#%d: No expected error matched output error %s", i, err.TypeString())
	}

	for j, val := range seen {
		if !val {
			t.Errorf("#%d: No output error matched expected error %s", i,
				FixError{Type: want[j]}.TypeString())
		}
	}
}

func matchTestChain(t *testing.T, i int, want []string, got []*x509.Certificate) {
	if len(got) != len(want) {
		t.Errorf("#%d: Expected a chain of length %d, got one of length %d",
			i, len(want), len(got))
		return
	}

	if want != nil {
		for j, cert := range got {
			if !strings.Contains(nameToKey(&cert.Subject), want[j]) {
				t.Errorf("#%d: Chain does not match expected chain at position %d", i, j)
			}
		}
	}
}

func matchTestRoots(t *testing.T, i int, want []string, got *x509.CertPool) {
	if len(got.Subjects()) != len(want) {
		t.Errorf("#%d: received %d roots, expected %d", i, len(got.Subjects()), len(want))
	}
	testRoots := extractTestChain(t, i, want)
	seen := make([]bool, len(testRoots))
NextRoot:
	for _, rootSub := range got.Subjects() {
		for j, testRoot := range testRoots {
			if seen[j] {
				continue
			}
			if bytes.Equal(rootSub, testRoot.RawSubject) {
				seen[j] = true
				continue NextRoot
			}
		}
		t.Errorf("#%d: No expected root matches one of the output roots", i)
	}

	for j, val := range seen {
		if !val {
			t.Errorf("#%d: No output root matches expected root %s", i, nameToKey(&testRoots[j].Subject))
		}
	}
}

func extractTestChain(t *testing.T, _ int, testChain []string) []*x509.Certificate {
	var chain []*x509.Certificate
	for _, cert := range testChain {
		chain = append(chain, GetTestCertificateFromPEM(t, cert))
	}
	return chain

}

func extractTestRoots(t *testing.T, i int, testRoots []string) *x509.CertPool {
	roots := x509.NewCertPool()
	for j, cert := range testRoots {
		ok := roots.AppendCertsFromPEM([]byte(cert))
		if !ok {
			t.Errorf("#%d: Failed to parse root #%d", i, j)
		}
	}
	return roots
}

func testChains(t *testing.T, i int, expectedChains [][]string, chains chan []*x509.Certificate) {
	var allChains [][]*x509.Certificate
	for chain := range chains {
		allChains = append(allChains, chain)
	}
	matchTestChainList(t, i, expectedChains, allChains)
}

func testErrors(t *testing.T, i int, expectedErrs []errorType, errors chan *FixError) {
	var allFerrs []*FixError
	for ferr := range errors {
		allFerrs = append(allFerrs, ferr)
	}
	matchTestErrorList(t, i, expectedErrs, allFerrs)
}

func stringRootsToJSON(roots []string) []byte {
	type Roots struct {
		Certs [][]byte `json:"certificates"`
	}
	var r Roots
	for _, root := range roots {
		cert, err := x509util.CertificateFromPEM([]byte(root))
		if err != nil {
			log.Fatalf("Failed to parse certificate: %s", err)
		}
		r.Certs = append(r.Certs, cert.Raw)
	}
	b, err := json.Marshal(r)
	if err != nil {
		log.Fatalf("Can't marshal JSON: %s", err)
	}
	return b
}
