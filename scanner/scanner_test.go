// Copyright 2014 Google LLC. All Rights Reserved.
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

package scanner

import (
	"container/list"
	"context"
	"log"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	ct "github.com/OlegBabkin/certificate-transparency-go"
	"github.com/OlegBabkin/certificate-transparency-go/client"
	"github.com/OlegBabkin/certificate-transparency-go/jsonclient"
	"github.com/OlegBabkin/certificate-transparency-go/x509"
)

func TestScannerMatchAll(t *testing.T) {
	var cert x509.Certificate
	m := &MatchAll{}
	if !m.CertificateMatches(&cert) {
		t.Fatal("MatchAll didn't match!")
	}
}
func TestScannerMatchNone(t *testing.T) {
	var cert x509.Certificate
	m := &MatchNone{}
	if m.CertificateMatches(&cert) {
		t.Fatal("MatchNone matched!")
	}
}

func TestScannerMatchSubjectRegexMatchesCertificateCommonName(t *testing.T) {
	const SubjectName = "www.example.com"
	const SubjectRegEx = ".*example.com"
	var cert x509.Certificate
	cert.Subject.CommonName = SubjectName

	m := MatchSubjectRegex{regexp.MustCompile(SubjectRegEx), nil}
	if !m.CertificateMatches(&cert) {
		t.Fatal("MatchSubjectRegex failed to match on Cert Subject CommonName")
	}
}

func TestScannerMatchSubjectRegexIgnoresDifferentCertificateCommonName(t *testing.T) {
	const SubjectName = "www.google.com"
	const SubjectRegEx = ".*example.com"
	var cert x509.Certificate
	cert.Subject.CommonName = SubjectName

	m := MatchSubjectRegex{regexp.MustCompile(SubjectRegEx), nil}
	if m.CertificateMatches(&cert) {
		t.Fatal("MatchSubjectRegex incorrectly matched on Cert Subject CommonName")
	}
}

func TestScannerMatchSubjectRegexIgnoresDifferentCertificateSAN(t *testing.T) {
	const SubjectName = "www.google.com"
	const SubjectRegEx = ".*example.com"
	var cert x509.Certificate
	cert.Subject.CommonName = SubjectName

	m := MatchSubjectRegex{regexp.MustCompile(SubjectRegEx), nil}
	cert.Subject.CommonName = "Wibble"              // Doesn't match
	cert.DNSNames = append(cert.DNSNames, "Wibble") // Nor this
	cert.DNSNames = append(cert.DNSNames, SubjectName)

	if m.CertificateMatches(&cert) {
		t.Fatal("MatchSubjectRegex incorrectly matched on Cert SubjectAlternativeName")
	}
}

func TestScannerMatchSubjectRegexMatchesCertificateSAN(t *testing.T) {
	const SubjectName = "www.example.com"
	const SubjectRegEx = ".*example.com"
	var cert x509.Certificate
	cert.Subject.CommonName = SubjectName

	m := MatchSubjectRegex{regexp.MustCompile(SubjectRegEx), nil}
	cert.Subject.CommonName = "Wibble"              // Doesn't match
	cert.DNSNames = append(cert.DNSNames, "Wibble") // Nor this
	cert.DNSNames = append(cert.DNSNames, SubjectName)

	if !m.CertificateMatches(&cert) {
		t.Fatal("MatchSubjectRegex failed to match on Cert SubjectAlternativeName")
	}
}

func TestScannerMatchSubjectRegexMatchesPrecertificateCommonName(t *testing.T) {
	const SubjectName = "www.example.com"
	const SubjectRegEx = ".*example.com"
	var precert ct.Precertificate
	precert.TBSCertificate = &x509.Certificate{}
	precert.TBSCertificate.Subject.CommonName = SubjectName

	m := MatchSubjectRegex{nil, regexp.MustCompile(SubjectRegEx)}
	if !m.PrecertificateMatches(&precert) {
		t.Fatal("MatchSubjectRegex failed to match on Precert Subject CommonName")
	}
}

func TestScannerMatchSubjectRegexIgnoresDifferentPrecertificateCommonName(t *testing.T) {
	const SubjectName = "www.google.com"
	const SubjectRegEx = ".*example.com"
	var precert ct.Precertificate
	precert.TBSCertificate = &x509.Certificate{}
	precert.TBSCertificate.Subject.CommonName = SubjectName

	m := MatchSubjectRegex{nil, regexp.MustCompile(SubjectRegEx)}
	if m.PrecertificateMatches(&precert) {
		t.Fatal("MatchSubjectRegex incorrectly matched on Precert Subject CommonName")
	}
}

func TestScannerMatchSubjectRegexIgnoresDifferentPrecertificateSAN(t *testing.T) {
	const SubjectName = "www.google.com"
	const SubjectRegEx = ".*example.com"
	var precert ct.Precertificate
	precert.TBSCertificate = &x509.Certificate{}
	precert.TBSCertificate.Subject.CommonName = SubjectName

	m := MatchSubjectRegex{nil, regexp.MustCompile(SubjectRegEx)}
	precert.TBSCertificate.Subject.CommonName = "Wibble"                                // Doesn't match
	precert.TBSCertificate.DNSNames = append(precert.TBSCertificate.DNSNames, "Wibble") // Nor this
	precert.TBSCertificate.DNSNames = append(precert.TBSCertificate.DNSNames, SubjectName)

	if m.PrecertificateMatches(&precert) {
		t.Fatal("MatchSubjectRegex incorrectly matched on Precert SubjectAlternativeName")
	}
}

func TestScannerMatchSubjectRegexMatchesPrecertificateSAN(t *testing.T) {
	const SubjectName = "www.example.com"
	const SubjectRegEx = ".*example.com"
	var precert ct.Precertificate
	precert.TBSCertificate = &x509.Certificate{}
	precert.TBSCertificate.Subject.CommonName = SubjectName

	m := MatchSubjectRegex{nil, regexp.MustCompile(SubjectRegEx)}
	precert.TBSCertificate.Subject.CommonName = "Wibble"                                // Doesn't match
	precert.TBSCertificate.DNSNames = append(precert.TBSCertificate.DNSNames, "Wibble") // Nor this
	precert.TBSCertificate.DNSNames = append(precert.TBSCertificate.DNSNames, SubjectName)

	if !m.PrecertificateMatches(&precert) {
		t.Fatal("MatchSubjectRegex failed to match on Precert SubjectAlternativeName")
	}
}

func TestScannerEndToEnd(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ct/v1/get-sth":
			log.Printf("GetSTH")
			if _, err := w.Write([]byte(FourEntrySTH)); err != nil {
				t.Fatal("Failed to write get-sth response")
			}
		case "/ct/v1/get-entries":
			log.Printf("GetEntries %s", r.URL.RawQuery)
			if _, err := w.Write([]byte(FourEntries)); err != nil {
				t.Fatal("Failed to write get-sth response")
			}
		default:
			t.Fatal("Unexpected request")
		}
	}))
	defer ts.Close()

	logClient, err := client.New(ts.URL, &http.Client{}, jsonclient.Options{})
	if err != nil {
		t.Fatal(err)
	}
	opts := ScannerOptions{
		FetcherOptions: FetcherOptions{
			BatchSize:     10,
			ParallelFetch: 1,
			StartIndex:    0,
		},
		Matcher:    &MatchSubjectRegex{regexp.MustCompile(`.*\.google\.com`), nil},
		NumWorkers: 1,
	}
	scanner := NewScanner(logClient, opts)

	var matchedCerts list.List
	var matchedPrecerts list.List

	ctx := context.Background()
	err = scanner.Scan(ctx, func(re *ct.RawLogEntry) {
		// Annoyingly we can't t.Fatal() in here, as this is run in another go
		// routine
		e, _ := re.ToLogEntry()
		if e.X509Cert == nil {
			return
		}
		matchedCerts.PushBack(*e.X509Cert)
	}, func(re *ct.RawLogEntry) {
		e, _ := re.ToLogEntry()
		if e.X509Cert == nil {
			return
		}
		matchedPrecerts.PushBack(*e.Precert)
	})

	if err != nil {
		t.Fatal(err)
	}

	if matchedPrecerts.Len() != 0 {
		t.Fatal("Found unexpected Precert")
	}

	switch matchedCerts.Len() {
	case 0:
		t.Fatal("Failed to find mail.google.com cert")
	case 1:
		if matchedCerts.Front().Value.(x509.Certificate).Subject.CommonName != "mail.google.com" {
			t.Fatal("Matched unexpected cert")
		}
	default:
		t.Fatal("Found unexpected number of certs")
	}
}

func TestDefaultScannerOptions(t *testing.T) {
	opts := DefaultScannerOptions()
	switch opts.Matcher.(type) {
	case *MatchAll:
		// great
	default:
		t.Fatalf("Default Matcher is a %T, expected MatchAll.", opts.Matcher)
	}
	if opts.PrecertOnly {
		t.Fatal("Expected PrecertOnly to be false.")
	}
	if opts.BatchSize < 1 {
		t.Fatalf("Insane BatchSize %d", opts.BatchSize)
	}
	if opts.NumWorkers < 1 {
		t.Fatalf("Insane NumWorkers %d", opts.NumWorkers)
	}
	if opts.ParallelFetch < 1 {
		t.Fatalf("Insane ParallelFetch %d", opts.ParallelFetch)
	}
	if opts.StartIndex != 0 {
		t.Fatalf("Expected StartIndex to be 0, but was %d", opts.StartIndex)
	}
}
