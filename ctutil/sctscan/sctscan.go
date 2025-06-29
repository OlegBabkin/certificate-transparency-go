// Copyright 2018 Google LLC. All Rights Reserved.
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

// sctscan is a utility to scan a CT log and check embedded SCTs (Signed Certificate
// Timestamps) in certificates in the log.
package main

import (
	"context"
	"crypto/sha256"
	"flag"
	"net/http"
	"time"

	ct "github.com/OlegBabkin/certificate-transparency-go"
	"github.com/OlegBabkin/certificate-transparency-go/client"
	"github.com/OlegBabkin/certificate-transparency-go/ctutil"
	"github.com/OlegBabkin/certificate-transparency-go/jsonclient"
	"github.com/OlegBabkin/certificate-transparency-go/loglist3"
	"github.com/OlegBabkin/certificate-transparency-go/scanner"
	"github.com/OlegBabkin/certificate-transparency-go/x509"
	"github.com/OlegBabkin/certificate-transparency-go/x509util"
	"k8s.io/klog/v2"
)

var (
	logURI        = flag.String("log_uri", "https://ct.googleapis.com/pilot", "CT log base URI")
	logList       = flag.String("log_list", loglist3.AllLogListURL, "Location of master CT log list (URL or filename)")
	inclusion     = flag.Bool("inclusion", false, "Whether to do inclusion checking")
	deadline      = flag.Duration("deadline", 30*time.Second, "Timeout deadline for HTTP requests")
	batchSize     = flag.Int("batch_size", 1000, "Max number of entries to request at per call to get-entries")
	numWorkers    = flag.Int("num_workers", 2, "Number of concurrent matchers")
	parallelFetch = flag.Int("parallel_fetch", 2, "Number of concurrent GetEntries fetches")
	startIndex    = flag.Int64("start_index", 0, "Log index to start scanning at")
)

func main() {
	klog.InitFlags(nil)
	flag.Parse()
	ctx := context.Background()
	klog.CopyStandardLogTo("WARNING")

	hc := &http.Client{
		Timeout: *deadline,
		Transport: &http.Transport{
			TLSHandshakeTimeout:   30 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
			MaxIdleConnsPerHost:   10,
			DisableKeepAlives:     false,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}
	logClient, err := client.New(*logURI, hc, jsonclient.Options{UserAgent: "ct-go-sctscan/1.0"})
	if err != nil {
		klog.Exitf("Failed to create log client: %v", err)
	}
	llData, err := x509util.ReadFileOrURL(*logList, hc)
	if err != nil {
		klog.Exitf("Failed to read log list: %v", err)
	}
	ll, err := loglist3.NewFromJSON(llData)
	if err != nil {
		klog.Exitf("Failed to parse log list: %v", err)
	}
	klog.Warning("Performing validations via direct log queries")
	logsByHash, err := ctutil.LogInfoByKeyHash(ll, hc)
	if err != nil {
		klog.Exitf("Failed to build log info map: %v", err)
	}

	scanOpts := scanner.ScannerOptions{
		FetcherOptions: scanner.FetcherOptions{
			BatchSize:     *batchSize,
			ParallelFetch: *parallelFetch,
			StartIndex:    *startIndex,
		},
		Matcher:    EmbeddedSCTMatcher{},
		NumWorkers: *numWorkers,
	}
	s := scanner.NewScanner(logClient, scanOpts)

	if err := s.Scan(ctx,
		func(entry *ct.RawLogEntry) {
			checkCertWithEmbeddedSCT(ctx, logsByHash, *inclusion, entry)
		},
		func(entry *ct.RawLogEntry) {
			klog.Errorf("Internal error: found pre-cert! %+v", entry)
		}); err != nil {
		klog.Exitf("Scan failed: %v", err)
	}
}

// EmbeddedSCTMatcher implements the scanner.Matcher interface by matching just certificates
// that have embedded SCTs.
type EmbeddedSCTMatcher struct{}

// CertificateMatches identifies certificates in the log that have the SCTList extension.
func (e EmbeddedSCTMatcher) CertificateMatches(cert *x509.Certificate) bool {
	return len(cert.SCTList.SCTList) > 0
}

// PrecertificateMatches identifies those precertificates in the log that are of
// interest: none.
func (e EmbeddedSCTMatcher) PrecertificateMatches(*ct.Precertificate) bool {
	return false
}

// checkCertWithEmbeddedSCT is the callback that the scanner invokes for each cert found by the matcher.
// Here, we only expect to get certificates that have embedded SCT lists.
func checkCertWithEmbeddedSCT(ctx context.Context, logsByKey map[[sha256.Size]byte]*ctutil.LogInfo, checkInclusion bool, rawEntry *ct.RawLogEntry) {
	entry, err := rawEntry.ToLogEntry()
	if x509.IsFatal(err) {
		klog.Errorf("[%d] Internal error: failed to parse cert in entry: %v", rawEntry.Index, err)
		return
	}

	leaf := entry.X509Cert
	if leaf == nil {
		klog.Errorf("[%d] Internal error: no cert in entry", entry.Index)
		return
	}
	if len(entry.Chain) == 0 {
		klog.Errorf("[%d] No issuance chain found", entry.Index)
		return
	}
	issuer, err := x509.ParseCertificate(entry.Chain[0].Data)
	if err != nil {
		klog.Errorf("[%d] Failed to parse issuer: %v", entry.Index, err)
	}

	// Build a Merkle leaf that corresponds to the embedded SCTs.  We can use the same
	// leaf for all of the SCTs, as long as the timestamp field gets updated.
	merkleLeaf, err := ct.MerkleTreeLeafForEmbeddedSCT([]*x509.Certificate{leaf, issuer}, 0)
	if err != nil {
		klog.Errorf("[%d] Failed to build Merkle leaf: %v", entry.Index, err)
		return
	}

	for i, sctData := range leaf.SCTList.SCTList {
		sct, err := x509util.ExtractSCT(&sctData)
		if err != nil {
			klog.Errorf("[%d] Failed to deserialize SCT[%d] data: %v", entry.Index, i, err)
			continue
		}
		logInfo := logsByKey[sct.LogID.KeyID]
		if logInfo == nil {
			klog.Infof("[%d] SCT[%d] for unknown logID: %x, cannot validate SCT", entry.Index, i, sct.LogID)
			continue
		}

		if err := logInfo.VerifySCTSignature(*sct, *merkleLeaf); err != nil {
			klog.Errorf("[%d] Failed to verify SCT[%d] signature from log %q: %v", entry.Index, i, logInfo.Description, err)
		} else {
			klog.V(1).Infof("[%d] Verified SCT[%d] against log %q", entry.Index, i, logInfo.Description)
		}

		if !checkInclusion {
			continue
		}

		if index, err := logInfo.VerifyInclusionLatest(ctx, *merkleLeaf, sct.Timestamp); err != nil {
			// Inclusion failure may be OK if the SCT is within the Log's MMD
			sth := logInfo.LastSTH()
			if sth != nil {
				delta := time.Duration(sth.Timestamp-sct.Timestamp) * time.Millisecond
				if delta < logInfo.MMD {
					klog.Warningf("[%d] Failed to verify SCT[%d] inclusion proof (%v), but Log's MMD has not passed %d -> %d < %v", entry.Index, i, err, sct.Timestamp, sth.Timestamp, logInfo.MMD)
					continue
				}
			}
			klog.Errorf("[%d] Failed to verify SCT[%d] inclusion proof: %v", entry.Index, i, err)
		} else {
			klog.V(1).Infof("[%d] Checked SCT[%d] inclusion against log %q, at index %d", entry.Index, i, logInfo.Description, index)
		}
	}
}
