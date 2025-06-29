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

package util

import (
	"crypto/sha256"

	ct "github.com/OlegBabkin/certificate-transparency-go"
	"github.com/OlegBabkin/certificate-transparency-go/tls"
	"github.com/google/trillian"
	"k8s.io/klog/v2"
)

// BuildLogLeaf returns a Trillian LogLeaf structure for a (pre-)cert and the
// chain of certificates leading it up to a known root.
func BuildLogLeaf(logPrefix string,
	merkleLeaf ct.MerkleTreeLeaf, leafIndex int64,
	cert ct.ASN1Cert, chain []ct.ASN1Cert, isPrecert bool,
) (*trillian.LogLeaf, error) {
	return buildLogLeaf(logPrefix, merkleLeaf, leafIndex, cert, chain, nil, isPrecert)
}

// ExtraDataForChain creates the extra data associated with a log entry as
// described in RFC6962 section 4.6.
func ExtraDataForChain(cert ct.ASN1Cert, chain []ct.ASN1Cert, isPrecert bool) ([]byte, error) {
	var extra interface{}
	if isPrecert {
		// For a pre-cert, the extra data is a TLS-encoded PrecertChainEntry.
		extra = ct.PrecertChainEntry{
			PreCertificate:   cert,
			CertificateChain: chain,
		}
	} else {
		// For a certificate, the extra data is a TLS-encoded:
		//   ASN.1Cert certificate_chain<0..2^24-1>;
		// containing the chain after the leaf.
		extra = ct.CertificateChain{Entries: chain}
	}
	return tls.Marshal(extra)
}

// BuildLogLeafWithChainHash returns a Trillian LogLeaf structure for a
// (pre-)cert and the chain of certificates leading it up to a known root.
func BuildLogLeafWithChainHash(logPrefix string, merkleLeaf ct.MerkleTreeLeaf, leafIndex int64, cert ct.ASN1Cert, chainHash []byte, isPrecert bool) (*trillian.LogLeaf, error) {
	return buildLogLeaf(logPrefix, merkleLeaf, leafIndex, cert, nil, chainHash, isPrecert)
}

// ExtraDataForChainHash creates the extra data associated with a log entry as
// described in RFC6962 section 4.6 except the chain being replaced with its hash.
func ExtraDataForChainHash(cert ct.ASN1Cert, chainHash []byte, isPrecert bool) ([]byte, error) {
	var extra any

	if isPrecert {
		// For a pre-cert, the extra data is a TLS-encoded PrecertChainEntry.
		extra = ct.PrecertChainEntryHash{
			PreCertificate:    cert,
			IssuanceChainHash: chainHash,
		}
	} else {
		// For a certificate, the extra data is a TLS-encoded:
		//   ASN.1Cert certificate_chain<0..2^24-1>;
		// containing the chain after the leaf.
		extra = ct.CertificateChainHash{
			IssuanceChainHash: chainHash,
		}
	}
	return tls.Marshal(extra)
}

// buildLogLeaf builds the trillian.LogLeaf. The chainHash argument controls
// whether ExtraDataForChain or ExtraDataForChainHash method will be called.
// If chainHash is not nil, but neither is chain, then chain will be ignored.
func buildLogLeaf(logPrefix string, merkleLeaf ct.MerkleTreeLeaf, leafIndex int64, cert ct.ASN1Cert, chain []ct.ASN1Cert, chainHash []byte, isPrecert bool) (*trillian.LogLeaf, error) {
	leafData, err := tls.Marshal(merkleLeaf)
	if err != nil {
		klog.Warningf("%s: Failed to serialize Merkle leaf: %v", logPrefix, err)
		return nil, err
	}

	var extraData []byte
	if chainHash == nil {
		extraData, err = ExtraDataForChain(cert, chain, isPrecert)
	} else {
		extraData, err = ExtraDataForChainHash(cert, chainHash, isPrecert)
	}
	if err != nil {
		klog.Warningf("%s: Failed to serialize chain for ExtraData: %v", logPrefix, err)
		return nil, err
	}
	// leafIDHash allows Trillian to detect duplicate entries, so this should be
	// a hash over the cert data.
	leafIDHash := sha256.Sum256(cert.Data)
	return &trillian.LogLeaf{
		LeafValue:        leafData,
		ExtraData:        extraData,
		LeafIndex:        leafIndex,
		LeafIdentityHash: leafIDHash[:],
	}, nil
}
