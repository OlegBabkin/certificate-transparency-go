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
	"crypto/sha256"
	"sort"

	"github.com/OlegBabkin/certificate-transparency-go/x509"
)

const hashSize = sha256.Size

var newHash = sha256.New

func hash(c *x509.Certificate) (hash [hashSize]byte) {
	copy(hash[:], newHash().Sum(c.Raw))
	return
}

func hashChain(ch []*x509.Certificate) (hash [hashSize]byte) {
	h := newHash()
	for _, c := range ch {
		h.Write(newHash().Sum(c.Raw))
	}
	copy(hash[:], h.Sum(nil))
	return
}

// hashBag hashes all of the certs in the chain, irrespective of their order.
// Chains containing the same certs in the same order with no duplicates will
// result in the same hash. Chains containing the same certs in different orders
// with no duplicates will result in the same hash.  Chains containing the same
// certs (either in the same order or in different orders) that contain exactly
// the same duplicated certs, will result in the same hash.  If chains contain
// the same certs (either in the same order or in different orders) and some
// certs are duplicated, but the specific certs that are duplicated differ
// and/or the number of times they are duplicated differ, these chains will
// result in different hashes.
func hashBag(chain []*x509.Certificate) [hashSize]byte {
	b := bag{certs: make([]*x509.Certificate, len(chain))}
	copy(b.certs, chain)
	sort.Sort(b)
	return hashChain(b.certs)
}

// bag is a collection of certificates that can contain duplicates.
// Applying sort will order them by their raw representation.
type bag struct {
	certs []*x509.Certificate
}

// Len implements sort.Sort(data Interface) for bag.
func (b bag) Len() int { return len(b.certs) }

// Less implements sort.Sort(data Interface) for bag.
func (b bag) Less(i, j int) bool {
	ci := b.certs[i].Raw
	cj := b.certs[j].Raw
	if len(ci) != len(cj) {
		return len(ci) < len(cj)
	}
	for n := range ci {
		if ci[n] < cj[n] {
			return true
		}
		if ci[n] > cj[n] {
			return false
		}
	}
	return false
}

// Swap implements sort.Sort(data Interface) for bag.
func (b bag) Swap(i, j int) {
	t := b.certs[i]
	b.certs[i] = b.certs[j]
	b.certs[j] = t
}
