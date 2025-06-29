// Copyright 2017 Google LLC. All Rights Reserved.
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

package integration

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/rand"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/OlegBabkin/certificate-transparency-go/client"
	"github.com/OlegBabkin/certificate-transparency-go/schedule"
	"github.com/OlegBabkin/certificate-transparency-go/tls"
	"github.com/OlegBabkin/certificate-transparency-go/trillian/ctfe"
	"github.com/OlegBabkin/certificate-transparency-go/trillian/ctfe/configpb"
	"github.com/OlegBabkin/certificate-transparency-go/x509"
	"github.com/google/trillian/monitoring"
	"github.com/transparency-dev/merkle"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	"k8s.io/klog/v2"

	ct "github.com/OlegBabkin/certificate-transparency-go"
)

const (
	// How many STHs and SCTs to hold on to.
	sthCount = 10
	sctCount = 10

	// How far beyond current tree size to request for invalid requests.
	invalidStretch = int64(1000000000)
)

var (
	// Metrics are all per-log (label "logid"), but may also be
	// per-entrypoint (label "ep") or per-return-code (label "rc").
	once        sync.Once
	reqs        monitoring.Counter   // logid, ep => value
	errs        monitoring.Counter   // logid, ep => value
	rsps        monitoring.Counter   // logid, ep, rc => value
	rspLatency  monitoring.Histogram // logid, ep, rc => values
	invalidReqs monitoring.Counter   // logid, ep => value
)

// setupMetrics initializes all the exported metrics.
func setupMetrics(mf monitoring.MetricFactory) {
	reqs = mf.NewCounter("reqs", "Number of valid requests sent", "logid", "ep")
	errs = mf.NewCounter("errs", "Number of error responses received for valid requests", "logid", "ep")
	rsps = mf.NewCounter("rsps", "Number of responses received for valid requests", "logid", "ep", "rc")
	rspLatency = mf.NewHistogram("rsp_latency", "Latency of valid responses in seconds", "logid", "ep", "rc")
	invalidReqs = mf.NewCounter("invalid_reqs", "Number of deliberately-invalid requests sent", "logid", "ep")
}

// errSkip indicates that a test operation should be skipped.
type errSkip struct{}

func (e errSkip) Error() string {
	return "test operation skipped"
}

// Choice represents a random decision about a hammer operation.
type Choice string

// Constants for per-operation choices.
const (
	ParamTooBig    = Choice("ParamTooBig")
	Param2TooBig   = Choice("Param2TooBig")
	ParamNegative  = Choice("ParamNegative")
	ParamInvalid   = Choice("ParamInvalid")
	ParamsInverted = Choice("ParamsInverted")
	InvalidBase64  = Choice("InvalidBase64")
	EmptyChain     = Choice("EmptyChain")
	CertNotPrecert = Choice("CertNotPrecert")
	PrecertNotCert = Choice("PrecertNotCert")
	NoChainToRoot  = Choice("NoChainToRoot")
	UnparsableCert = Choice("UnparsableCert")
	NewCert        = Choice("NewCert")
	LastCert       = Choice("LastCert")
	FirstCert      = Choice("FirstCert")
)

// Limiter is an interface to allow different rate limiters to be used with the
// hammer.
type Limiter interface {
	Wait(context.Context) error
}

type unLimited struct{}

func (u unLimited) Wait(ctx context.Context) error {
	return nil
}

// HammerConfig provides configuration for a stress/load test.
type HammerConfig struct {
	// Configuration for the log.
	LogCfg *configpb.LogConfig
	// How to create process-wide metrics.
	MetricFactory monitoring.MetricFactory
	// Maximum merge delay.
	MMD time.Duration
	// Certificate chain generator.
	ChainGenerator ChainGenerator
	// ClientPool provides the clients used to make requests.
	ClientPool ClientPool
	// Bias values to favor particular log operations.
	EPBias HammerBias
	// Range of how many entries to get.
	MinGetEntries, MaxGetEntries int
	// OversizedGetEntries governs whether get-entries requests that go beyond the
	// current tree size are allowed (with a truncated response expected).
	OversizedGetEntries bool
	// Number of operations to perform.
	Operations uint64
	// Rate limiter
	Limiter Limiter
	// MaxParallelChains sets the upper limit for the number of parallel
	// add-*-chain requests to make when the biasing model says to perform an add.
	MaxParallelChains int
	// EmitInterval defines how frequently stats are logged.
	EmitInterval time.Duration
	// IgnoreErrors controls whether a hammer run fails immediately on any error.
	IgnoreErrors bool
	// MaxRetryDuration governs how long to keep retrying when IgnoreErrors is true.
	MaxRetryDuration time.Duration
	// RequestDeadline indicates the deadline to set on each request to the log.
	RequestDeadline time.Duration
	// DuplicateChance sets the probability of attempting to add a duplicate when
	// calling add[-pre]-chain (as the N in 1-in-N). Set to 0 to disable sending
	// duplicates.
	DuplicateChance int
	// StrictSTHConsistencySize if set to true will cause Hammer to only request
	// STH consistency proofs between tree sizes for which it's seen valid STHs.
	// If set to false, Hammer will request a consistency proof between the
	// current tree size, and a random smaller size greater than zero.
	StrictSTHConsistencySize bool
}

// HammerBias indicates the bias for selecting different log operations.
type HammerBias struct {
	Bias  map[ctfe.EntrypointName]int
	total int
	// InvalidChance gives the odds of performing an invalid operation, as the N in 1-in-N.
	InvalidChance map[ctfe.EntrypointName]int
}

// Choose randomly picks an operation to perform according to the biases.
func (hb HammerBias) Choose() ctfe.EntrypointName {
	if hb.total == 0 {
		for _, ep := range ctfe.Entrypoints {
			hb.total += hb.Bias[ep]
		}
	}
	which := rand.Intn(hb.total)
	for _, ep := range ctfe.Entrypoints {
		which -= hb.Bias[ep]
		if which < 0 {
			return ep
		}
	}
	panic("random choice out of range")
}

// Invalid randomly chooses whether an operation should be invalid.
func (hb HammerBias) Invalid(ep ctfe.EntrypointName) bool {
	chance := hb.InvalidChance[ep]
	if chance <= 0 {
		return false
	}
	return rand.Intn(chance) == 0
}

type submittedCert struct {
	leafData    []byte
	leafHash    [sha256.Size]byte
	sct         *ct.SignedCertificateTimestamp
	integrateBy time.Time
	precert     bool
}

// pendingCerts holds certificates that have been submitted that we want
// to check inclusion proofs for.  The array is ordered from oldest to
// most recent, but new entries are only appended when enough time has
// passed since the last append, so the SCTs that get checked are spread
// out across the MMD period.
type pendingCerts struct {
	mu    sync.Mutex
	certs [sctCount]*submittedCert
}

func (pc *pendingCerts) empty() bool {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	return pc.certs[0] == nil
}

// tryAppendCert locks mu, checks whether it's possible to append the cert, and
// appends it if so.
func (pc *pendingCerts) tryAppendCert(now time.Time, mmd time.Duration, submitted *submittedCert) {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	if pc.canAppend(now, mmd) {
		which := 0
		for ; which < sctCount; which++ {
			if pc.certs[which] == nil {
				break
			}
		}
		pc.certs[which] = submitted
	}
}

// canAppend checks whether a pending cert can be appended.
// It must be called with mu locked.
func (pc *pendingCerts) canAppend(now time.Time, mmd time.Duration) bool {
	if pc.certs[sctCount-1] != nil {
		return false // full already
	}
	if pc.certs[0] == nil {
		return true // nothing yet
	}
	// Only allow append if enough time has passed, namely MMD/#savedSCTs.
	last := sctCount - 1
	for ; last >= 0; last-- {
		if pc.certs[last] != nil {
			break
		}
	}
	lastTime := timeFromMS(pc.certs[last].sct.Timestamp)
	nextTime := lastTime.Add(mmd / sctCount)
	return now.After(nextTime)
}

// oldestIfMMDPassed returns the oldest submitted certificate if the maximum
// merge delay has passed, i.e. it is expected to be integrated as of now.  This
// function locks mu.
func (pc *pendingCerts) oldestIfMMDPassed(now time.Time) *submittedCert {
	pc.mu.Lock()
	defer pc.mu.Unlock()

	if pc.certs[0] == nil {
		return nil
	}
	submitted := pc.certs[0]
	if !now.After(submitted.integrateBy) {
		// Oldest cert not due to be integrated yet, so neither will any others.
		return nil
	}
	return submitted
}

// dropOldest removes the oldest submitted certificate.
func (pc *pendingCerts) dropOldest() {
	pc.mu.Lock()
	defer pc.mu.Unlock()

	// Can pop the oldest cert and shuffle the others along, which make room for
	// another cert to be stored.
	for i := 0; i < (sctCount - 1); i++ {
		pc.certs[i] = pc.certs[i+1]
	}
	pc.certs[sctCount-1] = nil
}

// hammerState tracks the operations that have been performed during a test run, including
// earlier SCTs/STHs for later checking.
type hammerState struct {
	cfg *HammerConfig

	// Store the first submitted and the most recently submitted [pre-]chain,
	// to allow submission of both old and new duplicates.
	chainMu                     sync.Mutex
	firstChain, lastChain       []ct.ASN1Cert
	firstChainIntegrated        time.Time
	firstPreChain, lastPreChain []ct.ASN1Cert
	firstPreChainIntegrated     time.Time
	firstTBS, lastTBS           []byte

	mu sync.RWMutex
	// STHs are arranged from later to earlier (so [0] is the most recent), and the
	// discovery of new STHs will push older ones off the end.
	sth [sthCount]*ct.SignedTreeHead
	// Submitted certs also run from later to earlier, but the discovery of new SCTs
	// does not affect the existing contents of the array, so if the array is full it
	// keeps the same elements.  Instead, the oldest entry is removed (and a space
	// created) when we are able to get an inclusion proof for it.
	pending pendingCerts
	// Operations that are required to fix dependencies.
	nextOp []ctfe.EntrypointName

	hasher merkle.LogHasher
}

func newHammerState(cfg *HammerConfig) (*hammerState, error) {
	mf := cfg.MetricFactory
	if mf == nil {
		mf = monitoring.InertMetricFactory{}
	}
	once.Do(func() { setupMetrics(mf) })
	if cfg.MinGetEntries <= 0 {
		cfg.MinGetEntries = 1
	}
	if cfg.MaxGetEntries <= cfg.MinGetEntries {
		cfg.MaxGetEntries = cfg.MinGetEntries + 300
	}
	if cfg.EmitInterval <= 0 {
		cfg.EmitInterval = 10 * time.Second
	}
	if cfg.Limiter == nil {
		cfg.Limiter = unLimited{}
	}
	if cfg.MaxRetryDuration <= 0 {
		cfg.MaxRetryDuration = 60 * time.Second
	}

	if cfg.LogCfg.IsMirror {
		klog.Warningf("%v: disabling add-[pre-]chain for mirror log", cfg.LogCfg.Prefix)
		cfg.EPBias.Bias[ctfe.AddChainName] = 0
		cfg.EPBias.Bias[ctfe.AddPreChainName] = 0
	}

	state := hammerState{
		cfg:    cfg,
		nextOp: make([]ctfe.EntrypointName, 0),
		hasher: rfc6962.DefaultHasher,
	}
	return &state, nil
}

func (s *hammerState) client() *client.LogClient {
	return s.cfg.ClientPool.Next()
}

func (s *hammerState) lastTreeSize() uint64 {
	if s.sth[0] == nil {
		return 0
	}
	return s.sth[0].TreeSize
}

func (s *hammerState) needOps(ops ...ctfe.EntrypointName) {
	klog.V(2).Infof("need operations %+v to satisfy dependencies", ops)
	s.nextOp = append(s.nextOp, ops...)
}

// addMultiple calls the passed in function a random number
// (1 <= n < MaxParallelChains) of times.
// The first of any errors returned by calls to addOne will be returned by this function.
func (s *hammerState) addMultiple(ctx context.Context, addOne func(context.Context) error) error {
	var wg sync.WaitGroup
	numAdds := rand.Intn(s.cfg.MaxParallelChains) + 1
	klog.V(2).Infof("%s: do %d parallel add operations...", s.cfg.LogCfg.Prefix, numAdds)
	errs := make(chan error, numAdds)
	for i := 0; i < numAdds; i++ {
		wg.Add(1)
		go func() {
			if err := addOne(ctx); err != nil {
				errs <- err
			}
			wg.Done()
		}()
	}
	wg.Wait()
	klog.V(2).Infof("%s: do %d parallel add operations...done", s.cfg.LogCfg.Prefix, numAdds)
	select {
	case err := <-errs:
		return err
	default:
	}
	return nil
}

func (s *hammerState) getChain() (Choice, []ct.ASN1Cert, error) {
	s.chainMu.Lock()
	defer s.chainMu.Unlock()

	choice := s.chooseCertToAdd()
	// Override choice if necessary
	if s.lastChain == nil {
		choice = NewCert
	}
	if choice == FirstCert && time.Now().Before(s.firstChainIntegrated) {
		choice = NewCert
	}
	switch choice {
	case NewCert:
		chain, err := s.cfg.ChainGenerator.CertChain()
		if err != nil {
			return choice, nil, fmt.Errorf("failed to make fresh cert: %v", err)
		}
		if s.firstChain == nil {
			s.firstChain = chain
			s.firstChainIntegrated = time.Now().Add(s.cfg.MMD)
		}
		s.lastChain = chain
		return choice, chain, nil
	case FirstCert:
		return choice, s.firstChain, nil
	case LastCert:
		return choice, s.lastChain, nil
	}
	return choice, nil, fmt.Errorf("unhandled choice %s", choice)
}

func (s *hammerState) addChain(ctx context.Context) error {
	choice, chain, err := s.getChain()
	if err != nil {
		return fmt.Errorf("failed to make chain (%s): %v", choice, err)
	}

	sct, err := s.client().AddChain(ctx, chain)
	if err != nil {
		if err, ok := err.(client.RspError); ok {
			klog.Errorf("%s: add-chain(%s): error %v HTTP status %d body %s", s.cfg.LogCfg.Prefix, choice, err.Error(), err.StatusCode, err.Body)
		}
		return fmt.Errorf("failed to add-chain(%s): %v", choice, err)
	}
	klog.V(2).Infof("%s: Uploaded %s cert, got SCT(time=%q)", s.cfg.LogCfg.Prefix, choice, timeFromMS(sct.Timestamp))
	// Calculate leaf hash =  SHA256(0x00 | tls-encode(MerkleTreeLeaf))
	submitted := submittedCert{precert: false, sct: sct}
	leaf := ct.MerkleTreeLeaf{
		Version:  ct.V1,
		LeafType: ct.TimestampedEntryLeafType,
		TimestampedEntry: &ct.TimestampedEntry{
			Timestamp:  sct.Timestamp,
			EntryType:  ct.X509LogEntryType,
			X509Entry:  &(chain[0]),
			Extensions: sct.Extensions,
		},
	}
	submitted.integrateBy = timeFromMS(sct.Timestamp).Add(s.cfg.MMD)
	submitted.leafData, err = tls.Marshal(leaf)
	if err != nil {
		return fmt.Errorf("failed to tls.Marshal leaf cert: %v", err)
	}
	submitted.leafHash = sha256.Sum256(append([]byte{ct.TreeLeafPrefix}, submitted.leafData...))
	s.pending.tryAppendCert(time.Now(), s.cfg.MMD, &submitted)
	klog.V(3).Infof("%s: Uploaded %s cert has leaf-hash %x", s.cfg.LogCfg.Prefix, choice, submitted.leafHash)
	return nil
}

func (s *hammerState) addChainInvalid(ctx context.Context) error {
	choices := []Choice{EmptyChain, PrecertNotCert, NoChainToRoot, UnparsableCert}
	choice := choices[rand.Intn(len(choices))]

	var err error
	var chain []ct.ASN1Cert
	switch choice {
	case EmptyChain:
	case PrecertNotCert:
		chain, _, err = s.cfg.ChainGenerator.PreCertChain()
		if err != nil {
			return fmt.Errorf("failed to make chain(%s): %v", choice, err)
		}
	case NoChainToRoot:
		chain, err = s.cfg.ChainGenerator.CertChain()
		if err != nil {
			return fmt.Errorf("failed to make chain(%s): %v", choice, err)
		}
		// Drop the intermediate (chain[1]).
		chain = append(chain[:1], chain[2:]...)
	case UnparsableCert:
		chain, err = s.cfg.ChainGenerator.CertChain()
		if err != nil {
			return fmt.Errorf("failed to make chain(%s): %v", choice, err)
		}
		// Remove the initial ASN.1 SEQUENCE type byte (0x30) to make an unparsable cert.
		chain[0].Data[0] = 0x00
	default:
		klog.Exitf("Unhandled choice %s", choice)
	}

	sct, err := s.client().AddChain(ctx, chain)
	klog.V(3).Infof("invalid add-chain(%s) => error %v", choice, err)
	if err, ok := err.(client.RspError); ok {
		klog.V(3).Infof("   HTTP status %d body %s", err.StatusCode, err.Body)
	}
	if err == nil {
		return fmt.Errorf("unexpected success: add-chain(%s): %+v", choice, sct)
	}
	return nil
}

// chooseCertToAdd determines whether to add a new or pre-existing cert.
func (s *hammerState) chooseCertToAdd() Choice {
	if s.cfg.DuplicateChance > 0 && rand.Intn(s.cfg.DuplicateChance) == 0 {
		// TODO(drysdale): restore LastCert as an option
		return FirstCert
	}
	return NewCert
}

func (s *hammerState) getPreChain() (Choice, []ct.ASN1Cert, []byte, error) {
	s.chainMu.Lock()
	defer s.chainMu.Unlock()

	choice := s.chooseCertToAdd()
	// Override choice if necessary
	if s.lastPreChain == nil {
		choice = NewCert
	}
	if choice == FirstCert && time.Now().Before(s.firstPreChainIntegrated) {
		choice = NewCert
	}
	switch choice {
	case NewCert:
		prechain, tbs, err := s.cfg.ChainGenerator.PreCertChain()
		if err != nil {
			return choice, nil, nil, fmt.Errorf("failed to make fresh pre-cert: %v", err)
		}
		if s.firstPreChain == nil {
			s.firstPreChain = prechain
			s.firstPreChainIntegrated = time.Now().Add(s.cfg.MMD)
			s.firstTBS = tbs
		}
		s.lastPreChain = prechain
		s.lastTBS = tbs
		return choice, prechain, tbs, nil
	case FirstCert:
		return choice, s.firstPreChain, s.firstTBS, nil
	case LastCert:
		return choice, s.lastPreChain, s.lastTBS, nil
	}
	return choice, nil, nil, fmt.Errorf("unhandled choice %s", choice)
}

func (s *hammerState) addPreChain(ctx context.Context) error {
	choice, prechain, tbs, err := s.getPreChain()
	if err != nil {
		return fmt.Errorf("failed to make pre-cert chain (%s): %v", choice, err)
	}
	issuer, err := x509.ParseCertificate(prechain[1].Data)
	if err != nil {
		return fmt.Errorf("failed to parse pre-cert issuer: %v", err)
	}

	sct, err := s.client().AddPreChain(ctx, prechain)
	if err != nil {
		if err, ok := err.(client.RspError); ok {
			klog.Errorf("%s: add-pre-chain(%s): error %v HTTP status %d body %s", s.cfg.LogCfg.Prefix, choice, err.Error(), err.StatusCode, err.Body)
		}
		return fmt.Errorf("failed to add-pre-chain: %v", err)
	}
	klog.V(2).Infof("%s: Uploaded %s pre-cert, got SCT(time=%q)", s.cfg.LogCfg.Prefix, choice, timeFromMS(sct.Timestamp))

	// Calculate leaf hash =  SHA256(0x00 | tls-encode(MerkleTreeLeaf))
	submitted := submittedCert{precert: true, sct: sct}
	leaf := ct.MerkleTreeLeaf{
		Version:  ct.V1,
		LeafType: ct.TimestampedEntryLeafType,
		TimestampedEntry: &ct.TimestampedEntry{
			Timestamp: sct.Timestamp,
			EntryType: ct.PrecertLogEntryType,
			PrecertEntry: &ct.PreCert{
				IssuerKeyHash:  sha256.Sum256(issuer.RawSubjectPublicKeyInfo),
				TBSCertificate: tbs,
			},
			Extensions: sct.Extensions,
		},
	}
	submitted.integrateBy = timeFromMS(sct.Timestamp).Add(s.cfg.MMD)
	submitted.leafData, err = tls.Marshal(leaf)
	if err != nil {
		return fmt.Errorf("tls.Marshal(precertLeaf)=(nil,%v); want (_,nil)", err)
	}
	submitted.leafHash = sha256.Sum256(append([]byte{ct.TreeLeafPrefix}, submitted.leafData...))
	s.pending.tryAppendCert(time.Now(), s.cfg.MMD, &submitted)
	klog.V(3).Infof("%s: Uploaded %s pre-cert has leaf-hash %x", s.cfg.LogCfg.Prefix, choice, submitted.leafHash)
	return nil
}

func (s *hammerState) addPreChainInvalid(ctx context.Context) error {
	choices := []Choice{EmptyChain, CertNotPrecert, NoChainToRoot, UnparsableCert}
	choice := choices[rand.Intn(len(choices))]

	var err error
	var prechain []ct.ASN1Cert
	switch choice {
	case EmptyChain:
	case CertNotPrecert:
		prechain, err = s.cfg.ChainGenerator.CertChain()
		if err != nil {
			return fmt.Errorf("failed to make pre-chain(%s): %v", choice, err)
		}
	case NoChainToRoot:
		prechain, _, err = s.cfg.ChainGenerator.PreCertChain()
		if err != nil {
			return fmt.Errorf("failed to make pre-chain(%s): %v", choice, err)
		}
		// Drop the intermediate (prechain[1]).
		prechain = append(prechain[:1], prechain[2:]...)
	case UnparsableCert:
		prechain, _, err = s.cfg.ChainGenerator.PreCertChain()
		if err != nil {
			return fmt.Errorf("failed to make pre-chain(%s): %v", choice, err)
		}
		// Remove the initial ASN.1 SEQUENCE type byte (0x30) to make an unparsable cert.
		prechain[0].Data[0] = 0x00
	default:
		klog.Exitf("Unhandled choice %s", choice)
	}

	sct, err := s.client().AddPreChain(ctx, prechain)
	klog.V(3).Infof("invalid add-pre-chain(%s) => error %v", choice, err)
	if err, ok := err.(client.RspError); ok {
		klog.V(3).Infof("   HTTP status %d body %s", err.StatusCode, err.Body)
	}
	if err == nil {
		return fmt.Errorf("unexpected success: add-pre-chain: %+v", sct)
	}
	return nil
}

func (s *hammerState) getSTH(ctx context.Context) error {
	// Shuffle earlier STHs along.
	for i := sthCount - 1; i > 0; i-- {
		s.sth[i] = s.sth[i-1]
	}
	var err error
	s.sth[0], err = s.client().GetSTH(ctx)
	if err != nil {
		return fmt.Errorf("failed to get-sth: %v", err)
	}
	klog.V(2).Infof("%s: Got STH(time=%q, size=%d)", s.cfg.LogCfg.Prefix, timeFromMS(s.sth[0].Timestamp), s.sth[0].TreeSize)
	return nil
}

// chooseSTHs gets the current STH, and also picks an earlier STH.
func (s *hammerState) chooseSTHs(ctx context.Context) (*ct.SignedTreeHead, *ct.SignedTreeHead, error) {
	// Get current size, and pick an earlier size
	sthNow, err := s.client().GetSTH(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get-sth for current tree: %v", err)
	}
	which := rand.Intn(sthCount)
	if s.sth[which] == nil {
		klog.V(3).Infof("%s: skipping get-sth-consistency as no earlier STH", s.cfg.LogCfg.Prefix)
		s.needOps(ctfe.GetSTHName)
		return nil, sthNow, errSkip{}
	}
	if s.sth[which].TreeSize == 0 {
		klog.V(3).Infof("%s: skipping get-sth-consistency as no earlier STH", s.cfg.LogCfg.Prefix)
		s.needOps(ctfe.AddChainName, ctfe.GetSTHName)
		return nil, sthNow, errSkip{}
	}
	if s.sth[which].TreeSize == sthNow.TreeSize {
		klog.V(3).Infof("%s: skipping get-sth-consistency as same size (%d)", s.cfg.LogCfg.Prefix, sthNow.TreeSize)
		s.needOps(ctfe.AddChainName, ctfe.GetSTHName)
		return nil, sthNow, errSkip{}
	}
	return s.sth[which], sthNow, nil
}

func (s *hammerState) getSTHConsistency(ctx context.Context) error {
	sthOld, sthNow, err := s.chooseSTHs(ctx)
	if err != nil {
		// bail on actual errors
		if _, ok := err.(errSkip); !ok {
			return err
		}
		// If we're being asked to skip, it's because we don't have an earlier STH,
		// if the config says we must only use "known" STHs then we'll have to wait
		// until we get a larger STH.
		if s.cfg.StrictSTHConsistencySize {
			return err
		}

		// Otherwise, let's use our imagination and make one up, if possible...
		if sthNow.TreeSize < 2 {
			klog.V(3).Infof("%s: current STH size too small to invent a smaller STH for consistency proof (%d)", s.cfg.LogCfg.Prefix, sthNow.TreeSize)
			return errSkip{}
		}
		sthOld = &ct.SignedTreeHead{TreeSize: uint64(1 + rand.Int63n(int64(sthNow.TreeSize)))}
		klog.V(3).Infof("%s: Inventing a smaller STH size for consistency proof (%d)", s.cfg.LogCfg.Prefix, sthOld.TreeSize)
	}

	proof, err := s.client().GetSTHConsistency(ctx, sthOld.TreeSize, sthNow.TreeSize)
	if err != nil {
		return fmt.Errorf("failed to get-sth-consistency(%d, %d): %v", sthOld.TreeSize, sthNow.TreeSize, err)
	}
	if sthOld.Timestamp == 0 {
		klog.V(3).Infof("%s: Skipping consistency proof verification for invented STH", s.cfg.LogCfg.Prefix)
		return nil
	}

	if err := s.checkCTConsistencyProof(sthOld, sthNow, proof); err != nil {
		return fmt.Errorf("get-sth-consistency(%d, %d) proof check failed: %v", sthOld.TreeSize, sthNow.TreeSize, err)
	}
	klog.V(2).Infof("%s: Got STH consistency proof (size=%d => %d) len %d",
		s.cfg.LogCfg.Prefix, sthOld.TreeSize, sthNow.TreeSize, len(proof))
	return nil
}

func (s *hammerState) getSTHConsistencyInvalid(ctx context.Context) error {
	lastSize := s.lastTreeSize()
	if lastSize == 0 {
		return errSkip{}
	}

	choices := []Choice{ParamTooBig, ParamsInverted, ParamNegative, ParamInvalid}
	choice := choices[rand.Intn(len(choices))]

	var err error
	var proof [][]byte
	switch choice {
	case ParamTooBig:
		first := lastSize + uint64(invalidStretch)
		second := first + 100
		proof, err = s.client().GetSTHConsistency(ctx, first, second)
	case Param2TooBig:
		first := lastSize
		second := lastSize + uint64(invalidStretch)
		proof, err = s.client().GetSTHConsistency(ctx, first, second)
	case ParamsInverted:
		var sthOld, sthNow *ct.SignedTreeHead
		sthOld, sthNow, err = s.chooseSTHs(ctx)
		if err != nil {
			return err
		}
		proof, err = s.client().GetSTHConsistency(ctx, sthNow.TreeSize, sthOld.TreeSize)
	case ParamNegative, ParamInvalid:
		params := make(map[string]string)
		switch choice {
		case ParamNegative:
			params["first"] = "-3"
			params["second"] = "-1"
		case ParamInvalid:
			params["first"] = "foo"
			params["second"] = "bar"
		}
		// Need to use lower-level API to be able to use invalid parameters
		var resp ct.GetSTHConsistencyResponse
		var httpRsp *http.Response
		var body []byte
		httpRsp, body, err = s.client().GetAndParse(ctx, ct.GetSTHConsistencyPath, params, &resp)
		if err != nil && httpRsp != nil {
			err = client.RspError{Err: err, StatusCode: httpRsp.StatusCode, Body: body}
		}
		proof = resp.Consistency
	default:
		klog.Exitf("Unhandled choice %s", choice)
	}

	klog.V(3).Infof("invalid get-sth-consistency(%s) => error %v", choice, err)
	if err, ok := err.(client.RspError); ok {
		klog.V(3).Infof("   HTTP status %d body %s", err.StatusCode, err.Body)
	}
	if err == nil {
		return fmt.Errorf("unexpected success: get-sth-consistency(%s): %+v", choice, proof)
	}
	return nil
}

func (s *hammerState) getProofByHash(ctx context.Context) error {
	submitted := s.pending.oldestIfMMDPassed(time.Now())
	if submitted == nil {
		// No SCT that is guaranteed to be integrated, so move on.
		return errSkip{}
	}
	// Get an STH that should include this submitted [pre-]cert.
	sth, err := s.client().GetSTH(ctx)
	if err != nil {
		return fmt.Errorf("failed to get-sth for proof: %v", err)
	}
	// Get and check an inclusion proof.
	rsp, err := s.client().GetProofByHash(ctx, submitted.leafHash[:], sth.TreeSize)
	if err != nil {
		return fmt.Errorf("failed to get-proof-by-hash(size=%d) on cert with SCT @ %v: %v, %+v", sth.TreeSize, timeFromMS(submitted.sct.Timestamp), err, rsp)
	}
	if err := proof.VerifyInclusion(s.hasher, uint64(rsp.LeafIndex), sth.TreeSize, submitted.leafHash[:], rsp.AuditPath, sth.SHA256RootHash[:]); err != nil {
		return fmt.Errorf("failed to VerifyInclusion(%d, %d)=%v", rsp.LeafIndex, sth.TreeSize, err)
	}
	s.pending.dropOldest()
	return nil
}

func (s *hammerState) getProofByHashInvalid(ctx context.Context) error {
	lastSize := s.lastTreeSize()
	if lastSize == 0 {
		return errSkip{}
	}
	submitted := s.pending.oldestIfMMDPassed(time.Now())

	choices := []Choice{ParamInvalid, ParamTooBig, ParamNegative, InvalidBase64}
	choice := choices[rand.Intn(len(choices))]

	var err error
	var rsp *ct.GetProofByHashResponse
	switch choice {
	case ParamInvalid:
		rsp, err = s.client().GetProofByHash(ctx, []byte{0x01, 0x02}, 1) // Hash too short
	case ParamTooBig:
		if submitted == nil {
			return errSkip{}
		}
		rsp, err = s.client().GetProofByHash(ctx, submitted.leafHash[:], lastSize+uint64(invalidStretch))
	case ParamNegative, InvalidBase64:
		params := make(map[string]string)
		switch choice {
		case ParamNegative:
			if submitted == nil {
				return errSkip{}
			}
			params["tree_size"] = "-1"
			params["hash"] = base64.StdEncoding.EncodeToString(submitted.leafHash[:])
		case InvalidBase64:
			params["tree_size"] = "1"
			params["hash"] = "@^()"
		}
		var r ct.GetProofByHashResponse
		rsp = &r
		var httpRsp *http.Response
		var body []byte
		httpRsp, body, err = s.client().GetAndParse(ctx, ct.GetProofByHashPath, params, &r)
		if err != nil && httpRsp != nil {
			err = client.RspError{Err: err, StatusCode: httpRsp.StatusCode, Body: body}
		}
	default:
		klog.Exitf("Unhandled choice %s", choice)
	}

	klog.V(3).Infof("invalid get-proof-by-hash(%s) => error %v", choice, err)
	if err, ok := err.(client.RspError); ok {
		klog.V(3).Infof("   HTTP status %d body %s", err.StatusCode, err.Body)
	}
	if err == nil {
		return fmt.Errorf("unexpected success: get-proof-by-hash(%s): %+v", choice, rsp)
	}
	return nil
}

func (s *hammerState) getEntries(ctx context.Context) error {
	if s.sth[0] == nil {
		klog.V(3).Infof("%s: skipping get-entries as no earlier STH", s.cfg.LogCfg.Prefix)
		s.needOps(ctfe.GetSTHName)
		return errSkip{}
	}
	lastSize := s.lastTreeSize()
	if lastSize == 0 {
		if s.pending.empty() {
			klog.V(3).Infof("%s: skipping get-entries as tree size 0", s.cfg.LogCfg.Prefix)
			s.needOps(ctfe.AddChainName, ctfe.GetSTHName)
			return errSkip{}
		}
		klog.V(3).Infof("%s: skipping get-entries as STH stale", s.cfg.LogCfg.Prefix)
		s.needOps(ctfe.GetSTHName)
		return errSkip{}
	}
	// Entry indices are zero-based, and may or may not be allowed to extend
	// beyond current tree size (RFC 6962 s4.6).
	first := rand.Intn(int(lastSize))
	span := s.cfg.MaxGetEntries - s.cfg.MinGetEntries
	count := s.cfg.MinGetEntries + rand.Intn(int(span))
	last := first + count

	if !s.cfg.OversizedGetEntries && last >= int(lastSize) {
		last = int(lastSize) - 1
	}

	entries, err := s.client().GetEntries(ctx, int64(first), int64(last))
	if err != nil {
		return fmt.Errorf("failed to get-entries(%d,%d): %v", first, last, err)
	}
	for i, entry := range entries {
		if want := int64(first + i); entry.Index != want {
			return fmt.Errorf("leaf[%d].LeafIndex=%d; want %d", i, entry.Index, want)
		}
		leaf := entry.Leaf
		if leaf.Version != 0 {
			return fmt.Errorf("leaf[%d].Version=%v; want V1(0)", i, leaf.Version)
		}
		if leaf.LeafType != ct.TimestampedEntryLeafType {
			return fmt.Errorf("leaf[%d].Version=%v; want TimestampedEntryLeafType", i, leaf.LeafType)
		}
		ts := leaf.TimestampedEntry
		if ts.EntryType != ct.X509LogEntryType && ts.EntryType != ct.PrecertLogEntryType {
			return fmt.Errorf("leaf[%d].ts.EntryType=%v; want {X509,Precert}LogEntryType", i, ts.EntryType)
		}
	}
	klog.V(2).Infof("%s: Got entries [%d:%d)\n", s.cfg.LogCfg.Prefix, first, first+len(entries))
	return nil
}

func (s *hammerState) getEntriesInvalid(ctx context.Context) error {
	lastSize := s.lastTreeSize()
	if lastSize == 0 {
		return errSkip{}
	}

	choices := []Choice{ParamTooBig, ParamNegative, ParamsInverted}
	choice := choices[rand.Intn(len(choices))]

	var first, last int64
	switch choice {
	case ParamTooBig:
		last = int64(lastSize) + invalidStretch
		first = last - 4
	case ParamNegative:
		first = -2
		last = 10
	case ParamsInverted:
		first = 10
		last = 5
	default:
		klog.Exitf("Unhandled choice %s", choice)
	}

	entries, err := s.client().GetEntries(ctx, first, last)
	klog.V(3).Infof("invalid get-entries(%s) => error %v", choice, err)
	if err, ok := err.(client.RspError); ok {
		klog.V(3).Infof("   HTTP status %d body %s", err.StatusCode, err.Body)
	}
	if err == nil {
		return fmt.Errorf("unexpected success: get-entries(%d,%d): %d entries", first, last, len(entries))
	}
	return nil
}

func (s *hammerState) getRoots(ctx context.Context) error {
	roots, err := s.client().GetAcceptedRoots(ctx)
	if err != nil {
		return fmt.Errorf("failed to get-roots: %v", err)
	}
	klog.V(2).Infof("%s: Got roots (len=%d)", s.cfg.LogCfg.Prefix, len(roots))
	return nil
}

func sthSize(sth *ct.SignedTreeHead) string {
	if sth == nil {
		return "n/a"
	}
	return fmt.Sprintf("%d", sth.TreeSize)
}

func (s *hammerState) label() string {
	return strconv.FormatInt(s.cfg.LogCfg.LogId, 10)
}

func (s *hammerState) String() string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	details := ""
	statusOK := strconv.Itoa(http.StatusOK)
	totalReqs := 0
	totalInvalidReqs := 0
	totalErrs := 0
	for _, ep := range ctfe.Entrypoints {
		reqCount := int(reqs.Value(s.label(), string(ep)))
		totalReqs += reqCount
		if s.cfg.EPBias.Bias[ep] > 0 {
			details += fmt.Sprintf(" %s=%d/%d", ep, int(rsps.Value(s.label(), string(ep), statusOK)), reqCount)
		}
		totalInvalidReqs += int(invalidReqs.Value(s.label(), string(ep)))
		totalErrs += int(errs.Value(s.label(), string(ep)))
	}
	return fmt.Sprintf("%10s: lastSTH.size=%s ops: total=%d invalid=%d errs=%v%s", s.cfg.LogCfg.Prefix, sthSize(s.sth[0]), totalReqs, totalInvalidReqs, totalErrs, details)
}

func (s *hammerState) performOp(ctx context.Context, ep ctfe.EntrypointName) (int, error) {
	if err := s.cfg.Limiter.Wait(ctx); err != nil {
		return http.StatusRequestTimeout, fmt.Errorf("Limiter.Wait(): %v", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.cfg.RequestDeadline > 0 {
		cctx, cancel := context.WithTimeout(ctx, s.cfg.RequestDeadline)
		defer cancel()
		ctx = cctx
	}

	status := http.StatusOK
	var err error
	switch ep {
	case ctfe.AddChainName:
		err = s.addMultiple(ctx, s.addChain)
	case ctfe.AddPreChainName:
		err = s.addMultiple(ctx, s.addPreChain)
	case ctfe.GetSTHName:
		err = s.getSTH(ctx)
	case ctfe.GetSTHConsistencyName:
		err = s.getSTHConsistency(ctx)
	case ctfe.GetProofByHashName:
		err = s.getProofByHash(ctx)
	case ctfe.GetEntriesName:
		err = s.getEntries(ctx)
	case ctfe.GetRootsName:
		err = s.getRoots(ctx)
	case ctfe.GetEntryAndProofName:
		status = http.StatusNotImplemented
		klog.V(2).Infof("%s: hammering entrypoint %s not yet implemented", s.cfg.LogCfg.Prefix, ep)
	default:
		err = fmt.Errorf("internal error: unknown entrypoint %s selected", ep)
	}
	return status, err
}

func (s *hammerState) performInvalidOp(ctx context.Context, ep ctfe.EntrypointName) error {
	if err := s.cfg.Limiter.Wait(ctx); err != nil {
		return fmt.Errorf("Limiter.Wait(): %v", err)
	}
	switch ep {
	case ctfe.AddChainName:
		return s.addChainInvalid(ctx)
	case ctfe.AddPreChainName:
		return s.addPreChainInvalid(ctx)
	case ctfe.GetSTHConsistencyName:
		return s.getSTHConsistencyInvalid(ctx)
	case ctfe.GetProofByHashName:
		return s.getProofByHashInvalid(ctx)
	case ctfe.GetEntriesName:
		return s.getEntriesInvalid(ctx)
	case ctfe.GetSTHName, ctfe.GetRootsName:
		return fmt.Errorf("no invalid request possible for entrypoint %s", ep)
	case ctfe.GetEntryAndProofName:
		return fmt.Errorf("hammering entrypoint %s not yet implemented", ep)
	}
	return fmt.Errorf("internal error: unknown entrypoint %s", ep)
}

func (s *hammerState) chooseOp() (ctfe.EntrypointName, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.nextOp) > 0 {
		ep := s.nextOp[0]
		s.nextOp = s.nextOp[1:]
		if s.cfg.EPBias.Bias[ep] > 0 {
			return ep, false
		}
	}
	ep := s.cfg.EPBias.Choose()
	return ep, s.cfg.EPBias.Invalid(ep)
}

// Perform a random operation on the log, retrying if necessary. If non-empty, the
// returned entrypoint should be performed next to unblock dependencies.
func (s *hammerState) retryOneOp(ctx context.Context) error {
	ep, invalid := s.chooseOp()
	if invalid {
		klog.V(3).Infof("perform invalid %s operation", ep)
		invalidReqs.Inc(s.label(), string(ep))
		err := s.performInvalidOp(ctx, ep)
		if _, ok := err.(errSkip); ok {
			klog.V(2).Infof("invalid operation %s was skipped", ep)
			return nil
		}
		return err
	}

	klog.V(3).Infof("perform %s operation", ep)
	deadline := time.Now().Add(s.cfg.MaxRetryDuration)

	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		start := time.Now()
		reqs.Inc(s.label(), string(ep))
		status, err := s.performOp(ctx, ep)
		period := time.Since(start)
		rspLatency.Observe(period.Seconds(), s.label(), string(ep), strconv.Itoa(status))

		switch err.(type) {
		case nil:
			rsps.Inc(s.label(), string(ep), strconv.Itoa(status))
			return nil
		case errSkip:
			klog.V(2).Infof("operation %s was skipped", ep)
			return nil
		default:
			errs.Inc(s.label(), string(ep))
			if s.cfg.IgnoreErrors {
				left := time.Until(deadline)
				if left < 0 {
					klog.Warningf("%s: gave up retrying failed op %v after %v, returning last err: %v", s.cfg.LogCfg.Prefix, ep, s.cfg.MaxRetryDuration, err)
					return err
				}
				klog.Warningf("%s: op %v failed after %v (will retry for %v more): %v", s.cfg.LogCfg.Prefix, ep, period, left, err)
			} else {
				return err
			}
		}
	}
}

// checkCTConsistencyProof checks the given consistency proof.
func (s *hammerState) checkCTConsistencyProof(sth1, sth2 *ct.SignedTreeHead, pf [][]byte) error {
	return proof.VerifyConsistency(s.hasher, sth1.TreeSize, sth2.TreeSize, pf, sth1.SHA256RootHash[:], sth2.SHA256RootHash[:])
}

// HammerCTLog performs load/stress operations according to given config.
func HammerCTLog(ctx context.Context, cfg HammerConfig) error {
	s, err := newHammerState(&cfg)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	go schedule.Every(ctx, cfg.EmitInterval, func(ctx context.Context) {
		klog.Info(s.String())
	})

	for count := uint64(1); count < cfg.Operations; count++ {
		if err := s.retryOneOp(ctx); err != nil {
			return err
		}
		// Terminate from the loop if the context is cancelled.
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	klog.Infof("%s: completed %d operations on log", cfg.LogCfg.Prefix, cfg.Operations)

	return nil
}
