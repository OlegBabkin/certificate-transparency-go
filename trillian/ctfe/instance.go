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

package ctfe

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/OlegBabkin/certificate-transparency-go/asn1"
	"github.com/OlegBabkin/certificate-transparency-go/schedule"
	"github.com/OlegBabkin/certificate-transparency-go/trillian/ctfe/cache"
	"github.com/OlegBabkin/certificate-transparency-go/trillian/ctfe/storage"
	"github.com/OlegBabkin/certificate-transparency-go/trillian/util"
	"github.com/OlegBabkin/certificate-transparency-go/x509"
	"github.com/OlegBabkin/certificate-transparency-go/x509util"
	"github.com/google/trillian"
	"github.com/google/trillian/crypto/keys"
	"github.com/google/trillian/monitoring"
	"golang.org/x/time/rate"
	"k8s.io/klog/v2"
)

// InstanceOptions describes the options for a log instance.
type InstanceOptions struct {
	// Validated holds the original configuration options for the log, and some
	// of its fields parsed as a result of validating it.
	Validated *ValidatedLogConfig
	// Client is a corresponding Trillian log client.
	Client trillian.TrillianLogClient
	// Deadline is a timeout for Trillian RPC requests.
	Deadline time.Duration
	// MetricFactory allows creating metrics.
	MetricFactory monitoring.MetricFactory
	// ErrorMapper converts an error from an RPC request to an HTTP status, plus
	// a boolean to indicate whether the conversion succeeded.
	ErrorMapper func(error) (int, bool)
	// RequestLog provides structured logging of CTFE requests.
	RequestLog RequestLog
	// RemoteUser returns a string representing the originating host for the
	// given request. This string will be used as a User quota key.
	// If unset, no quota will be requested for remote users.
	RemoteQuotaUser func(*http.Request) string
	// CertificateQuotaUser returns a string representing the passed in
	// intermediate certificate. This string will be user as a User quota key for
	// the cert. Quota will be requested for each intermediate in an
	// add-[pre]-chain request so as to allow individual issuers to be rate
	// limited. If unset, no quota will be requested for intermediate
	// certificates.
	CertificateQuotaUser func(*x509.Certificate) string
	// FreshSubmissionMaxAge is the maximum age of a fresh submission.
	// Freshness is determined by comparing the NotBefore timestamp of
	// the first certificate in the submitted chain against the current time.
	FreshSubmissionMaxAge time.Duration
	// NonFreshSubmissionLimiter limits the rate at which this log instance
	// will accept non-fresh submissions.
	// This is used to prevent the log from being flooded with requests for
	// "old" certificates.
	NonFreshSubmissionLimiter *rate.Limiter
	// STHStorage provides STHs of a source log for the mirror. Only mirror
	// instances will use it, i.e. when IsMirror == true in the config. If it is
	// empty then the DefaultMirrorSTHStorage will be used.
	STHStorage MirrorSTHStorage
	// MaskInternalErrors indicates if internal server errors should be masked
	// or returned to the user containing the full error message.
	MaskInternalErrors bool
	// CacheType is the CTFE cache type.
	CacheType cache.Type
	// CacheOption includes the cache size and time-to-live (TTL).
	CacheOption cache.Option
}

// Instance is a set up log/mirror instance. It must be created with the
// SetUpInstance call.
type Instance struct {
	Handlers  PathHandlers
	STHGetter STHGetter
	li        *logInfo
}

// RunUpdateSTH regularly updates the Instance STH so our metrics stay
// up-to-date with any tree head changes that are not triggered by us.
func (i *Instance) RunUpdateSTH(ctx context.Context, period time.Duration) {
	c := i.li.instanceOpts.Validated.Config
	klog.Infof("Start internal get-sth operations on %v (%d)", c.Prefix, c.LogId)
	schedule.Every(ctx, period, func(ctx context.Context) {
		klog.V(1).Infof("Force internal get-sth for %v (%d)", c.Prefix, c.LogId)
		if _, err := i.li.getSTH(ctx); err != nil {
			klog.Warningf("Failed to retrieve STH for %v (%d): %v", c.Prefix, c.LogId, err)
		}
	})
}

// GetPublicKey returns the public key from the instance's signer.
func (i *Instance) GetPublicKey() crypto.PublicKey {
	if i.li != nil && i.li.signer != nil {
		return i.li.signer.Public()
	}
	return nil
}

// SetUpInstance sets up a log (or log mirror) instance using the provided
// configuration, and returns an object containing a set of handlers for this
// log, and an STH getter.
func SetUpInstance(ctx context.Context, opts InstanceOptions) (*Instance, error) {
	logInfo, err := setUpLogInfo(ctx, opts)
	if err != nil {
		return nil, err
	}
	handlers := logInfo.Handlers(opts.Validated.Config.Prefix)
	return &Instance{Handlers: handlers, STHGetter: logInfo.sthGetter, li: logInfo}, nil
}

func setUpLogInfo(ctx context.Context, opts InstanceOptions) (*logInfo, error) {
	vCfg := opts.Validated
	cfg := vCfg.Config

	// Check config validity.
	if !cfg.IsMirror && len(cfg.RootsPemFile) == 0 {
		return nil, errors.New("need to specify RootsPemFile")
	}
	// Load the trusted roots.
	roots := x509util.NewPEMCertPool()
	for _, pemFile := range cfg.RootsPemFile {
		if err := roots.AppendCertsFromPEMFile(pemFile); err != nil {
			return nil, fmt.Errorf("failed to read trusted roots: %v", err)
		}
	}

	var signer crypto.Signer
	if !cfg.IsMirror {
		var err error
		if signer, err = keys.NewSigner(ctx, vCfg.PrivKey); err != nil {
			return nil, fmt.Errorf("failed to load private key: %v", err)
		}

		// If a public key has been configured for a log, check that it is consistent with the private key.
		if vCfg.PubKey != nil {
			switch pub := vCfg.PubKey.(type) {
			case *ecdsa.PublicKey:
				if !pub.Equal(signer.Public()) {
					return nil, errors.New("public key is not consistent with private key")
				}
			case ed25519.PublicKey:
				if !pub.Equal(signer.Public()) {
					return nil, errors.New("public key is not consistent with private key")
				}
			case *rsa.PublicKey:
				if !pub.Equal(signer.Public()) {
					return nil, errors.New("public key is not consistent with private key")
				}
			default:
				return nil, errors.New("failed to verify consistency of public key with private key")
			}
		}
	}

	validationOpts := CertValidationOpts{
		trustedRoots:    roots,
		rejectExpired:   cfg.RejectExpired,
		rejectUnexpired: cfg.RejectUnexpired,
		notAfterStart:   vCfg.NotAfterStart,
		notAfterLimit:   vCfg.NotAfterLimit,
		acceptOnlyCA:    cfg.AcceptOnlyCa,
		extKeyUsages:    vCfg.KeyUsages,
	}
	var err error
	validationOpts.rejectExtIds, err = parseOIDs(cfg.RejectExtensions)
	if err != nil {
		return nil, fmt.Errorf("failed to parse RejectExtensions: %v", err)
	}

	// Initialise IssuanceChainService with IssuanceChainStorage and IssuanceChainCache.
	issuanceChainStorage, err := storage.NewIssuanceChainStorage(ctx, vCfg.ExtraDataIssuanceChainStorageBackend, vCfg.CTFEStorageConnectionString)
	if err != nil {
		return nil, err
	}
	if issuanceChainStorage == nil {
		return newLogInfo(opts, validationOpts, signer, new(util.SystemTimeSource), &directIssuanceChainService{}), nil
	}

	// We are storing chains outside of Trillian, so set up cache and service.
	issuanceChainCache, err := cache.NewIssuanceChainCache(ctx, opts.CacheType, opts.CacheOption)
	if err != nil {
		return nil, err
	}

	issuanceChainService := newIndirectIssuanceChainService(issuanceChainStorage, issuanceChainCache)

	logInfo := newLogInfo(opts, validationOpts, signer, new(util.SystemTimeSource), issuanceChainService)
	return logInfo, nil
}

func parseOIDs(oids []string) ([]asn1.ObjectIdentifier, error) {
	ret := make([]asn1.ObjectIdentifier, 0, len(oids))
	for _, s := range oids {
		bits := strings.Split(s, ".")
		var oid asn1.ObjectIdentifier
		for _, n := range bits {
			p, err := strconv.Atoi(n)
			if err != nil {
				return nil, err
			}
			oid = append(oid, p)
		}
		ret = append(ret, oid)
	}
	return ret, nil
}
