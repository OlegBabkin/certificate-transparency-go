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
	"errors"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	ct "github.com/OlegBabkin/certificate-transparency-go"
	"github.com/OlegBabkin/certificate-transparency-go/trillian/ctfe/cache"
	"github.com/OlegBabkin/certificate-transparency-go/trillian/ctfe/configpb"
	"github.com/google/trillian/crypto/keys"
	"github.com/google/trillian/crypto/keys/pem"
	"github.com/google/trillian/crypto/keyspb"
	"github.com/google/trillian/monitoring"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func init() {
	keys.RegisterHandler(&keyspb.PEMKeyFile{}, pem.FromProto)
}

func TestSetUpInstance(t *testing.T) {
	ctx := context.Background()

	privKey := mustMarshalAny(&keyspb.PEMKeyFile{Path: "../testdata/ct-http-server.privkey.pem", Password: "dirk"})
	missingPrivKey := mustMarshalAny(&keyspb.PEMKeyFile{Path: "../testdata/bogus.privkey.pem", Password: "dirk"})
	wrongPassPrivKey := mustMarshalAny(&keyspb.PEMKeyFile{Path: "../testdata/ct-http-server.privkey.pem", Password: "dirkly"})
	pubKey := mustReadPublicKey("../testdata/ct-http-server.pubkey.pem")

	var tests = []struct {
		desc    string
		cfg     *configpb.LogConfig
		wantErr string
	}{
		{
			desc: "valid",
			cfg: &configpb.LogConfig{
				LogId:        1,
				Prefix:       "log",
				RootsPemFile: []string{"../testdata/fake-ca.cert"},
				PrivateKey:   privKey,
			},
		},
		{
			desc: "valid-mirror",
			cfg: &configpb.LogConfig{
				LogId:        1,
				Prefix:       "log",
				RootsPemFile: []string{"../testdata/fake-ca.cert"},
				PublicKey:    pubKey,
				IsMirror:     true,
			},
		},
		{
			desc: "no-roots",
			cfg: &configpb.LogConfig{
				LogId:      1,
				Prefix:     "log",
				PrivateKey: privKey,
			},
			wantErr: "specify RootsPemFile",
		},
		{
			desc: "no-roots-mirror",
			cfg: &configpb.LogConfig{
				LogId:     1,
				Prefix:    "log",
				PublicKey: pubKey,
				IsMirror:  true,
			},
		},
		{
			desc: "missing-root-cert",
			cfg: &configpb.LogConfig{
				LogId:        1,
				Prefix:       "log",
				RootsPemFile: []string{"../testdata/bogus.cert"},
				PrivateKey:   privKey,
			},
			wantErr: "failed to read trusted roots",
		},
		{
			desc: "missing-privkey",
			cfg: &configpb.LogConfig{
				LogId:        1,
				Prefix:       "log",
				RootsPemFile: []string{"../testdata/fake-ca.cert"},
				PrivateKey:   missingPrivKey,
			},
			wantErr: "failed to load private key",
		},
		{
			desc: "privkey-wrong-password",
			cfg: &configpb.LogConfig{
				LogId:        1,
				Prefix:       "log",
				RootsPemFile: []string{"../testdata/fake-ca.cert"},
				PrivateKey:   wrongPassPrivKey,
			},
			wantErr: "failed to load private key",
		},
		{
			desc: "valid-ekus-1",
			cfg: &configpb.LogConfig{
				LogId:        1,
				Prefix:       "log",
				RootsPemFile: []string{"../testdata/fake-ca.cert"},
				PrivateKey:   privKey,
				ExtKeyUsages: []string{"Any"},
			},
		},
		{
			desc: "valid-ekus-2",
			cfg: &configpb.LogConfig{
				LogId:        1,
				Prefix:       "log",
				RootsPemFile: []string{"../testdata/fake-ca.cert"},
				PrivateKey:   privKey,
				ExtKeyUsages: []string{"Any", "ServerAuth", "TimeStamping"},
			},
		},
		{
			desc: "valid-reject-ext",
			cfg: &configpb.LogConfig{
				LogId:            1,
				Prefix:           "log",
				RootsPemFile:     []string{"../testdata/fake-ca.cert"},
				PrivateKey:       privKey,
				RejectExtensions: []string{"1.2.3.4", "5.6.7.8"},
			},
		},
		{
			desc: "invalid-reject-ext",
			cfg: &configpb.LogConfig{
				LogId:            1,
				Prefix:           "log",
				RootsPemFile:     []string{"../testdata/fake-ca.cert"},
				PrivateKey:       privKey,
				RejectExtensions: []string{"1.2.3.4", "one.banana.two.bananas"},
			},
			wantErr: "one",
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			vCfg, err := ValidateLogConfig(test.cfg)
			if err != nil {
				t.Fatalf("ValidateLogConfig(): %v", err)
			}
			opts := InstanceOptions{Validated: vCfg, Deadline: time.Second, MetricFactory: monitoring.InertMetricFactory{}}

			if _, err := SetUpInstance(ctx, opts); err != nil {
				if test.wantErr == "" {
					t.Errorf("SetUpInstance()=_,%v; want _,nil", err)
				} else if !strings.Contains(err.Error(), test.wantErr) {
					t.Errorf("SetUpInstance()=_,%v; want err containing %q", err, test.wantErr)
				}
				return
			}
			if test.wantErr != "" {
				t.Errorf("SetUpInstance()=_,nil; want err containing %q", test.wantErr)
			}
		})
	}
}

func equivalentTimes(a *time.Time, b *timestamppb.Timestamp) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil {
		// b can't be nil as it would have returned above.
		return false
	}
	tsA := timestamppb.New(*a)
	return tsA.AsTime().Format(time.RFC3339Nano) == b.AsTime().Format(time.RFC3339Nano)
}

func TestSetUpInstanceSetsValidationOpts(t *testing.T) {
	ctx := context.Background()

	start := timestamppb.New(time.Unix(10000, 0))
	limit := timestamppb.New(time.Unix(12000, 0))

	privKey, err := anypb.New(&keyspb.PEMKeyFile{Path: "../testdata/ct-http-server.privkey.pem", Password: "dirk"})
	if err != nil {
		t.Fatalf("Could not marshal private key proto: %v", err)
	}
	var tests = []struct {
		desc string
		cfg  *configpb.LogConfig
	}{
		{
			desc: "no validation opts",
			cfg: &configpb.LogConfig{
				LogId:        1,
				Prefix:       "/log",
				RootsPemFile: []string{"../testdata/fake-ca.cert"},
				PrivateKey:   privKey,
			},
		},
		{
			desc: "notAfterStart only",
			cfg: &configpb.LogConfig{
				LogId:         1,
				Prefix:        "/log",
				RootsPemFile:  []string{"../testdata/fake-ca.cert"},
				PrivateKey:    privKey,
				NotAfterStart: start,
			},
		},
		{
			desc: "notAfter range",
			cfg: &configpb.LogConfig{
				LogId:         1,
				Prefix:        "/log",
				RootsPemFile:  []string{"../testdata/fake-ca.cert"},
				PrivateKey:    privKey,
				NotAfterStart: start,
				NotAfterLimit: limit,
			},
		},
		{
			desc: "caOnly",
			cfg: &configpb.LogConfig{
				LogId:        1,
				Prefix:       "/log",
				RootsPemFile: []string{"../testdata/fake-ca.cert"},
				PrivateKey:   privKey,
				AcceptOnlyCa: true,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			vCfg, err := ValidateLogConfig(test.cfg)
			if err != nil {
				t.Fatalf("ValidateLogConfig(): %v", err)
			}
			opts := InstanceOptions{Validated: vCfg, Deadline: time.Second, MetricFactory: monitoring.InertMetricFactory{}, CacheType: cache.NOOP, CacheOption: cache.Option{}}

			inst, err := SetUpInstance(ctx, opts)
			if err != nil {
				t.Fatalf("%v: SetUpInstance() = %v, want no error", test.desc, err)
			}
			addChainHandler, ok := inst.Handlers[test.cfg.Prefix+ct.AddChainPath]
			if !ok {
				t.Fatal("Couldn't find AddChain handler")
			}
			gotOpts := addChainHandler.Info.validationOpts
			if got, want := gotOpts.notAfterStart, test.cfg.NotAfterStart; want != nil && !equivalentTimes(got, want) {
				t.Errorf("%v: handler notAfterStart %v, want %v", test.desc, got, want)
			}
			if got, want := gotOpts.notAfterLimit, test.cfg.NotAfterLimit; want != nil && !equivalentTimes(got, want) {
				t.Errorf("%v: handler notAfterLimit %v, want %v", test.desc, got, want)
			}
			if got, want := gotOpts.acceptOnlyCA, test.cfg.AcceptOnlyCa; got != want {
				t.Errorf("%v: handler acceptOnlyCA %v, want %v", test.desc, got, want)
			}
		})
	}
}

func TestErrorMasking(t *testing.T) {
	info := logInfo{}
	w := httptest.NewRecorder()
	prefix := "Internal Server Error"
	err := errors.New("well that's bad")
	info.SendHTTPError(w, 500, err)
	if got, want := w.Body.String(), fmt.Sprintf("%s\n%v\n", prefix, err); got != want {
		t.Errorf("SendHTTPError: got %s, want %s", got, want)
	}
	info.instanceOpts.MaskInternalErrors = true
	w = httptest.NewRecorder()
	info.SendHTTPError(w, 500, err)
	if got, want := w.Body.String(), prefix+"\n"; got != want {
		t.Errorf("SendHTTPError: got %s, want %s", got, want)
	}

}
