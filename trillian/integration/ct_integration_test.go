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

package integration

import (
	"context"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/OlegBabkin/certificate-transparency-go/trillian/ctfe"
	"github.com/OlegBabkin/certificate-transparency-go/trillian/ctfe/configpb"
	"github.com/google/trillian/crypto/keyspb"
	"github.com/google/trillian/storage/testdb"
	"google.golang.org/protobuf/types/known/anypb"
	timestamp "google.golang.org/protobuf/types/known/timestamppb"
)

var (
	adminServer    = flag.String("admin_server", "", "Address of log admin RPC server. Required for lifecycle test.")
	httpServers    = flag.String("ct_http_servers", "localhost:8092", "Comma-separated list of (assumed interchangeable) servers, each as address:port")
	metricsServers = flag.String("ct_metrics_servers", "localhost:8093", "Comma-separated list of (assumed interchangeable) metrics servers, each as address:port")
	testDir        = flag.String("testdata_dir", "testdata", "Name of directory with test data")
	logConfig      = flag.String("log_config", "", "File holding log config in JSON")
	mmd            = flag.Duration("mmd", 30*time.Second, "MMD for tested logs")
	skipStats      = flag.Bool("skip_stats", false, "Skip checks of expected log statistics")
)

func commonSetup(t *testing.T) []*configpb.LogConfig {
	t.Helper()
	if *logConfig == "" {
		t.Skip("Integration test skipped as no log config provided")
	}

	cfgs, err := ctfe.LogConfigFromFile(*logConfig)
	if err != nil {
		t.Fatalf("Failed to read log config: %v", err)
	}
	return cfgs
}

func TestLiveCTIntegration(t *testing.T) {
	flag.Parse()
	cfgs := commonSetup(t)
	for _, cfg := range cfgs {
		cfg := cfg // capture config
		t.Run(cfg.Prefix, func(t *testing.T) {
			t.Parallel()
			var stats *logStats
			if !*skipStats {
				stats = newLogStats(cfg.LogId)
			}
			if err := RunCTIntegrationForLog(cfg, *httpServers, *metricsServers, *testDir, *mmd, stats); err != nil {
				t.Errorf("%s: failed: %v", cfg.Prefix, err)
			}
		})
	}
}

func TestLiveLifecycleCTIntegration(t *testing.T) {
	flag.Parse()
	cfgs := commonSetup(t)
	for _, cfg := range cfgs {
		cfg := cfg // capture config
		t.Run(cfg.Prefix, func(t *testing.T) {
			t.Parallel()
			var stats *logStats
			if !*skipStats {
				stats = newLogStats(cfg.LogId)
			}
			if err := RunCTLifecycleForLog(cfg, *httpServers, *metricsServers, *adminServer, *testDir, *mmd, stats); err != nil {
				t.Errorf("%s: failed: %v", cfg.Prefix, err)
			}
		})
	}
}

const (
	rootsPEMFile    = "../testdata/fake-ca.cert"
	pubKeyPEMFile   = "../testdata/ct-http-server.pubkey.pem"
	privKeyPEMFile  = "../testdata/ct-http-server.privkey.pem"
	privKeyPassword = "dirk"
)

func TestInProcessCTIntegration(t *testing.T) {
	testdb.SkipIfNoMySQL(t)

	pubKeyDER, err := loadPublicKey(pubKeyPEMFile)
	if err != nil {
		t.Fatalf("Could not load public key: %v", err)
	}

	pubKey := &keyspb.PublicKey{Der: pubKeyDER}
	privKey, err := anypb.New(&keyspb.PEMKeyFile{Path: privKeyPEMFile, Password: privKeyPassword})
	if err != nil {
		t.Fatalf("Could not marshal private key as protobuf Any: %v", err)
	}

	ctx := context.Background()
	cfgs := []*configpb.LogConfig{
		{
			Prefix:       "athos",
			RootsPemFile: []string{rootsPEMFile},
			PublicKey:    pubKey,
			PrivateKey:   privKey,
		},
		{
			Prefix:       "porthos",
			RootsPemFile: []string{rootsPEMFile},
			PublicKey:    pubKey,
			PrivateKey:   privKey,
		},
		{
			Prefix:       "aramis",
			RootsPemFile: []string{rootsPEMFile},
			PublicKey:    pubKey,
			PrivateKey:   privKey,
		},
	}

	env, err := NewCTLogEnv(ctx, cfgs, 2, "TestInProcessCTIntegration")
	if err != nil {
		t.Fatalf("Failed to launch test environment: %v", err)
	}
	defer env.Close()

	mmd := 120 * time.Second
	// Run a container for the parallel sub-tests, so that we wait until they
	// all complete before terminating the test environment.
	t.Run("container", func(t *testing.T) {
		for _, cfg := range cfgs {
			cfg := cfg // capture config
			t.Run(cfg.Prefix, func(t *testing.T) {
				t.Parallel()
				stats := newLogStats(cfg.LogId)
				if err := RunCTIntegrationForLog(cfg, env.CTAddr, env.CTAddr, "../testdata", mmd, stats); err != nil {
					t.Errorf("%s: failed: %v", cfg.Prefix, err)
				}
			})
		}
	})
}

func loadPublicKey(path string) ([]byte, error) {
	pemKey, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(pemKey)
	if block == nil {
		return nil, fmt.Errorf("could not decode PEM public key: %v", path)
	}
	if block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("got %q PEM, want \"PUBLIC KEY\": %v", block.Type, path)
	}

	return block.Bytes, nil
}

func TestNotAfterForLog(t *testing.T) {
	tests := []struct {
		desc    string
		cfg     *configpb.LogConfig
		want    time.Time
		wantErr string
	}{
		{
			desc: "no-limits",
			cfg:  &configpb.LogConfig{},
			want: time.Now().Add(24 * time.Hour),
		},
		{
			desc: "malformed-start",
			cfg: &configpb.LogConfig{
				NotAfterStart: &timestamp.Timestamp{Seconds: 1000, Nanos: -1},
			},
			wantErr: "failed to parse NotAfterStart",
		},
		{
			desc: "malformed-limit",
			cfg: &configpb.LogConfig{
				NotAfterLimit: &timestamp.Timestamp{Seconds: 1000, Nanos: -1},
			},
			wantErr: "failed to parse NotAfterLimit",
		},
		{
			desc: "start-no-limit",
			cfg: &configpb.LogConfig{
				NotAfterStart: &timestamp.Timestamp{Seconds: 1230000000},
			},
			want: time.Date(2008, 12, 23, 2, 40, 0, 0, time.UTC).Add(24 * time.Hour),
		},
		{
			desc: "limit-no-start",
			cfg: &configpb.LogConfig{
				NotAfterLimit: &timestamp.Timestamp{Seconds: 1230000000},
			},
			want: time.Date(2008, 12, 23, 2, 40, 0, 0, time.UTC).Add(-1 * time.Hour),
		},
		{
			desc: "mid-range",
			cfg: &configpb.LogConfig{
				NotAfterStart: &timestamp.Timestamp{Seconds: 1230000000},
				NotAfterLimit: &timestamp.Timestamp{Seconds: 1230000000 + 86400},
			},
			want: time.Date(2008, 12, 23, 2, 40, 0, 0, time.UTC).Add(43200 * time.Second),
		},
	}
	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			got, err := NotAfterForLog(test.cfg)
			if err != nil {
				if len(test.wantErr) == 0 {
					t.Errorf("NotAfterForLog()=nil,%v, want _,nil", err)
				} else if !strings.Contains(err.Error(), test.wantErr) {
					t.Errorf("NotAfterForLog()=nil,%v, want _,err containing %q", err, test.wantErr)
				}
				return
			}
			if len(test.wantErr) > 0 {
				t.Errorf("NotAfterForLog()=%v, nil, want nil,err containing %q", got, test.wantErr)
			}
			delta := got.Sub(test.want)
			if delta < 0 {
				delta = -delta
			}
			if delta > time.Second {
				t.Errorf("NotAfterForLog()=%v, want %v (delta %v)", got, test.want, delta)
			}
		})

	}
}
