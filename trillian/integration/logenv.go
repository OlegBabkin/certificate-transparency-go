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
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/OlegBabkin/certificate-transparency-go/trillian/ctfe"
	"github.com/OlegBabkin/certificate-transparency-go/trillian/ctfe/configpb"
	"github.com/google/trillian"
	"github.com/google/trillian/client"
	"github.com/google/trillian/monitoring/prometheus"
	"github.com/google/trillian/testonly/integration"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"k8s.io/klog/v2"

	stestonly "github.com/google/trillian/storage/testonly"
)

// CTLogEnv is a test environment that contains both a log server and a CT personality
// connected to it.
type CTLogEnv struct {
	logEnv       *integration.LogEnv
	wg           *sync.WaitGroup
	ctListener   net.Listener
	ctHTTPServer *http.Server
	CTAddr       string
}

// NewCTLogEnv creates a fresh DB, log server, and CT personality.
// testID should be unique to each unittest package so as to allow parallel tests.
// Created logIDs will be set to cfgs.
func NewCTLogEnv(ctx context.Context, cfgs []*configpb.LogConfig, numSequencers int, testID string) (*CTLogEnv, error) {
	// Start log server and signer.
	logEnv, err := integration.NewLogEnvWithGRPCOptions(ctx, numSequencers, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create LogEnv: %v", err)
	}

	// Provision the logs.
	for _, cfg := range cfgs {
		tree, err := client.CreateAndInitTree(ctx,
			&trillian.CreateTreeRequest{Tree: stestonly.LogTree},
			logEnv.Admin, logEnv.Log)
		if err != nil {
			return nil, fmt.Errorf("failed to provision log %d: %v", cfg.LogId, err)
		}

		cfg.LogId = tree.TreeId
	}

	// Start the CT personality.
	addr, listener, err := listen()
	if err != nil {
		return nil, fmt.Errorf("failed to find an unused port for CT personality: %v", err)
	}
	server := http.Server{Addr: addr, Handler: nil}
	var wg sync.WaitGroup
	wg.Add(1)
	go func(env *integration.LogEnv, server *http.Server, listener net.Listener, cfgs []*configpb.LogConfig) {
		defer wg.Done()
		cl := trillian.NewTrillianLogClient(env.ClientConn)
		for _, cfg := range cfgs {
			vCfg, err := ctfe.ValidateLogConfig(cfg)
			if err != nil {
				klog.Fatalf("ValidateLogConfig failed: %+v: %v", cfg, err)
			}
			opts := ctfe.InstanceOptions{
				Validated:     vCfg,
				Client:        cl,
				Deadline:      10 * time.Second,
				MetricFactory: prometheus.MetricFactory{},
				RequestLog:    new(ctfe.DefaultRequestLog),
			}
			inst, err := ctfe.SetUpInstance(ctx, opts)
			if err != nil {
				klog.Fatalf("Failed to set up log instance for %+v: %v", cfg, err)
			}
			for path, handler := range inst.Handlers {
				http.Handle(path, handler)
			}
		}
		http.Handle("/metrics", promhttp.Handler())
		if err := server.Serve(listener); err != http.ErrServerClosed {
			klog.Fatalf("server.Serve(): %v", err)
		}
	}(logEnv, &server, listener, cfgs)
	return &CTLogEnv{
		logEnv:       logEnv,
		wg:           &wg,
		ctListener:   listener,
		ctHTTPServer: &server,
		CTAddr:       addr,
	}, nil
}

// Close shuts down the servers.
func (env *CTLogEnv) Close() {
	if err := env.ctListener.Close(); err != nil {
		log.Fatalf("Operation to close listener failed: %v", err)
	}
	env.wg.Wait()
	env.logEnv.Close()
}

// listen opens a random high numbered port for listening.
func listen() (string, net.Listener, error) {
	lis, err := net.Listen("tcp", ":0")
	if err != nil {
		return "", nil, err
	}
	_, port, err := net.SplitHostPort(lis.Addr().String())
	if err != nil {
		return "", nil, err
	}
	addr := "localhost:" + port
	return addr, lis, nil
}
