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

// Migrillian tool transfers certs from CT logs to Trillian pre-ordered logs in
// the same order.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"k8s.io/klog/v2"

	"github.com/OlegBabkin/certificate-transparency-go/client"
	"github.com/OlegBabkin/certificate-transparency-go/jsonclient"
	"github.com/OlegBabkin/certificate-transparency-go/trillian/migrillian/configpb"
	"github.com/OlegBabkin/certificate-transparency-go/trillian/migrillian/core"
	"github.com/google/trillian"
	"github.com/google/trillian/monitoring"
	"github.com/google/trillian/monitoring/prometheus"
	"github.com/google/trillian/util"
	"github.com/google/trillian/util/election2"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	cfgPath = flag.String("config", "", "Path to migration config file")

	forceMaster = flag.Bool("force_master", false, "If true, assume master for all logs")
	backend     = flag.String("backend", "", "GRPC endpoint to connect to Trillian logservers")

	metricsEndpoint = flag.String("metrics_endpoint", "localhost:8099", "Endpoint for serving metrics")

	maxIdleConnsPerHost = flag.Int("max_idle_conns_per_host", 10, "Max idle HTTP connections per host (0 = DefaultMaxIdleConnsPerHost)")
	maxIdleConns        = flag.Int("max_idle_conns", 100, "Max number of idle HTTP connections across all hosts (0 = unlimited)")
)

func main() {
	klog.InitFlags(nil)
	flag.Parse()
	klog.CopyStandardLogTo("WARNING")
	defer klog.Flush()

	if *backend == "" {
		klog.Exit("--backend flag must be specified")
	}
	cfg, err := getConfig()
	if err != nil {
		klog.Exitf("Failed to load MigrillianConfig: %v", err)
	}
	if err := core.ValidateConfig(cfg); err != nil {
		klog.Exitf("Failed to validate MigrillianConfig: %v", err)
	}

	klog.Infof("Dialling Trillian backend: %v", *backend)
	conn, err := grpc.Dial(*backend, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
	if err != nil {
		klog.Exitf("Could not dial Trillian server: %v: %v", *backend, err)
	}

	defer func() {
		if err := conn.Close(); err != nil {
			klog.Errorf("Could not close RPC connection: %v", err)
		}
	}()

	httpClient := getHTTPClient()
	mf := prometheus.MetricFactory{}
	ef, closeFn := getElectionFactory()
	defer closeFn()

	ctx := context.Background()
	var ctrls []*core.Controller
	for _, mc := range cfg.MigrationConfigs.Config {
		ctrl, err := getController(ctx, mc, httpClient, mf, ef, conn)
		if err != nil {
			klog.Exitf("Failed to create Controller for %q: %v", mc.SourceUri, err)
		}
		ctrls = append(ctrls, ctrl)
	}

	// Handle metrics on the DefaultServeMux.
	http.Handle("/metrics", promhttp.Handler())
	go func() {
		err := http.ListenAndServe(*metricsEndpoint, nil)
		klog.Fatalf("http.ListenAndServe(): %v", err)
	}()

	cctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go util.AwaitSignal(cctx, cancel)

	core.RunMigration(cctx, ctrls)
}

// getController creates a single log migration Controller.
func getController(
	ctx context.Context,
	cfg *configpb.MigrationConfig,
	httpClient *http.Client,
	mf monitoring.MetricFactory,
	ef election2.Factory,
	conn *grpc.ClientConn,
) (*core.Controller, error) {
	ctOpts := jsonclient.Options{PublicKeyDER: cfg.PublicKey.Der, UserAgent: "ct-go-migrillian/1.0"}
	ctClient, err := client.New(cfg.SourceUri, httpClient, ctOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to create CT client: %v", err)
	}
	plClient, err := newPreorderedLogClient(ctx, conn, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create PreorderedLogClient: %v", err)
	}

	opts := core.OptionsFromConfig(cfg)
	return core.NewController(opts, ctClient, plClient, ef, mf), nil
}

// getConfig returns MigrillianConfig loaded from the file specified in flags.
func getConfig() (*configpb.MigrillianConfig, error) {
	if len(*cfgPath) == 0 {
		return nil, errors.New("config file not specified")
	}
	cfg, err := core.LoadConfigFromFile(*cfgPath)
	if err != nil {
		return nil, err
	}
	return cfg, nil
}

// getHTTPClient returns an HTTP client created from flags.
func getHTTPClient() *http.Client {
	transport := &http.Transport{
		TLSHandshakeTimeout:   30 * time.Second,
		DisableKeepAlives:     false,
		MaxIdleConns:          *maxIdleConns,
		MaxIdleConnsPerHost:   *maxIdleConnsPerHost,
		IdleConnTimeout:       90 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	// TODO(pavelkalinnikov): Make the timeout tunable.
	return &http.Client{
		Timeout:   10 * time.Second,
		Transport: transport,
	}
}

// newPreorderedLogClient creates a PreorderedLogClient for the specified tree.
func newPreorderedLogClient(
	ctx context.Context,
	conn *grpc.ClientConn,
	cfg *configpb.MigrationConfig,
) (*core.PreorderedLogClient, error) {
	admin := trillian.NewTrillianAdminClient(conn)
	gt := trillian.GetTreeRequest{TreeId: cfg.LogId}
	tree, err := admin.GetTree(ctx, &gt)
	if err != nil {
		return nil, err
	}
	log := trillian.NewTrillianLogClient(conn)
	pref := fmt.Sprintf("%d", cfg.LogId)
	return core.NewPreorderedLogClient(log, tree, cfg.IdentityFunction, pref)
}

// getElectionFactory returns an election factory based on flags, and a
// function which releases the resources associated with the factory.
func getElectionFactory() (election2.Factory, func()) {
	if *forceMaster {
		klog.Warning("Acting as master for all logs")
		return election2.NoopFactory{}, func() {}
	}
	// There isn't any evidence of anyone running Migrillian. Of this possibly zero
	// set, it's presumed that zero people require etcd. If we're wrong we could re-add
	// support, but removing until there's any demand.
	klog.Exit("Migrillian no longer supports etcd. Please raise an issue in this repo if this affects you. Use --force_master to run without election.")
	return nil, nil
}
