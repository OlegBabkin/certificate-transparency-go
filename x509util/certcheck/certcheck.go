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

// certcheck is a utility to show and check the contents of certificates.
package main

import (
	"bytes"
	"crypto/tls"
	"flag"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/OlegBabkin/certificate-transparency-go/x509"
	"github.com/OlegBabkin/certificate-transparency-go/x509util"
	"k8s.io/klog/v2"
)

var (
	root                     = flag.String("root", "", "Root CA certificate file")
	intermediate             = flag.String("intermediate", "", "Intermediate CA certificate file")
	useSystemRoots           = flag.Bool("system_roots", false, "Use system roots")
	verbose                  = flag.Bool("verbose", false, "Verbose output")
	strict                   = flag.Bool("strict", true, "Set non-zero exit code for non-fatal errors in parsing")
	validate                 = flag.Bool("validate", false, "Validate certificate signatures")
	checkTime                = flag.Bool("check_time", false, "Check current validity of certificate")
	checkName                = flag.Bool("check_name", true, "Check certificate name validity")
	checkEKU                 = flag.Bool("check_eku", true, "Check EKU nesting validity")
	checkPathLen             = flag.Bool("check_path_len", true, "Check path len constraint validity")
	checkNameConstraint      = flag.Bool("check_name_constraint", true, "Check name constraints")
	checkUnknownCriticalExts = flag.Bool("check_unknown_critical_exts", true, "Check for unknown critical extensions")
	checkRevoked             = flag.Bool("check_revocation", false, "Check revocation status of certificate")
)

func addCerts(filename string, pool *x509.CertPool) {
	if filename != "" {
		dataList, err := x509util.ReadPossiblePEMFile(filename, "CERTIFICATE")
		if err != nil {
			klog.Exitf("Failed to read certificate file: %v", err)
		}
		for _, data := range dataList {
			certs, err := x509.ParseCertificates(data)
			if err != nil {
				klog.Exitf("Failed to parse certificate from %s: %v", filename, err)
			}
			for _, cert := range certs {
				pool.AddCert(cert)
			}
		}
	}
}

func main() {
	klog.InitFlags(nil)
	flag.Parse()

	failed := false
	for _, target := range flag.Args() {
		var err error
		var chain []*x509.Certificate
		if strings.HasPrefix(target, "https://") {
			chain, err = chainFromSite(target)
		} else {
			chain, err = chainFromFile(target)
		}
		if err != nil {
			klog.Errorf("%v", err)
		}
		if x509.IsFatal(err) {
			failed = true
			continue
		} else if err != nil && *strict {
			failed = true
		}
		for _, cert := range chain {
			if *verbose {
				fmt.Print(x509util.CertificateToString(cert))
			}
			if *checkRevoked {
				if err := checkRevocation(cert, *verbose); err != nil {
					klog.Errorf("%s: certificate is revoked: %v", target, err)
					failed = true
				}
			}
		}
		if *validate && len(chain) > 0 {
			opts := x509.VerifyOptions{
				DisableTimeChecks:              !*checkTime,
				DisableCriticalExtensionChecks: !*checkUnknownCriticalExts,
				DisableNameChecks:              !*checkName,
				DisableEKUChecks:               !*checkEKU,
				DisablePathLenChecks:           !*checkPathLen,
				DisableNameConstraintChecks:    !*checkNameConstraint,
			}
			if err := validateChain(chain, opts, *root, *intermediate, *useSystemRoots); err != nil {
				klog.Errorf("%s: verification error: %v", target, err)
				failed = true
			}
		}
	}
	if failed {
		os.Exit(1)
	}
}

// chainFromSite retrieves the certificate chain from an https: URL.
// Note that both a chain and an error can be returned (in which case
// the error will be of type x509.NonFatalErrors).
func chainFromSite(target string) ([]*x509.Certificate, error) {
	u, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to parse URL: %v", target, err)
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("%s: non-https URL provided", target)
	}
	host := u.Host
	if !strings.Contains(host, ":") {
		host += ":443"
	}

	// Insecure TLS connection here so we can always proceed.
	conn, err := tls.Dial("tcp", host, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return nil, fmt.Errorf("%s: failed to dial %q: %v", target, host, err)
	}
	defer conn.Close()

	// Convert base crypto/x509.Certificates to our forked x509.Certificate type.
	goChain := conn.ConnectionState().PeerCertificates
	var nfe *x509.NonFatalErrors
	chain := make([]*x509.Certificate, len(goChain))
	for i, goCert := range goChain {
		cert, err := x509.ParseCertificate(goCert.Raw)
		if x509.IsFatal(err) {
			return nil, fmt.Errorf("%s: failed to convert Go Certificate [%d]: %v", target, i, err)
		} else if errs, ok := err.(x509.NonFatalErrors); ok {
			nfe = nfe.Append(&errs)
		} else if err != nil {
			return nil, fmt.Errorf("%s: failed to convert Go Certificate [%d]: %v", target, i, err)
		}
		chain[i] = cert
	}

	if nfe.HasError() {
		return chain, *nfe
	}
	return chain, nil
}

// chainFromSite retrieves a certificate chain from a PEM file.
// Note that both a chain and an error can be returned (in which case
// the error will be of type x509.NonFatalErrors).
func chainFromFile(filename string) ([]*x509.Certificate, error) {
	dataList, err := x509util.ReadPossiblePEMFile(filename, "CERTIFICATE")
	if err != nil {
		return nil, fmt.Errorf("%s: failed to read data: %v", filename, err)
	}
	var nfe *x509.NonFatalErrors
	var chain []*x509.Certificate
	for _, data := range dataList {
		certs, err := x509.ParseCertificates(data)
		if x509.IsFatal(err) {
			return nil, fmt.Errorf("%s: failed to parse: %v", filename, err)
		} else if errs, ok := err.(x509.NonFatalErrors); ok {
			nfe = nfe.Append(&errs)
		} else if err != nil {
			return nil, fmt.Errorf("%s: failed to parse: %v", filename, err)
		}
		chain = append(chain, certs...)
	}
	if nfe.HasError() {
		return chain, *nfe
	}
	return chain, nil
}

func validateChain(chain []*x509.Certificate, opts x509.VerifyOptions, rootsFile, intermediatesFile string, useSystemRoots bool) error {
	roots := x509.NewCertPool()
	if useSystemRoots {
		systemRoots, err := x509.SystemCertPool()
		if err != nil {
			klog.Errorf("Failed to get system roots: %v", err)
		}
		roots = systemRoots
	}
	opts.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
	opts.Roots = roots
	opts.Intermediates = x509.NewCertPool()
	addCerts(rootsFile, opts.Roots)
	addCerts(intermediatesFile, opts.Intermediates)

	if !useSystemRoots && len(rootsFile) == 0 {
		// No root CA certs provided, so assume the chain is self-contained.
		if len(chain) > 1 {
			last := chain[len(chain)-1]
			if bytes.Equal(last.RawSubject, last.RawIssuer) {
				opts.Roots.AddCert(last)
			}
		}
	}
	if len(intermediatesFile) == 0 {
		// No intermediate CA certs provided, so assume later entries in the chain are intermediates.
		for i := 1; i < len(chain); i++ {
			opts.Intermediates.AddCert(chain[i])
		}
	}
	_, err := chain[0].Verify(opts)
	return err
}

func checkRevocation(cert *x509.Certificate, verbose bool) error {
	for _, crldp := range cert.CRLDistributionPoints {
		crlDataList, err := x509util.ReadPossiblePEMURL(crldp, "X509 CRL")
		if err != nil {
			klog.Errorf("failed to retrieve CRL from %q: %v", crldp, err)
			continue
		}
		for _, crlData := range crlDataList {
			crl, err := x509.ParseCertificateList(crlData)
			if x509.IsFatal(err) {
				klog.Errorf("failed to parse CRL from %q: %v", crldp, err)
				continue
			}
			if err != nil {
				klog.Errorf("non-fatal error parsing CRL from %q: %v", crldp, err)
			}
			if verbose {
				fmt.Printf("\nRevocation data from %s:\n", crldp)
				fmt.Print(x509util.CRLToString(crl))
			}
			for _, c := range crl.TBSCertList.RevokedCertificates {
				if c.SerialNumber.Cmp(cert.SerialNumber) == 0 {
					return fmt.Errorf("certificate is revoked since %v", c.RevocationTime)
				}
			}
		}
	}
	return nil
}
