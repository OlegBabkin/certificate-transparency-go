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

package ctpolicy

import (
	"github.com/OlegBabkin/certificate-transparency-go/loglist3"
	"github.com/OlegBabkin/certificate-transparency-go/x509"
)

// ChromeCTPolicy implements logic for complying with Chrome's CT log policy
type ChromeCTPolicy struct {
}

// LogsByGroup describes submission requirements for embedded SCTs according to
// https://github.com/chromium/ct-policy/blob/master/ct_policy.md#qualifying-certificate.
// Returns an error if it's not possible to satisfy the policy with the provided loglist.
func (chromeP ChromeCTPolicy) LogsByGroup(cert *x509.Certificate, approved *loglist3.LogList) (LogPolicyData, error) {
	googGroup := LogGroupInfo{Name: "Google-operated", IsBase: false}
	googGroup.populate(approved, func(op *loglist3.Operator) bool { return op.GoogleOperated() })
	if err := googGroup.setMinInclusions(1); err != nil {
		return nil, err
	}

	nonGoogGroup := LogGroupInfo{Name: "Non-Google-operated", IsBase: false}
	nonGoogGroup.populate(approved, func(op *loglist3.Operator) bool { return !op.GoogleOperated() })
	if err := nonGoogGroup.setMinInclusions(1); err != nil {
		return nil, err
	}
	var incCount int
	switch m := lifetimeInMonths(cert); {
	case m < 15:
		incCount = 2
	case m <= 27:
		incCount = 3
	case m <= 39:
		incCount = 4
	default:
		incCount = 5
	}
	baseGroup, err := BaseGroupFor(approved, incCount)
	if err != nil {
		return nil, err
	}
	groups := LogPolicyData{
		googGroup.Name:    &googGroup,
		nonGoogGroup.Name: &nonGoogGroup,
		baseGroup.Name:    baseGroup,
	}
	return groups, nil
}

// Name returns label for the submission policy.
func (chromeP ChromeCTPolicy) Name() string {
	return "Chrome"
}
