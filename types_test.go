// Copyright 2015 Google LLC. All Rights Reserved.
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

package ct

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/OlegBabkin/certificate-transparency-go/tls"
)

const (
	CertEntry    = "000000000149a6e03abe00000006513082064d30820535a003020102020c6a5d4161f5c9b68043270b0c300d06092a864886f70d0101050500305e310b300906035504061302424531193017060355040a1310476c6f62616c5369676e206e762d7361313430320603550403132b476c6f62616c5369676e20457874656e6465642056616c69646174696f6e204341202d2047322054455354301e170d3134313131333031353830315a170d3136313131333031353830315a3082011331183016060355040f0c0f427573696e65737320456e74697479311230100603550405130936363636363636363631133011060b2b0601040182373c0201031302444531293027060b2b0601040182373c02010113186576206a7572697364696374696f6e206c6f63616c69747931263024060b2b0601040182373c02010213156576206a7572697364696374696f6e207374617465310b3009060355040613024a50310a300806035504080c0153310a300806035504070c014c311530130603550409130c657620616464726573732033310c300a060355040b0c034f5531310c300a060355040b0c034f5532310a3008060355040a0c014f3117301506035504030c0e637372636e2e73736c32342e6a7030820122300d06092a864886f70d01010105000382010f003082010a02820101008db9f0d6b359466dffe95ba43dc1a5680eedc8f3cabbc573a236a109bf6e58df816c7bb8156147ab526eceaffd0576e6e1c09ea33433e114d7e5038c697298c7957f01a7e1142320847cf234995bbe42798340cb99e6a7e2cfa950277aef6e02f4d96ddceb0af9541171b0f8f1aa4f0d02453e6e654b25a13f2aff4357cae8177d3bd21855686591a2309d9ff5dead8240304e22eafcc5508587e6b6ad1d00b53c28e5b936269afbf214b73edbdc8a48a86c1c23f3dce55fcce60502c0908bca9bdb22c16c0b34d11b4fd27e9d7bcb56c5ec0fc4d52500fb06b0af5c4112e421022b78b31030cb73e9fd92ffc65919fd8f35e604fcaf025b9c77e3e5dff749a70203010001a38202523082024e300e0603551d0f0101ff0404030205a0304c0603551d2004453043304106092b06010401a03201013034303206082b06010505070201162668747470733a2f2f7777772e676c6f62616c7369676e2e636f6d2f7265706f7369746f72792f30480603551d1f0441303f303da03ba0398637687474703a2f2f63726c2e676c6f62616c7369676e2e636f6d2f67732f67736f7267616e697a6174696f6e76616c63617467322e63726c30819c06082b0601050507010104818f30818c304a06082b06010505073002863e687474703a2f2f7365637572652e676c6f62616c7369676e2e636f6d2f6361636572742f67736f7267616e697a6174696f6e76616c63617467322e637274303e06082b060105050730018632687474703a2f2f6f637370322e676c6f62616c7369676e2e636f6d2f67736f7267616e697a6174696f6e76616c6361746732301d0603551d250416301406082b0601050507030106082b0601050507030230190603551d1104123010820e637372636e2e73736c32342e6a70301d0603551d0e041604147f834b2903e35efff651619083a2efd69a6d70f4301f0603551d23041830168014ab30a406d972d0029ab2c7d3f4241be2fca5320230818a060a2b06010401d679020402047c047a0078007600b0cc83e5a5f97d6baf7c09cc284904872ac7e88b132c6350b7c6fd26e16c6c7700000149a6dc346b00000403004730450220469f4dc0553b7832bd56633c3b9d53faaec84df414b7a05ab1b2d544d146ac3e022100ee899419fd4f95544798f7883fe093692feb4c90e84d651600f7019166a43701300d06092a864886f70d010105050003820101007dcd3e228d68cdc0734c7629fd7d40cd742d0ed1d0d9f49a643af12dcdbc61394638b7c519bb7cae530ccdc3a5037d5cdd8a4d2c01abdc834daf1993f7a22ee2c223377a94da4e68ac69a0b50d2d473ec77651e001c5f71a23cc2defe7616fd6c6491aa7f9a2bb16b930ce3f8cc37cf6a47bfb04fd4eff7db8433cc6fdb05146a4a31fe65211875f2c51129bf0729ce2dc7ce1a5afc6eaa1eb3a36296cb9e091375edfc408c727f6d54bba408da60b46c496a364c504adf47ee0496a9260fe223c8b23c14832635c3dff0dba8a0c8cdd957a77f18443b7782a9b6c7636b7d66df426350b959537e911888e45b2c0b218e50d03fdcfa7f758e8e60dd1a1996bc00000"
	PrecertEntry = "00000000014b4981f0c800013760e2790f33a498f9b6c149fecfca3993954b536fbf36ad45d0a8415b79337d00047a30820476a00302010202100532298c396a3e25fcaa1977e827b5f3300d06092a864886f70d01010b0500306d310b300906035504061302555331163014060355040a130d47656f547275737420496e632e311f301d060355040b1316464f52205445535420505552504f534553204f4e4c59312530230603550403131c47656f54727573742045562053534c2054455354204341202d204734301e170d3135303230323030303030305a170d3136303232373233353935395a3081c331133011060b2b0601040182373c02010313024742311b3019060b2b0601040182373c020102140a43616c69666f726e6961311e301c060b2b0601040182373c0201010c0d4d6f756e7461696e2056696577310b30090603550406130247423113301106035504080c0a43616c69666f726e69613116301406035504070c0d4d6f756e7461696e2056696577311d301b060355040a0c1453796d616e74656320436f72706f726174696f6e3116301406035504030c0d736466656473662e747275737430820122300d06092a864886f70d01010105000382010f003082010a0282010100b19d97def39ff829c65ea099a3257298b33ff675451fdc5641a222347aee4a56201f4c1a406f2f19815d86dec1a611768e7d556c8e33a7f1b4c78db19cceae540e97ae1f0660b2ee4f8cff2045b84a9da228349744406eceaed0b08d46fdab3543b3d86ea708627a61a529b793a76adc6b776bc8d5b3d4fe21e2c4aa92cfd33b45e7412068e0683a2beffad1df2fc320b8ddbf02ffb603d2cf74798277fd9656b5acd45659b0e5d761e02dcf95c53095555a931ad5bfa9b4967c045d5f12de2d6b537cd93af2ad8b45e5540bd43279876d13e376fb649778e10dfa56165b901bd37e9dee4e46027b4c0732ca7ed64491862abaf6a24a4aaed8f49a0922ca4fb50203010001a38201d1308201cd30470603551d110440303e820d6b6a61736468662e7472757374820b73736466732e7472757374820d736466656473662e747275737482117777772e736466656473662e747275737430090603551d1304023000300e0603551d0f0101ff0404030205a0302b0603551d1f042430223020a01ea01c861a687474703a2f2f676d2e73796d63622e636f6d2f676d2e63726c3081a00603551d2004819830819530819206092b06010401f0220106308184303f06082b06010505070201163368747470733a2f2f7777772e67656f74727573742e636f6d2f7265736f75726365732f7265706f7369746f72792f6c6567616c304106082b0601050507020230350c3368747470733a2f2f7777772e67656f74727573742e636f6d2f7265736f75726365732f7265706f7369746f72792f6c6567616c301d0603551d250416301406082b0601050507030106082b06010505070302301f0603551d23041830168014b1699461abe6cb0c4ce759af5a498b1833c1e147305706082b06010505070101044b3049301f06082b060105050730018613687474703a2f2f676d2e73796d63642e636f6d302606082b06010505073002861a687474703a2f2f676d2e73796d63622e636f6d2f676d2e6372740000"
)

func TestUnmarshalMerkleTreeLeaf(t *testing.T) {
	var tests = []struct {
		in     string // hex string
		want   LogEntryType
		errstr string
	}{
		{CertEntry, X509LogEntryType, ""},
		{PrecertEntry, PrecertLogEntryType, ""},
		{"001234", 0, "LeafType: unhandled value"},
	}
	for _, test := range tests {
		inData, _ := hex.DecodeString(test.in)
		var got MerkleTreeLeaf
		_, err := tls.Unmarshal(inData, &got)
		if test.errstr != "" {
			if err == nil {
				t.Errorf("tls.Unmarshal(%s, &MerkleTreeLeaf)=%+v,nil; want error %q", test.in, got, test.errstr)
			} else if !strings.Contains(err.Error(), test.errstr) {
				t.Errorf("tls.Unmarshal(%s, &MerkleTreeLeaf)=nil,%q; want error %q", test.in, err.Error(), test.errstr)
			}
			continue
		}
		if err != nil {
			t.Errorf("tls.Unmarshal(%s, &MerkleTreeLeaf)=nil,%q; want type %v", test.in, err.Error(), test.want)
			continue
		}
		if got.Version != V1 {
			t.Errorf("tls.Unmarshal(%s, &MerkleTreeLeaf)=version=%v,nil; want version 1", test.in, got.Version)
		}
		if got.LeafType != TimestampedEntryLeafType {
			t.Errorf("tls.Unmarshal(%s, &MerkleTreeLeaf)=LeafType=%v,nil; want LeafType=%v", test.in, got.LeafType, TimestampedEntryLeafType)
		}
		if got.TimestampedEntry.EntryType != test.want {
			t.Errorf("tls.Unmarshal(%s, &MerkleTreeLeaf)=EntryType=%v,nil; want LeafType=%v", test.in, got.TimestampedEntry.EntryType, test.want)
		}
	}
}

func mustB64Decode(s string) []byte {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		fmt.Println(s)
		panic(err)
	}
	return b
}

func TestToSignedCertificateTimestamp(t *testing.T) {
	// From the sct:
	// {"sct_version":0,"id":"CEEUmABxUywWGQRgvPxH/cJlOvopLHKzf/hjrinMyfA=","timestamp":1512556025588,"extensions":"","signature":"BAMARjBEAiAJAPO7EKykH4eOQ81kTzKCb4IEWzcxTBdbdRCHLFPLFAIgBEoGXDUtcIaF3M5HWI+MxwkCQbvqR9TSGUHDCZoOr3Q="}
	validLogID := "CEEUmABxUywWGQRgvPxH/cJlOvopLHKzf/hjrinMyfA="
	longLogID := "CEEUmABxUywWGQRgvPxH/cJlOvopLHKzf/hjrinMyfA0"
	shortLogID := "CEEUmABxUywWGQRgvPxH/cJlOvopLHKzf/hjrinMyf=="
	validSCTSignature := "BAMARjBEAiAJAPO7EKykH4eOQ81kTzKCb4IEWzcxTBdbdRCHLFPLFAIgBEoGXDUtcIaF3M5HWI+MxwkCQbvqR9TSGUHDCZoOr3Q="
	longSCTSignature := "BAMARjBEAiAJAPO7EKykH4eOQ81kTzKCb4IEWzcxTBdbdRCHLFPLFAIgBEoGXDUtcIaF3M5HWI+MxwkCQbvqR9TSGUHDCZoOr3Q0"

	tests := []struct {
		desc      string
		logID     string
		exts      string
		signature string
		wantErr   bool
	}{
		{
			desc:      "success",
			logID:     validLogID,
			signature: validSCTSignature,
		},
		{
			desc:      "log ID too long",
			logID:     longLogID,
			signature: validSCTSignature,
			wantErr:   true,
		},
		{
			desc:      "log ID too short",
			logID:     shortLogID,
			signature: validSCTSignature,
			wantErr:   true,
		},
		{
			desc:      "extensions not base64",
			logID:     validLogID,
			exts:      "This is not Base64",
			signature: validSCTSignature,
			wantErr:   true,
		},
		{
			desc:      "signature trailing data",
			logID:     validLogID,
			signature: longSCTSignature,
			wantErr:   true,
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			sctResponse := &AddChainResponse{
				SCTVersion: 0,
				ID:         mustB64Decode(test.logID),
				Timestamp:  1512556025588,
				Extensions: test.exts,
				Signature:  mustB64Decode(test.signature),
			}
			sct, err := sctResponse.ToSignedCertificateTimestamp()
			if gotErr := err != nil; gotErr != test.wantErr {
				t.Errorf("AddChainResponse.ToSignedCertificateTimestamp() = %+v, %v, want err? %t", sct, err, test.wantErr)
			}
		})
	}
}

const (
	validRootHash = "708981e91d1487c2a9ea901ab5a8d053c1348585afcdb5e107bf60c0c1d20fc0"
	longRootHash  = "708981e91d1487c2a9ea901ab5a8d053c1348585afcdb5e107bf60c0c1d20fc000"
	shortRootHash = "708981e91d1487c2a9ea901ab5a8d053c1348585afcdb5e107bf60c0c1d20f"

	validSignature = "040300473045022007fb5ae3cea8f076b534a01a9a19e60625c6cc70704c6c1a7c88b30d8f67d4af022100840d37b8f2f9ce134e74eefda6a0c2ad034d591b785cdc4973c4c4f5d03f0439"
	longSignature  = "040300473045022007fb5ae3cea8f076b534a01a9a19e60625c6cc70704c6c1a7c88b30d8f67d4af022100840d37b8f2f9ce134e74eefda6a0c2ad034d591b785cdc4973c4c4f5d03f043900"
)

func mustHexDecode(s string) []byte {
	h, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return h
}

func TestToSignedTreeHead(t *testing.T) {
	tests := []struct {
		desc      string
		rootHash  string
		signature string
		wantErr   bool
	}{
		{
			desc:      "success",
			rootHash:  validRootHash,
			signature: validSignature,
		},
		{
			desc:      "root hash too long",
			rootHash:  longRootHash,
			signature: validSignature,
			wantErr:   true,
		},
		{
			desc:      "root hash too short",
			rootHash:  shortRootHash,
			signature: validSignature,
			wantErr:   true,
		},
		{
			desc:      "signature trailing data",
			rootHash:  validRootHash,
			signature: longSignature,
			wantErr:   true,
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			sthResponse := &GetSTHResponse{
				TreeSize:          278437663,
				Timestamp:         1527076172068,
				SHA256RootHash:    mustHexDecode(test.rootHash),
				TreeHeadSignature: mustHexDecode(test.signature),
			}
			sth, err := sthResponse.ToSignedTreeHead()
			if gotErr := err != nil; gotErr != test.wantErr {
				t.Errorf("GetSTHResponse.ToSignedTreeHead() = %+v, %v, want err? %t", sth, err, test.wantErr)
			}
		})
	}
}

func TestSTHString(t *testing.T) {
	tests := []struct {
		desc  string
		logID string
	}{
		{
			desc: "no logID",
		},
		{
			desc:  "logID",
			logID: "aPaY+B9kgr46jO65KB1M/HFRXWeT1ETRCmesu09P+8Q=",
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			sthResponse := &GetSTHResponse{
				TreeSize:          278437663,
				Timestamp:         1527076172068,
				SHA256RootHash:    mustHexDecode(validRootHash),
				TreeHeadSignature: mustHexDecode(validSignature),
			}
			sth, err := sthResponse.ToSignedTreeHead()
			if err != nil {
				t.Fatalf("sthResponse.ToSignedTreeHead(): %s", err)
			}

			if test.logID != "" {
				if err := sth.LogID.FromBase64String(test.logID); err != nil {
					t.Fatalf("SHA256Hash.FromBase64String(%s) = %s", test.logID, err)
				}
			}

			sthStr := sth.String()
			if got, want := strings.Contains(sthStr, "LogID"), len(test.logID) != 0; got != want {
				t.Errorf("SignedTreeHead.String(): contains LogID: %t, want LogID: %t", got, want)
			}
		})
	}
}
