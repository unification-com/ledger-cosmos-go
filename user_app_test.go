/*******************************************************************************
*   (c) 2018 ZondaX GmbH
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************/

package ledger_cosmos_go

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"strings"
	"testing"
)

// Ledger Test Mnemonic: equip will roof matter pink blind book anxiety banner elbow sun young

func Test_UserFindLedger(t *testing.T) {
	userApp, err := FindLedgerCosmosUserApp()
	if err != nil {
		t.Fatalf(err.Error())
	}

	assert.NotNil(t, userApp)
	defer userApp.Close()
}

func Test_UserGetVersion(t *testing.T) {
	userApp, err := FindLedgerCosmosUserApp()
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer userApp.Close()

	userApp.api.Logging = true

	version, err := userApp.GetVersion()
	require.Nil(t, err, "Detected error")
	fmt.Println(version)

	assert.Equal(t, uint8(0x0), version.AppMode, "TESTING MODE ENABLED!!")
	assert.Equal(t, uint8(0x2), version.Major, "Wrong Major version")
	assert.Equal(t, uint8(0x10), version.Minor, "Wrong Minor version")
	assert.Equal(t, uint8(0x1), version.Patch, "Wrong Patch version")
}

func Test_UserGetPublicKey(t *testing.T) {
	userApp, err := FindLedgerCosmosUserApp()
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer userApp.Close()

	userApp.api.Logging = true

	path := []uint32{44, 5555, 5, 0, 21}

	pubKey, err := userApp.GetPublicKeySECP256K1(path)
	if err != nil {
		t.Fatalf("Detected error, err: %s\n", err.Error())
	}

	assert.Equal(t, 33, len(pubKey),
		"Public key has wrong length: %x, expected length: %x\n", pubKey, 65)
	fmt.Printf("PUBLIC KEY: %x\n", pubKey)

	assert.Equal(t,
		"038b2084dc92ad489c9f59cf63c17d2ecff2fd416469ac069b93059aef74174bb1",
		hex.EncodeToString(pubKey),
		"Unexpected pubkey")
}

func Test_GetAddressPubKeySECP256K1_Zero(t *testing.T) {
	userApp, err := FindLedgerCosmosUserApp()
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer userApp.Close()

	userApp.api.Logging = true

	hrp := "und"
	path := []uint32{44, 5555, 0, 0, 0}

	pubKey, addr, err := userApp.GetAddressPubKeySECP256K1(path, hrp)
	if err != nil {
		t.Fatalf("Detected error, err: %s\n", err.Error())
	}

	fmt.Printf("PUBLIC KEY : %x\n", pubKey)
	fmt.Printf("BECH32 ADDR: %s\n", addr)

	assert.Equal(t, 33, len(pubKey), "Public key has wrong length: %x, expected length: %x\n", pubKey, 65)

	assert.Equal(t, "02265fd25096393614e9d5c6362cfad6291c6b7554b16cbd711f4fb5c720e126b5", hex.EncodeToString(pubKey), "Unexpected pubkey")
	assert.Equal(t, "und1nkcrcf4ymjq4j9rdmuhturgn3c23lr90kxxwkj", addr, "Unexpected addr")
}

func Test_GetAddressPubKeySECP256K1(t *testing.T) {
	userApp, err := FindLedgerCosmosUserApp()
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer userApp.Close()

	userApp.api.Logging = true

	hrp := "und"
	path := []uint32{44, 5555, 5, 0, 21}

	pubKey, addr, err := userApp.GetAddressPubKeySECP256K1(path, hrp)
	if err != nil {
		t.Fatalf("Detected error, err: %s\n", err.Error())
	}

	fmt.Printf("PUBLIC KEY : %x\n", pubKey)
	fmt.Printf("BECH32 ADDR: %s\n", addr)

	assert.Equal(t, 33, len(pubKey), "Public key has wrong length: %x, expected length: %x\n", pubKey, 65)

	assert.Equal(t, "038b2084dc92ad489c9f59cf63c17d2ecff2fd416469ac069b93059aef74174bb1", hex.EncodeToString(pubKey), "Unexpected pubkey")
	assert.Equal(t, "und1k4jy3y74fy007nf3w6atjgywclp7f204v0qekx", addr, "Unexpected addr")
}

func Test_UserPK_HDPaths(t *testing.T) {
	userApp, err := FindLedgerCosmosUserApp()
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer userApp.Close()

	userApp.api.Logging = true

	path := []uint32{44, 5555, 0, 0, 0}

	expected := []string{
		"02265fd25096393614e9d5c6362cfad6291c6b7554b16cbd711f4fb5c720e126b5",
		"037c33a9c03e05fbabe34e07fb51380f92bb85b39332ada7aaffbafa06001951fa",
		"039f725c714dddff552261dfb58b031aed161d9322e25df2682d31eb6f33e422ad",
		"03f8b3ecda6faa9a713fa5f77cafc82768b3461680196d2601928b4959668b08a1",
		"02f0c8e998820ea9d9796bebaf6163465a15e45d4716aab60ebb517bf6ab8d7e75",
		"0353733cf6cfeb0a1e47645e371accd3b906d88724e6b289e87e25fb11a62e988e",
		"0362a16d66460f20a8b9b6df1864d81f5769209cdea133906d23becbdc172fb6ba",
		"02cffc765f44a0a94fca2bcfd0724efef024cf2b7bd32ebff7d69fccbc3f81ac55",
		"02d4f8c815e368ed26dc66b47458ee564abe4306cffd2ce56e236be9f4d422318f",
		"036dfc242b93f1328f9c0465eb2e7c3f6ca189b9975db54ad018061dea939daaff",
	}

	for i := uint32(0); i < 10; i++ {
		path[4] = i

		pubKey, err := userApp.GetPublicKeySECP256K1(path)
		if err != nil {
			t.Fatalf("Detected error, err: %s\n", err.Error())
		}

		assert.Equal(
			t,
			33,
			len(pubKey),
			"Public key has wrong length: %x, expected length: %x\n", pubKey, 65)

		assert.Equal(
			t,
			expected[i],
			hex.EncodeToString(pubKey),
			"Public key 44'/5555'/0'/0/%d does not match\n", i)

		_, err = btcec.ParsePubKey(pubKey[:], btcec.S256())
		require.Nil(t, err, "Error parsing public key err: %s\n", err)

	}
}

func getDummyTx() []byte {
	dummyTx := `{
		"account_number": 1,
		"chain_id": "some_chain",
		"fee": {
			"amount": [{"amount": 10, "denom": "DEN"}],
			"gas": 5
		},
		"memo": "MEMO",
		"msgs": ["SOMETHING"],
		"sequence": 3
	}`
	dummyTx = strings.Replace(dummyTx, " ", "", -1)
	dummyTx = strings.Replace(dummyTx, "\n", "", -1)
	dummyTx = strings.Replace(dummyTx, "\t", "", -1)

	return []byte(dummyTx)
}

func Test_UserSign(t *testing.T) {
	userApp, err := FindLedgerCosmosUserApp()
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer userApp.Close()

	userApp.api.Logging = true

	path := []uint32{44, 5555, 0, 0, 5}

	message := getDummyTx()
	signature, err := userApp.SignSECP256K1(path, message)
	fmt.Printf("SIGNATURE : %x\n",  signature)
	if err != nil {
		t.Fatalf("[Sign] Error: %s\n", err.Error())
	}

	// Verify Signature
	pubKey, err := userApp.GetPublicKeySECP256K1(path)
	fmt.Printf("PUBLIC KEY : %x\n",  pubKey)
	if err != nil {
		t.Fatalf("Detected error, err: %s\n", err.Error())
	}

	if err != nil {
		t.Fatalf("[GetPK] Error: " + err.Error())
		return
	}

	pub2, err := btcec.ParsePubKey(pubKey[:], btcec.S256())
	fmt.Printf("PUBLIC KEY2 : %x\n",  pub2)
	if err != nil {
		t.Fatalf("[ParsePK] Error: " + err.Error())
		return
	}

	sig2, err := btcec.ParseDERSignature(signature[:], btcec.S256())
	fmt.Printf("SIGNATURE 2 : %x\n",  sig2)
	if err != nil {
		t.Fatalf("[ParseSig] Error: " + err.Error())
		return
	}

	hash := sha256.Sum256(message)
	verified := sig2.Verify(hash[:], pub2)
	fmt.Printf("VERIFIED : %t\n",  verified)
	if !verified {
		t.Fatalf("[VerifySig] Error verifying signature: " + err.Error())
		return
	}
}

func Test_UserSign_Fails(t *testing.T) {
	userApp, err := FindLedgerCosmosUserApp()
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer userApp.Close()

	userApp.api.Logging = true

	path := []uint32{44, 5555, 0, 0, 5}

	message := getDummyTx()
	garbage := []byte{65}
	message = append(garbage, message...)

	_, err = userApp.SignSECP256K1(path, message)
	assert.Error(t, err)
	errMessage := err.Error()

	if errMessage != "Invalid character in JSON string" && errMessage != "Unexpected characters" {
		assert.Fail(t, "Unexpected error message returned: " + errMessage )
	}
}
