package did

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"testing"
)

func TestDidDoc(t *testing.T) {
	testPaths := []string{
		"testdata/did_doc_legacy.json",
		"testdata/did_doc_multikey.json",
	}
	for _, path := range testPaths {
		f, err := os.Open(path)
		if err != nil {
			t.Error(err)
		}
		defer f.Close()
		fBytes, err := io.ReadAll(f)
		if err != nil {
			t.Error(err)
		}

		var doc Document
		if err := json.Unmarshal(fBytes, &doc); err != nil {
			t.Error(err)
		}

		pk, err := doc.GetPublicKey("#atproto")
		if err != nil {
			t.Error(err)
		}

		if pk.DID() != "did:key:zQ3shXjHeiBuRCKmM36cuYnm7YEMzhGnCmCyW92sRJ9pribSF" {
			fmt.Println(pk.DID())
			t.Error("didn't export key as expected")
		}
	}
}

func TestSig(t *testing.T) {
	vmstr := `{
      "id": "#atproto",
      "type": "EcdsaSecp256k1VerificationKey2019",
      "controller": "did:plc:wj5jny4sq4sohwoaxjkjgug6",
      "publicKeyMultibase": "zQYEBzXeuTM9UR3rfvNag6L3RNAs5pQZyYPsomTsgQhsxLdEgCrPTLgFna8yqCnxPpNT7DBk6Ym3dgPKNu86vt9GR"
    }`
	var vm VerificationMethod

	if err := json.Unmarshal([]byte(vmstr), &vm); err != nil {
		t.Fatal(err)
	}

	_, err := vm.GetPublicKey()
	if err != nil {
		t.Fatal(err)
	}
}
