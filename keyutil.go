package did

import (
	"crypto/ed25519"
	"fmt"

	"github.com/multiformats/go-multibase"
)

func DIDFromKey(k interface{}) (DID, error) {
	switch k := k.(type) {
	case ed25519.PublicKey:
		return didFromEd15519(k), nil
	default:
		return DID{}, fmt.Errorf("unrecognized key type: %T", k)
	}
}

func didFromEd15519(k ed25519.PublicKey) DID {
	b := append([]byte{0xed}, k...)
	str, _ := multibase.Encode(multibase.Base58BTC, b)
	id, err := ParseDID(fmt.Sprintf("did:key:%s", str))
	if err != nil {
		panic(err)
	}

	return id
}
