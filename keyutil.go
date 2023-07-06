package did

import (
	"crypto/ed25519"
	"fmt"

	"github.com/multiformats/go-multibase"
)

// OldDIDFromKey is specific to ed25519.PublicKey and is the other way
// this package used to construct DIDs, using an encoding method that
// was inconsistent with itself.
func OldDIDFromKey(k interface{}) (DID, error) {
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
