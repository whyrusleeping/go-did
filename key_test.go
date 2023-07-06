package did

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"testing"

	secp "github.com/ipsn/go-secp256k1"
	"github.com/multiformats/go-multibase"
)

func TestKeySignVerify(t *testing.T) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	sk := &PrivKey{
		Type: KeyTypeP256,
		Raw:  k,
	}

	msg := []byte("foo bar beep boop bop")

	for i := 0; i < 5000; i++ {
		sig, err := sk.Sign(msg)
		if err != nil {
			t.Fatal(err)
		}

		enc, err := multibase.Encode(multibase.Base58BTC, sk.Public().Raw.([]byte))
		if err != nil {
			t.Fatal(err)
		}

		rpk, err := KeyFromMultibase(VerificationMethod{
			ID:                 "#atproto",
			Type:               "EcdsaSecp256r1VerificationKey2019",
			PublicKeyMultibase: &enc,
		})
		if err != nil {
			t.Fatal(err)
		}

		fmt.Println(sig)
		if err := rpk.Verify(msg, sig); err != nil {
			t.Fatalf("iteration %d: %s", i, err)
		}
	}
}

func TestKeySignVerifySecp(t *testing.T) {
	t.Skip()
	k, err := ecdsa.GenerateKey(secp.S256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	privkey := make([]byte, 32)
	blob := k.D.Bytes()
	copy(privkey[32-len(blob):], blob)

	pubkey := elliptic.Marshal(secp.S256(), k.X, k.Y)

	fmt.Printf("PUBKEY: %x\n", pubkey)

	sk := &PrivKey{
		Type: KeyTypeSecp256k1,
		Raw:  privkey,
	}

	msg := []byte("foo bar beep boop bop")

	sig, err := sk.Sign(msg)
	if err != nil {
		t.Fatal(err)
	}

	mbs := sk.Public().MultibaseString()
	fmt.Println("MULTIBASE: ", mbs)

	rpk, err := KeyFromMultibase(VerificationMethod{
		ID:                 "#atproto",
		Type:               KeyTypeSecp256k1,
		PublicKeyMultibase: &mbs,
	})
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println(sig)

	fmt.Printf("RPK: %x\n", rpk.Raw)

	if err := rpk.Verify(msg, sig); err != nil {
		t.Fatal(err)
	}
}
