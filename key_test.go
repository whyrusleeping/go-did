package did

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
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

	sig, err := sk.Sign(msg)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println(sig)

	if err := sk.Public().Verify(msg, sig); err != nil {
		t.Fatal(err)
	}
}

func TestKeySignVerifySecp256k(t *testing.T) {
	k, err := ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	sk := &PrivKey{
		Type: KeyTypeSecp256k1,
		Raw:  k,
	}

	msg := []byte("foo bar beep boop bop")

	sig, err := sk.Sign(msg)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println(sig)

	if err := sk.Public().Verify(msg, sig); err != nil {
		t.Fatal(err)
	}
}
