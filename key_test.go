package did

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"testing"
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
