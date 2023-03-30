package did

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/ipsn/go-secp256k1"
)

func TestKeySignVerifyP256(t *testing.T) {
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

func TestKeySignVerifyK256(t *testing.T) {
	k, err := ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// this bit copied from upstream go-secp256k1 tests
	privkey := make([]byte, 32)
	blob := k.D.Bytes()
	copy(privkey[32-len(blob):], blob)

	sk := &PrivKey{
		Type: KeyTypeSecp256k1,
		Raw:  privkey,
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

func TestKeySignVerifyEd25519(t *testing.T) {
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	sk := &PrivKey{
		Type: KeyTypeEd25519,
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
