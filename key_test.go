package did

import (
	"crypto"
	"crypto/rand"
	"testing"
)

var allKeyTypes = []string{
	KeyTypeSecp256k1,
	KeyTypeP256,
	KeyTypeEd25519,
}

type privEqualAble interface {
	Equal(x crypto.PrivateKey) bool
}

type pubEqualAble interface {
	Equal(x crypto.PublicKey) bool
}

func TestKey(t *testing.T) {
	t.Run("Integration", func(t *testing.T) {
		for _, keyType := range allKeyTypes {
			t.Run(keyType, func(t *testing.T) {
				sk, err := GeneratePrivKey(rand.Reader, keyType)
				if err != nil {
					t.Fatal(err)
				}
				if sk.Type != keyType {
					t.Fatalf("secret key type mismatch: got %s, expected %s", sk.Type, keyType)
				}

				pk := sk.Public()
				if pk.Type != keyType {
					t.Fatalf("public key type mismatch: got %s, expected %s", pk.Type, keyType)
				}

				msg := []byte("foo bar beep boop bop")

				sig, err := sk.Sign(msg)
				if err != nil {
					t.Fatal(err)
				}

				if err := pk.Verify(msg, sig); err != nil {
					t.Fatal(err)
				}
			})
		}
	})

	t.Run("s11n", func(t *testing.T) {
		for _, keyType := range allKeyTypes {
			t.Run(keyType, func(t *testing.T) {
				sk, err := GeneratePrivKey(rand.Reader, keyType)
				if err != nil {
					t.Fatal(err)
				}
				pk := sk.Public()

				skBytes, _ := sk.RawBytes()
				sk2, err := PrivKeyFromRawBytes(keyType, skBytes)
				if err != nil {
					t.Fatal(err)
				}

				skRaw, sk2Raw := sk.Raw.(privEqualAble), sk2.Raw.(crypto.PrivateKey)
				if !skRaw.Equal(sk2Raw) {
					t.Fatalf("private key raw did not round-trip: got %+v, expected %+v", sk2Raw, skRaw)
				}

				// Roundtrip Multibase encoding.
				pkStr := pk.MultibaseString()

				vm := VerificationMethod{
					Type:               keyType,
					PublicKeyMultibase: &pkStr,
				}
				pk2, err := KeyFromMultibase(vm)
				if err != nil {
					t.Fatal(err)
				}

				if pk.Type != pk2.Type {
					t.Fatalf("public key type did not round-trip: got %s, expected %s", pk2.Type, pk.Type)
				}

				pkDID, pk2DID := pk.DID(), pk2.DID()
				if pkDID != pk2DID {
					t.Fatalf("public key DID did not round-trip: got %s, expected %s", pk2DID, pkDID)
				}

				pkRaw, pk2Raw := pk.Raw.(pubEqualAble), pk2.Raw.(crypto.PublicKey)
				if !pkRaw.Equal(pk2Raw) {
					t.Fatalf("public key raw did not round-trip: got %+v, expected %+v", pk2Raw, pkRaw)
				}
			})
		}
	})
}
