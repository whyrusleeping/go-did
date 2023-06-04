package did

import (
	"bytes"
	"crypto/rand"
	"testing"
)

var allKeyTypes = []string{
	KeyTypeSecp256k1,
	KeyTypeP256,
	KeyTypeEd25519,
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

				skBytes, _ := sk.RawBytes()
				_ = skBytes // At some point, test round-tripping this.
				pk := sk.Public()

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

				pkB, pk2B := pk.Raw.([]byte), pk2.Raw.([]byte)
				if !bytes.Equal(pkB, pk2B) {
					t.Fatalf("public key raw did not round-trip: got %x, expected %x", pk2B, pkB)
				}

				pkDID, pk2DID := pk.DID(), pk2.DID()
				if pkDID != pk2DID {
					t.Fatalf("public key DID did not round-trip: got %s, expected %s", pk2DID, pkDID)
				}
			})
		}
	})
}
