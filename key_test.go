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

				pk2, err := PubKeyFromMultibaseString(pkStr)
				if err != nil {
					t.Fatal(err)
				}
				if !pk.Equal(pk2) {
					t.Fatalf("public key did not round-trip: got %+v, expected %+v", pk2, pk)
				}

				// Roundtrip Multibase VM encoding.
				vm, err := VerificationMethodFromKey(pk)
				if err != nil {
					t.Fatal(err)
				}

				pk3, err := vm.GetPublicKey()
				if err != nil {
					t.Fatal(err)
				}
				if !pk.Equal(pk3) {
					t.Fatalf("public key did not round-trip: got %+v, expected %+v", pk3, pk)
				}

				// Roundtrip DID encoding.
				//
				// TODO: Generate known-good DID test vectors for all the
				// key types and also test.
				pkDID := pk.DID()
				pk4, err := PubKeyFromDIDString(pkDID)
				if err != nil {
					t.Fatal(err)
				}
				if !pk.Equal(pk4) {
					t.Fatalf("public key did not round-trip: got %+v, expected %+v", pk4, pk)
				}

				// Test generic DID from library key
				pkRaw := pk.Raw.(crypto.PublicKey)
				did, err := DIDFromKey(pkRaw)
				if err != nil {
					t.Fatal(err)
				}

				if didStr := did.String(); didStr != pkDID {
					t.Fatalf("did mismatch: got %+v, expected %+v", didStr, pkDID)
				}
			})
		}
	})
}
