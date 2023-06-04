package did

import (
	"crypto/rand"
	"testing"
)

func TestKey(t *testing.T) {
	t.Run("Integration", func(t *testing.T) {
		for _, keyType := range []string{
			KeyTypeSecp256k1,
			KeyTypeP256,
			KeyTypeEd25519,
		} {
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
}
