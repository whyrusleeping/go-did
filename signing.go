package did

import (
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
)

const (
	TEd25519 = "ed25519"
)

type Signature struct {
	Bytes []byte
	Type  string
}

type SignedDocument struct {
	Signature *Signature
	Document  *Document
}

func SignDocument(doc *Document, k ed25519.PrivateKey) (*SignedDocument, error) {
	b, err := doc.Serialize()
	if err != nil {
		return nil, err
	}

	h := sha256.Sum256(b)

	sig := ed25519.Sign(k, h[:])

	return &SignedDocument{
		Document: doc,
		Signature: &Signature{
			Bytes: sig,
			Type:  TEd25519,
		},
	}, nil
}

func VerifyDocumentSignature(sd *SignedDocument, pubk ed25519.PublicKey) error {
	b, err := sd.Document.Serialize()
	if err != nil {
		return err
	}

	h := sha256.Sum256(b)

	if !ed25519.Verify(pubk, h[:], sd.Signature.Bytes) {
		return fmt.Errorf("invalid signature")
	}
	return nil
}
