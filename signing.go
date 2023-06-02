package did

import (
	"crypto/sha256"
)

const (
	TEd25519 = "ed25519"
)

type Signature struct {
	Bytes []byte
	Type  string
}

type SignedDocument struct {
	Signature *Signature `json:"signature"`
	Document  *Document  `json:"document"`

	// TODO: should probably have a sequence number on these to prevent replays
	//Sequence  int        `json:"seq"`
}

func SignDocument(doc *Document, k *PrivKey) (*SignedDocument, error) {
	b, err := doc.Serialize()
	if err != nil {
		return nil, err
	}

	h := sha256.Sum256(b)
	sig, err := k.Sign(h[:])
	if err != nil {
		return nil, err
	}

	return &SignedDocument{
		Document: doc,
		Signature: &Signature{
			Bytes: sig,
			Type:  TEd25519,
		},
	}, nil
}

func VerifyDocumentSignature(sd *SignedDocument, pubk *PubKey) error {
	b, err := sd.Document.Serialize()
	if err != nil {
		return err
	}

	h := sha256.Sum256(b)
	return pubk.Verify(h[:], sd.Signature.Bytes)
}
