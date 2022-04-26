package did

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

const (
	CtxDIDv1             = "https://www.w3.org/ns/did/v1"
	CtxSecEd25519_2020v1 = "https://w3id.org/security/suites/ed25519-2020/v1"
	CtxSecX25519_2019v1  = "https://w3id.org/security/suites/x25519-2019/v1"
)

type DID struct {
	val string
}

func (d *DID) String() string {
	return d.val
}

func (d DID) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.val)
}

func (d *DID) UnmarshalJSON(b []byte) error {
	return json.Unmarshal(b, &d.val)
}

func ParseDID(s string) (DID, error) {
	// TODO: some actual parsing
	return DID{val: s}, nil
}

type Document struct {
	Context []string `json:"@context"`

	ID DID `json:"id"`

	Authentication []interface{} `json:"authentication"`

	VerificationMethod []VerificationMethod `json:"verificationMethod"`

	Services []Service `json:"services"`
}

// TODO: this needs to be a 'canonical' serialization
func (d *Document) Serialize() ([]byte, error) {
	return json.Marshal(d)
}

type Service struct {
	ID              DID    `json:"id"`
	Type            string `json:"type"`
	ServiceEndpoint string `json:"serviceEndpoint"`
}

type VerificationMethod struct {
	ID                 DID           `json:"id"`
	Type               string        `json:"type"`
	Controller         string        `json:"controller"`
	PublicKeyJwk       *PublicKeyJwk `json:"publicKeyJwk,omitempty"`
	PublicKeyMultibase *string       `json:"publicKeyMultibase,omitempty"`
}

func (vm VerificationMethod) GetPublicKey() (ed25519.PublicKey, error) {
	if vm.PublicKeyJwk != nil {
		k, err := vm.PublicKeyJwk.GetRawKey()
		if err != nil {
			return nil, err
		}

		ek, ok := k.(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("only ed25519 keys are currently supported")
		}

		return ek, nil
	}

	return nil, fmt.Errorf("currently only jwk format keys are allowed")
}

type PublicKeyJwk struct {
	Key jwk.Key
}

func (pkj *PublicKeyJwk) UnmarshalJSON(b []byte) error {
	parsed, err := jwk.Parse(b)
	if err != nil {
		return err
	}

	if parsed.Len() != 1 {
		return fmt.Errorf("expected a single key in the jwk field")
	}

	k, ok := parsed.Key(0)
	if !ok {
		return fmt.Errorf("should be unpossible")
	}

	pkj.Key = k

	return nil
}

func (pkj *PublicKeyJwk) MarshalJSON() ([]byte, error) {
	return json.Marshal(pkj.Key)
}

func (pk *PublicKeyJwk) GetRawKey() (interface{}, error) {
	var rawkey interface{}
	if err := pk.Key.Raw(&rawkey); err != nil {
		return nil, err
	}

	return rawkey, nil
}

func (d *Document) GetPublicKey() (ed25519.PublicKey, error) {
	if len(d.VerificationMethod) != 1 {
		return nil, fmt.Errorf("doc must have only one verification method (todo: fixme)")
	}
	vm := d.VerificationMethod[0]

	return vm.GetPublicKey()
}
