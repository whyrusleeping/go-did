package did

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

const (
	CtxDIDv1             = "https://www.w3.org/ns/did/v1"
	CtxSecEd25519_2020v1 = "https://w3id.org/security/suites/ed25519-2020/v1"
	CtxSecX25519_2019v1  = "https://w3id.org/security/suites/x25519-2019/v1"
)

type DID struct {
	raw      string
	proto    string
	value    string
	fragment string
}

func (d *DID) String() string {
	return d.raw
}

func (d *DID) Value() string {
	return d.value
}

func (d DID) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.raw)
}

func (d *DID) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}

	o, err := ParseDID(s)
	if err != nil {
		return err
	}

	*d = o
	return nil
}

func (d *DID) Protocol() string {
	return d.proto
}

func ParseDID(s string) (DID, error) {
	// Fragment only DID
	if strings.HasPrefix(s, "#") {
		return DID{
			raw:      s,
			fragment: s,
		}, nil
	}

	dfrag := strings.SplitN(s, "#", 2)

	segm := strings.SplitN(dfrag[0], ":", 3)
	if len(segm) != 3 {
		return DID{}, fmt.Errorf("invalid did: must contain three parts: %v", segm)
	}

	if segm[0] != "did" {
		return DID{}, fmt.Errorf("invalid did: first segment must be 'did'")
	}

	var frag string
	if len(dfrag) == 2 {
		frag = "#" + dfrag[1]
	}

	return DID{
		raw:      s,
		proto:    segm[1],
		value:    segm[2],
		fragment: frag,
	}, nil
}

type Document struct {
	Context []string `json:"@context"`

	ID DID `json:"id"`

	AlsoKnownAs []string `json:"alsoKnownAs"`

	Authentication []interface{} `json:"authentication"`

	VerificationMethod []VerificationMethod `json:"verificationMethod"`

	Service []Service `json:"service"`
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
	ID                 string        `json:"id"`
	Type               string        `json:"type"`
	Controller         string        `json:"controller"`
	PublicKeyJwk       *PublicKeyJwk `json:"publicKeyJwk,omitempty"`
	PublicKeyMultibase *string       `json:"publicKeyMultibase,omitempty"`
}

func (vm VerificationMethod) GetPublicKey() (*PubKey, error) {
	if vm.PublicKeyJwk != nil {
		k, err := vm.PublicKeyJwk.GetRawKey()
		if err != nil {
			return nil, err
		}

		ek, ok := k.(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("only ed25519 keys are currently supported")
		}

		return &PubKey{
			Type: "ed25519",
			Raw:  []byte(ek),
		}, nil
	}

	if vm.PublicKeyMultibase != nil {
		k, err := KeyFromMultibase(vm)
		if err != nil {
			return nil, err
		}

		return k, nil

	}

	return nil, fmt.Errorf("no public key specified in verificationMethod")
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

func (d *Document) GetPublicKey(id string) (*PubKey, error) {
	for _, vm := range d.VerificationMethod {
		if id == vm.ID || id == "" {
			return vm.GetPublicKey()
		}
	}

	return nil, fmt.Errorf("no key found by that ID")
}
