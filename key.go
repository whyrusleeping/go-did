package did

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"math/big"

	"github.com/multiformats/go-multibase"
	"github.com/multiformats/go-varint"

	secp "github.com/ipsn/go-secp256k1"
)

const (
	MCed25519   = 0xED
	MCP256      = 0x1200
	MCSecp256k1 = 0xe7
)
const (
	KeyTypeSecp256k1 = "EcdsaSecp256k1VerificationKey2019"
	KeyTypeP256      = "EcdsaSecp256r1VerificationKey2019"
	KeyTypeEd25519   = "Ed25519VerificationKey2020"
)

type PrivKey struct {
	Raw  interface{}
	Type string
}

func (k *PrivKey) Public() *PubKey {
	switch k.Type {
	case KeyTypeEd25519:
		kb := k.Raw.(ed25519.PrivateKey)
		pub := kb.Public().(ed25519.PublicKey)

		return &PubKey{
			Type: k.Type,
			Raw:  pub,
		}
	case KeyTypeP256:
		sk := k.Raw.(*ecdsa.PrivateKey)

		return &PubKey{
			Type: k.Type,
			Raw:  elliptic.MarshalCompressed(elliptic.P256(), sk.X, sk.Y),
		}
	case KeyTypeSecp256k1:
		curve := secp.S256()
		x, y := curve.ScalarBaseMult(k.Raw.([]byte))
		encPub := elliptic.MarshalCompressed(secp.S256(), x, y)

		return &PubKey{
			Type: k.Type,
			Raw:  encPub,
		}
	default:
		panic("invalid key type")
	}
}

func (k *PrivKey) Sign(b []byte) ([]byte, error) {
	switch k.Type {
	case KeyTypeEd25519:
		return ed25519.Sign(k.Raw.(ed25519.PrivateKey), b), nil
	case KeyTypeP256:
		h := sha256.Sum256(b)
		//return ecdsa.SignASN1(rand.Reader, k.Raw.(*ecdsa.PrivateKey), h[:])
		r, s, err := ecdsa.Sign(rand.Reader, k.Raw.(*ecdsa.PrivateKey), h[:])
		if err != nil {
			return nil, err
		}

		out := make([]byte, 64)
		copy(out[:32], r.Bytes())
		copy(out[32:], s.Bytes())

		return out, nil
	case KeyTypeSecp256k1:
		h := sha256.Sum256(b)

		return secp.Sign(h[:], k.Raw.([]byte))
	default:
		return nil, fmt.Errorf("unsupported key type: %s", k.Type)
	}
}

func (k *PrivKey) KeyType() string {
	return k.Type
}

func varEncode(pref uint64, body []byte) []byte {
	buf := make([]byte, 8+len(body))
	n := varint.PutUvarint(buf, pref)
	copy(buf[n:], body)
	buf = buf[:n+len(body)]

	return buf
}

type PubKey struct {
	Raw  any
	Type string
}

func (k *PubKey) DID() string {
	return "did:key:" + k.MultibaseString()
}

func (k *PubKey) MultibaseString() string {
	var buf []byte
	switch k.Type {
	case KeyTypeEd25519:
		buf = varEncode(MCed25519, k.Raw.([]byte))
	case KeyTypeP256:
		buf = varEncode(MCP256, k.Raw.([]byte))
	case KeyTypeSecp256k1:
		buf = varEncode(MCSecp256k1, k.Raw.([]byte))
	default:
		return "<invalid key type>"
	}

	kstr, err := multibase.Encode(multibase.Base58BTC, buf)
	if err != nil {
		panic(err)
	}
	return kstr
}

var ErrInvalidSignature = fmt.Errorf("invalid signature")

func (k *PubKey) Verify(msg, sig []byte) error {
	switch k.Type {
	case KeyTypeEd25519:
		if !ed25519.Verify(k.Raw.(ed25519.PublicKey), msg, sig) {
			return ErrInvalidSignature
		}

		return nil
	case KeyTypeP256:
		x, y := elliptic.UnmarshalCompressed(elliptic.P256(), k.Raw.([]byte))
		pubk := &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     x,
			Y:     y,
		}

		r, s, err := parseP256Sig(sig)
		if err != nil {
			return err
		}

		h := sha256.Sum256(msg)
		if !ecdsa.Verify(pubk, h[:], r, s) {
			return ErrInvalidSignature
		}
		return nil

	case KeyTypeSecp256k1:
		panic("nyi")
	default:
		return fmt.Errorf("unsupported key type: %q", k.Type)

	}
}

func parseP256Sig(buf []byte) (*big.Int, *big.Int, error) {
	if len(buf) != 64 {
		return nil, nil, fmt.Errorf("p256 signatures must be 64 bytes")
	}

	r := big.NewInt(0)
	s := big.NewInt(0)

	r.SetBytes(buf[:32])
	s.SetBytes(buf[32:])

	return r, s, nil
}

func (k *PrivKey) RawBytes() ([]byte, error) {
	switch k.Type {
	case KeyTypeEd25519:
		return k.Raw.([]byte), nil
	case KeyTypeP256:
		b, err := x509.MarshalECPrivateKey(k.Raw.(*ecdsa.PrivateKey))
		if err != nil {
			return nil, err
		}

		return b, nil
	case KeyTypeSecp256k1:
		return k.Raw.([]byte), nil
	default:
		return nil, fmt.Errorf("unsupported key type: %q", k.Type)
	}
}

func KeyFromMultibase(mbstr string) (*PubKey, error) {
	_, data, err := multibase.Decode(mbstr)
	if err != nil {
		return nil, err
	}

	val, n, err := varint.FromUvarint(data)
	if err != nil {
		return nil, err
	}

	switch val {
	case MCed25519:
		return &PubKey{
			Type: KeyTypeEd25519,
			Raw:  data[n:],
		}, nil
	case MCP256:
		return &PubKey{
			Type: KeyTypeP256,
			Raw:  data[n:],
		}, nil
	case MCSecp256k1:
		return &PubKey{
			Type: KeyTypeSecp256k1,
			Raw:  data[n:],
		}, nil
	default:
		return nil, fmt.Errorf("unrecognized key multicodec")
	}
}
