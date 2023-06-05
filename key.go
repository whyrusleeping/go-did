package did

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"io"
	"math/big"

	"github.com/multiformats/go-multibase"
	"github.com/multiformats/go-varint"

	secp "gitlab.com/yawning/secp256k1-voi"
	secpEc "gitlab.com/yawning/secp256k1-voi/secec"
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

var varPrefixMap = map[string]uint64{
	KeyTypeSecp256k1: MCSecp256k1,
	KeyTypeP256:      MCP256,
	KeyTypeEd25519:   MCed25519,
}

type PrivKey struct {
	Raw  any
	Type string
}

func (k *PrivKey) Public() *PubKey {
	switch k.Type {
	case KeyTypeEd25519:
		sk := k.Raw.(ed25519.PrivateKey)

		return &PubKey{
			Type: k.Type,
			Raw:  sk.Public().(ed25519.PublicKey),
		}
	case KeyTypeP256:
		sk := k.Raw.(*ecdsa.PrivateKey)

		return &PubKey{
			Type: k.Type,
			Raw:  sk.Public().(*ecdsa.PublicKey),
		}
	case KeyTypeSecp256k1:
		sk := k.Raw.(*secpEc.PrivateKey)

		return &PubKey{
			Type: k.Type,
			Raw:  sk.PublicKey(),
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

		r, s, err := ecdsa.Sign(rand.Reader, k.Raw.(*ecdsa.PrivateKey), h[:])
		if err != nil {
			return nil, err
		}

		out := make([]byte, 64)
		r.FillBytes(out[:32])
		s.FillBytes(out[32:])

		return out, nil
	case KeyTypeSecp256k1:
		h := sha256.Sum256(b)

		sk := k.Raw.(*secpEc.PrivateKey)
		r, s, _, err := sk.Sign(rand.Reader, h[:])
		if err != nil {
			return nil, err
		}

		out := make([]byte, 0, 64)
		out = append(out, r.Bytes()...)
		out = append(out, s.Bytes()...)

		return out, nil
	default:
		return nil, fmt.Errorf("unsupported key type: %s", k.Type)
	}
}

func (k *PrivKey) KeyType() string {
	return k.Type
}

func GeneratePrivKey(rng io.Reader, keyType string) (*PrivKey, error) {
	ret := &PrivKey{
		Type: keyType,
	}

	var err error
	switch keyType {
	case KeyTypeP256:
		if ret.Raw, err = ecdsa.GenerateKey(elliptic.P256(), rng); err != nil {
			return nil, fmt.Errorf("p256 key generation failed: %w", err)
		}
	case KeyTypeEd25519:
		if _, ret.Raw, err = ed25519.GenerateKey(rng); err != nil {
			return nil, fmt.Errorf("ed25519 key generation failed: %w", err)
		}
	case KeyTypeSecp256k1:
		if ret.Raw, err = secpEc.GenerateKey(rng); err != nil {
			return nil, fmt.Errorf("k256 key generation failed: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported key type: %s", keyType)
	}
	return ret, nil
}

func varEncode(pref uint64, body []byte) []byte {
	buf := make([]byte, 8+len(body))
	n := varint.PutUvarint(buf, pref)
	copy(buf[n:], body)
	buf = buf[:n+len(body)]

	return buf
}

func varDecode(buf []byte) (uint64, []byte, error) {
	prefix, left, err := varint.FromUvarint(buf)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to read prefix: %w", err)
	}
	return prefix, buf[left:], nil
}

type PubKey struct {
	Raw  any
	Type string
}

func (k *PubKey) DID() string {
	return "did:key:" + k.MultibaseString()
}

func (k *PubKey) MultibaseString() string {
	prefix, ok := varPrefixMap[k.Type]
	if !ok {
		return "<invalid key type>"
	}

	var kb []byte
	switch k.Type {
	case KeyTypeEd25519:
		kb = []byte(k.Raw.(ed25519.PublicKey))
	case KeyTypeP256:
		pk := k.Raw.(*ecdsa.PublicKey)
		if !pk.Curve.IsOnCurve(pk.X, pk.Y) {
			return "<invalid key>"
		}
		kb = elliptic.MarshalCompressed(pk.Curve, pk.X, pk.Y)
	case KeyTypeSecp256k1:
		pk := k.Raw.(*secpEc.PublicKey)
		p := pk.Point()
		if p.IsIdentity() != 0 {
			return "<invalid key>"
		}
		kb = p.CompressedBytes()
	}
	buf := varEncode(prefix, kb)

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
		pk := k.Raw.(ed25519.PublicKey)

		if !ed25519.Verify(pk, msg, sig) {
			return ErrInvalidSignature
		}

		return nil
	case KeyTypeP256:
		pk := k.Raw.(*ecdsa.PublicKey)

		r, s, err := parseP256Sig(sig)
		if err != nil {
			return err
		}

		h := sha256.Sum256(msg)
		if !ecdsa.Verify(pk, h[:], r, s) {
			return ErrInvalidSignature
		}

		return nil
	case KeyTypeSecp256k1:
		pk := k.Raw.(*secpEc.PublicKey)

		r, s, err := parseK256Sig(sig)
		if err != nil {
			return err
		}

		h := sha256.Sum256(msg)

		// Checking `s <= n/2` to prevent signature mallability is not
		// part of SEC 1, Version 2.0.  libsecp256k1 which used to be
		// used by this package, includes the check, so retain behavior
		// compatibility.
		if s.IsGreaterThanHalfN() != 0 {
			return ErrInvalidSignature
		}

		if !pk.Verify(h[:], r, s) {
			return ErrInvalidSignature
		}

		return nil
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

func parseK256Sig(buf []byte) (*secp.Scalar, *secp.Scalar, error) {
	if len(buf) != 2*secp.ScalarSize {
		return nil, nil, fmt.Errorf("k256 signatures must be 64 bytes")
	}

	r, err := secp.NewScalarFromCanonicalBytes((*[secp.ScalarSize]byte)(buf[:32]))
	if err != nil {
		return nil, nil, fmt.Errorf("invalid k256 signature r: %w", err)
	}

	s, err := secp.NewScalarFromCanonicalBytes((*[secp.ScalarSize]byte)(buf[32:]))
	if err != nil {
		return nil, nil, fmt.Errorf("invalid k256 signature s: %w", err)
	}

	return r, s, nil
}

func (k *PrivKey) RawBytes() ([]byte, error) {
	switch k.Type {
	case KeyTypeEd25519:
		kb := k.Raw.(ed25519.PrivateKey)
		return []byte(kb), nil
	case KeyTypeP256:
		kb, err := x509.MarshalECPrivateKey(k.Raw.(*ecdsa.PrivateKey))
		if err != nil {
			return nil, err
		}

		return kb, nil
	case KeyTypeSecp256k1:
		return k.Raw.(*secpEc.PrivateKey).Bytes(), nil
	default:
		return nil, fmt.Errorf("unsupported key type: %q", k.Type)
	}
}

func KeyFromMultibase(vm VerificationMethod) (*PubKey, error) {
	_, data, err := multibase.Decode(*vm.PublicKeyMultibase)
	if err != nil {
		return nil, err
	}

	pk := &PubKey{
		Type: vm.Type,
	}

	var raw []byte
	switch vm.Type {
	case KeyTypeEd25519, KeyTypeSecp256k1, KeyTypeP256:
		var (
			prefix uint64
			err    error
		)
		if prefix, raw, err = varDecode(data); err != nil {
			return nil, err
		}
		if varPrefixMap[vm.Type] != prefix {
			return nil, fmt.Errorf("invalid key multicodec prefix: %x", prefix)
		}
	default:
		return nil, fmt.Errorf("unrecognized key multicodec: %q", vm.Type)
	}

	// Convert from the binary encoding of the compressed point,
	// to the actual concrete public key type.
	switch vm.Type {
	case KeyTypeEd25519:
		// The stdlib does not expose a way to check if the public key
		// is actually valid, but we can at least check the length.
		if len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("invalid ed25519 public key")
		}

		pk.Raw = ed25519.PublicKey(raw)
	case KeyTypeSecp256k1:
		// secpEc.NewPublicKey accepts any valid encoding, while we
		// explicitly want compressed, so use the explicit point
		// decompression routine.
		p, err := secp.NewIdentityPoint().SetCompressedBytes(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid k256 public key: %w", err)
		}

		pub, err := secpEc.NewPublicKeyFromPoint(p)
		if err != nil {
			return nil, fmt.Errorf("invalid k256 public key: %w", err)
		}
		pk.Raw = pub
	case KeyTypeP256:
		x, y := elliptic.UnmarshalCompressed(elliptic.P256(), raw)
		if x == nil {
			return nil, fmt.Errorf("invalid p256 public key")
		}
		pk.Raw = &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     x,
			Y:     y,
		}
	}

	return pk, nil
}
