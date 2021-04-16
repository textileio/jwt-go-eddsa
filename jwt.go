package eddsa

import (
	"crypto/sha256"

	"github.com/dgrijalva/jwt-go"
	"github.com/libp2p/go-libp2p-core/crypto"
)

// SigningMethodEd25519 implements the Ed25519 signing method.
// Expects *crypto.Ed25519PublicKey for signing and *crypto.Ed25519PublicKey
// for validation.
// The signing method can be optionally configured to sign and validate the
// sha256 hash of the input string.
type SigningMethodEd25519 struct {
	Name string
	Hash bool
}

// SigningMethodEd25519i is a specific instance for Ed25519.
var SigningMethodEd25519i *SigningMethodEd25519

// SigningMethodEd25519Sha is a non-standard, specific instance for Ed25519
// with sha256 hashing enabled.
var SigningMethodEd25519Sha256 *SigningMethodEd25519

func init() {
	SigningMethodEd25519i = &SigningMethodEd25519{"EdDSA", false}
	jwt.RegisterSigningMethod(SigningMethodEd25519i.Alg(), func() jwt.SigningMethod {
		return SigningMethodEd25519i
	})
	// Register non-standard method
	SigningMethodEd25519Sha256 = &SigningMethodEd25519{"EdDSASha256", true}
	jwt.RegisterSigningMethod(SigningMethodEd25519Sha256.Alg(), func() jwt.SigningMethod {
		return SigningMethodEd25519Sha256
	})
}

// Alg returns the name of this signing method.
func (m *SigningMethodEd25519) Alg() string {
	return m.Name
}

// Verify implements the Verify method from SigningMethod.
// For this signing method, must be a *crypto.Ed25519PublicKey structure.
func (m *SigningMethodEd25519) Verify(signingString, signature string, key interface{}) error {
	var err error

	// Decode the signature
	var sig []byte
	if sig, err = jwt.DecodeSegment(signature); err != nil {
		return err
	}

	var ed25519Key *crypto.Ed25519PublicKey
	var ok bool

	if ed25519Key, ok = key.(*crypto.Ed25519PublicKey); !ok {
		return jwt.ErrInvalidKeyType
	}

	if m.Hash {
		h := sha256.New()
		_, err := h.Write([]byte(signingString))
		if err != nil {
			return err
		}
		signingString = string(h.Sum(nil))
	}

	// verify the signature
	valid, err := ed25519Key.Verify([]byte(signingString), sig)
	if err != nil {
		return err
	}
	if !valid {
		return jwt.ErrSignatureInvalid
	}

	return nil
}

// Sign implements the Sign method from SigningMethod.
// For this signing method, must be a *crypto.Ed25519PublicKey structure.
func (m *SigningMethodEd25519) Sign(signingString string, key interface{}) (string, error) {
	var ed25519Key *crypto.Ed25519PrivateKey
	var ok bool

	// validate type of key
	if ed25519Key, ok = key.(*crypto.Ed25519PrivateKey); !ok {
		return "", jwt.ErrInvalidKey
	}

	if m.Hash {
		h := sha256.New()
		_, err := h.Write([]byte(signingString))
		if err != nil {
			return "", err
		}
		signingString = string(h.Sum(nil))
	}

	sigBytes, err := ed25519Key.Sign([]byte(signingString))
	if err != nil {
		return "", err
	}
	return jwt.EncodeSegment(sigBytes), nil
}
