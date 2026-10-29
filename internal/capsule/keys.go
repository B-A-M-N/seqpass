package capsule

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"

	"github.com/tink-crypto/tink-go/v2/hybrid"
	hpkeutil "github.com/tink-crypto/tink-go/v2/hybrid/subtle"
	"github.com/tink-crypto/tink-go/v2/insecurecleartextkeyset"
	"github.com/tink-crypto/tink-go/v2/keyset"
)

var rawHPKETemplate = hybrid.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_CHACHA20_POLY1305_Raw_Key_Template()

// GenerateRecipientKeys creates an RFC 9180 X25519 keyset for use by a
// recipient-owned service. The private keyset is plaintext on disk and MUST
// be stored in a 0700 recipient-only directory under a separate service UID.
// The agent must not share that UID or be able to read this file.
func GenerateRecipientKeys(privatePath, publicPath string) ([]byte, error) {
	if privatePath == "" || publicPath == "" || privatePath == publicPath {
		return nil, ErrInvalid
	}
	priv, err := keyset.NewHandle(rawHPKETemplate)
	if err != nil {
		return nil, err
	}
	pub, err := priv.Public()
	if err != nil {
		return nil, err
	}
	pubBytes, err := hpkeutil.SerializePrimaryPublicKey(pub, rawHPKETemplate)
	if err != nil {
		return nil, err
	}
	var private bytes.Buffer
	if err := insecurecleartextkeyset.Write(priv, keyset.NewJSONWriter(&private)); err != nil {
		return nil, err
	}
	privateBytes := private.Bytes()
	defer zero(privateBytes)
	if err := writeKeyFile(privatePath, privateBytes, 0400); err != nil {
		return nil, err
	}
	if err := writeKeyFile(publicPath, pubBytes, 0644); err != nil {
		_ = os.Remove(privatePath)
		return nil, err
	}
	return append([]byte(nil), pubBytes...), nil
}

// LoadRecipientPrivate reads a recipient-owned Tink keyset after checking
// owner-only file permissions and that it is exactly the supported RFC 9180
// ciphersuite.
func LoadRecipientPrivate(path string) (*keyset.Handle, error) {
	if err := validatePrivateKeyFile(path); err != nil {
		return nil, err
	}
	f, err := openPrivateKeyFile(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	reader := keyset.NewJSONReader(f)
	h, err := insecurecleartextkeyset.Read(reader)
	if err != nil {
		return nil, fmt.Errorf("invalid recipient keyset")
	}
	pub, err := h.Public()
	if err != nil {
		return nil, fmt.Errorf("invalid recipient keyset")
	}
	if _, err := hpkeutil.SerializePrimaryPublicKey(pub, rawHPKETemplate); err != nil {
		return nil, fmt.Errorf("unsupported recipient keyset")
	}
	if _, err := hybrid.NewHybridDecrypt(h); err != nil {
		return nil, fmt.Errorf("unsupported recipient keyset")
	}
	return h, nil
}

// RecipientPublicHandle parses the registered raw X25519 public key with the
// one supported RFC 9180 ciphersuite.
func RecipientPublicHandle(pub []byte) (*keyset.Handle, error) {
	if len(pub) != 32 {
		return nil, ErrInvalid
	}
	return hpkeutil.KeysetHandleFromSerializedPublicKey(pub, rawHPKETemplate)
}

// GenerateIssuerKeys creates a separate Ed25519 signing identity. Its private
// seed must be provisioned only to the issuer service identity; it is never
// shared with the recipient or AegisKeys helper attestation.
func GenerateIssuerKeys(privatePath, publicPath string) (ed25519.PublicKey, error) {
	if privatePath == "" || publicPath == "" || privatePath == publicPath {
		return nil, ErrInvalid
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	seed := priv.Seed()
	defer zero(seed)
	defer zero(priv)
	if err := writeKeyFile(privatePath, seed, 0400); err != nil {
		return nil, err
	}
	if err := writeKeyFile(publicPath, pub, 0644); err != nil {
		return nil, err
	}
	return append(ed25519.PublicKey(nil), pub...), nil
}

// GenerateReceiptKeys creates a separate recipient receipt-signing identity.
// The private seed is recipient-owned and never reused as an HPKE key.
func GenerateReceiptKeys(privatePath, publicPath string) (ed25519.PublicKey, error) {
	if privatePath == "" || publicPath == "" || privatePath == publicPath {
		return nil, ErrInvalid
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	seed := priv.Seed()
	defer zero(seed)
	defer zero(priv)
	if err := writeKeyFile(privatePath, seed, 0400); err != nil {
		return nil, err
	}
	if err := writeKeyFile(publicPath, pub, 0644); err != nil {
		_ = os.Remove(privatePath)
		return nil, err
	}
	return append(ed25519.PublicKey(nil), pub...), nil
}

// LoadReceiptPrivate loads a recipient-only Ed25519 seed.
func LoadReceiptPrivate(path string) (ed25519.PrivateKey, error) {
	if err := validatePrivateKeyFile(path); err != nil {
		return nil, err
	}
	seed, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	defer zero(seed)
	if len(seed) != ed25519.SeedSize {
		return nil, ErrInvalid
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// LoadIssuerPrivate loads the 32-byte Ed25519 seed from a private file.
func LoadIssuerPrivate(path string) (ed25519.PrivateKey, error) {
	if err := validatePrivateKeyFile(path); err != nil {
		return nil, err
	}
	seed, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	defer zero(seed)
	if len(seed) != ed25519.SeedSize {
		return nil, ErrInvalid
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func writeKeyFile(path string, data []byte, mode os.FileMode) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("key path must be absolute")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	if err := validateKeyParent(filepath.Dir(path)); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		_ = f.Close()
		if !ok {
			_ = os.Remove(path)
		}
	}()
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Chmod(mode); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		return err
	}
	ok = true
	return nil
}
