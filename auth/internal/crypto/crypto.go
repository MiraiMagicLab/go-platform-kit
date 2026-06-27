package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
)

// StringCipher encrypts and decrypts UTF-8 strings using AES-256-GCM.
// The nonce is prepended to the ciphertext and the result is base64-encoded.
type StringCipher struct {
	key []byte
}

// NewStringCipher creates a StringCipher with a 32-byte AES-256 key.
// It returns an error if the key is not exactly 32 bytes.
func NewStringCipher(key []byte) (*StringCipher, error) {
	if len(key) != 32 {
		return nil, errors.New("data encryption key must be 32 bytes")
	}
	return &StringCipher{key: key}, nil
}

// Encrypt encrypts the plaintext string using AES-256-GCM with a random nonce.
// The returned string is base64-encoded and contains the nonce prepended to the ciphertext.
func (c *StringCipher) Encrypt(plain string) (string, error) {
	block, err := aes.NewCipher(c.key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, []byte(plain), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts a base64-encoded AES-256-GCM ciphertext produced by Encrypt.
func (c *StringCipher) Decrypt(encrypted string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(c.key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	n := gcm.NonceSize()
	if len(raw) < n {
		return "", errors.New("invalid ciphertext")
	}
	nonce := raw[:n]
	ct := raw[n:]
	pt, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", err
	}
	return string(pt), nil
}
