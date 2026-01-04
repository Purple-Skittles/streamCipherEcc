// Package encryptor provides functions to load keys, generate key pairs, derive shared secrets, and encrypt messages
package encryptor

import (
	"crypto/rand"
	"embed"
	"errors"
	"fmt"
	"log/slog"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

func LoadKey(keyFiles embed.FS, filename string) ([32]byte, error) {
	var key [32]byte
	data, err := keyFiles.ReadFile(filename)

	if err != nil {
		slog.Error("failed to read key file", "filename", filename, "error", err)
		return key, fmt.Errorf("failed to read %s: %w", filename, err)
	}

	if len(data) != 32 {
		slog.Error("invalid key length", "filename", filename, "length", len(data))
		return key, errors.New("invalid key length, expected 32 bytes")
	}

	copy(key[:], data)
	return key, nil
}

func GenerateKeyPair() ([32]byte, [32]byte) {
	var priv [32]byte

	_, err := rand.Read(priv[:])
	if err != nil {
		slog.Error("error generating private key", "error", err)
	}

	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		slog.Error("error generating public key", "error", err)
		return [32]byte{}, [32]byte{}
	}

	var pubArray [32]byte
	copy(pubArray[:], pub)

	return priv, pubArray
}

func GetSharedSecret(privKey [32]byte, pubKey [32]byte) ([32]byte, error) {
	sharedSecret, err := curve25519.X25519(privKey[:], pubKey[:])
	if err != nil {
		slog.Error("error generating shared secret", "error", err)
		return [32]byte{}, err
	}

	var sharedSecretArray [32]byte
	copy(sharedSecretArray[:], sharedSecret)

	return sharedSecretArray, nil
}

func Encrypt(sharedSecret [32]byte, plaintext []byte) (ciphertext []byte, err error) {
	aead, err := chacha20poly1305.New(sharedSecret[:])
	if err != nil {
		slog.Error("error creating new aead cipher", "error", err)
		return nil, fmt.Errorf("error creating new aead cipher: %v", err)
	}

	nonce := make([]byte, aead.NonceSize()) // Use aead.NonceSize() instead of chacha20poly1305.NonceSize
	_, err = rand.Read(nonce)
	if err != nil {
		slog.Error("error generating nonce", "error", err)
		return nil, fmt.Errorf("error generating nonce: %v", err)
	}

	ciphertext = make([]byte, 0, len(nonce)+len(plaintext)+aead.Overhead())

	ciphertext = append(ciphertext, nonce...)

	ciphertext = aead.Seal(ciphertext, nonce, plaintext, nil)
	return ciphertext, nil
}
