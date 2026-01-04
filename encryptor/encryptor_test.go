package encryptor

import (
	"bytes"
	"crypto/subtle"
	"embed"
	"testing"

	"github.com/Purple-Skittles/streamCipherEcc/testData"
	"github.com/stretchr/testify/assert"
)

var (
	serverPrivateKey = [32]byte{
		0x85, 0x3e, 0x0d, 0x8e, 0xba, 0x74, 0xf4, 0x4f,
		0x78, 0x08, 0x43, 0xbf, 0x3f, 0x1c, 0x7a, 0x67,
		0x9a, 0x6d, 0x0a, 0x3d, 0x1c, 0x63, 0xd8, 0xf9,
		0x2e, 0x18, 0xf3, 0xc9, 0x9a, 0x22, 0x9b, 0xa5,
	}

	serverPubKey = [32]byte{
		0x83, 0x3e, 0x0d, 0x8e, 0xba, 0x74, 0xf4, 0x4f,
		0x78, 0x08, 0x43, 0xbf, 0x3f, 0x1c, 0x7a, 0x67,
		0x9a, 0x6d, 0x0a, 0x3d, 0x1c, 0x63, 0xd8, 0xf9,
		0x2e, 0x18, 0xf3, 0xc9, 0x9a, 0x22, 0x9b, 0xa5,
	}

	expectedSharedSecret = [32]byte{
		0x91, 0x04, 0xe6, 0x07, 0xe5, 0x05, 0x89, 0x94,
		0x07, 0x8a, 0x4c, 0x35, 0x6c, 0x7b, 0x41, 0x4b,
		0x68, 0xb0, 0xa8, 0xf3, 0x2c, 0x03, 0x24, 0xf5,
		0x4d, 0xef, 0xd4, 0x23, 0xfb, 0x9f, 0xc4, 0x30,
	}

	clientPubKey = [32]byte{
		0xc9, 0x5c, 0x04, 0xfd, 0xd9, 0x79, 0x9f, 0x2b,
		0xc1, 0xea, 0x9a, 0x03, 0x80, 0x3d, 0xb0, 0xc4,
		0x1d, 0xbe, 0xf8, 0x30, 0x8a, 0x76, 0xa9, 0x6f,
		0x09, 0x0c, 0xe6, 0x6b, 0x6e, 0xb5, 0x21, 0x96,
	}
)

var testKeyFiles embed.FS

func TestLoadKey(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		filepath string
		wantErr  bool
		expected [32]byte
	}{
		{
			name:     "valid private key",
			filepath: "serverPrivate.key",
			wantErr:  false,
		},
		{
			name:     "valid public key",
			filepath: "serverPublic.key",
			wantErr:  false,
		},
		{
			name:     "missing key file",
			filepath: "missing.key",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := LoadKey(keys.TestKeyFiles, tt.filepath)

			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			expectedK, _ := keys.TestKeyFiles.ReadFile(tt.filepath)
			var expectedKey [32]byte
			copy(expectedKey[:], expectedK)

			if subtle.ConstantTimeCompare(key[:], expectedKey[:]) != 1 {
				t.Errorf("loaded key does not match expected key")
			}
		})
	}
}

func TestGenerateKeyPair(t *testing.T) {
	t.Parallel()
	priv, pub := GenerateKeyPair()
	assert.Len(t, priv, 32, "The expected key size is 32 bytes")
	assert.Len(t, pub, 32, "The expected key size is 32 bytes")
}

func TestGetSharedSecret(t *testing.T) {
	t.Parallel()
	secret, err := GetSharedSecret(serverPrivateKey, serverPubKey)
	if err != nil {
		t.Errorf("failed to get shared secret: %v", err)
	}
	if len(secret) != 32 {
		t.Errorf("unexpected shared secret size")
	}
	if !bytes.Equal(secret[:], expectedSharedSecret[:]) {
		t.Errorf("shared secret does not match expected value")
	}
}

func TestEncrypt(t *testing.T) {
	t.Parallel()
	priv, _ := GenerateKeyPair()
	sharedSecret, _ := GetSharedSecret(priv, serverPubKey)
	plaintext := []byte("example plaintext")
	ciphertext, err := Encrypt(sharedSecret, plaintext)
	if err != nil {
		t.Errorf("encryption failed: %v", err)
	}
	if len(ciphertext) == 0 {
		t.Errorf("encryption failed")
	}
}
