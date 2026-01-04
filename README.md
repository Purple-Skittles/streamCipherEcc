# streamCipherEcc

Fast, reliable ECC encryption using X25519 key exchange and ChaCha20-Poly1305 authenticated stream cipher.

## Overview

These packages provide a simple interface for:
- Generating Curve25519 key pairs
- Performing X25519 key exchange to derive shared secrets
- Encrypting/decrypting data using ChaCha20-Poly1305 AEAD
- Loading keys from embedded filesystems

## Installation

```bash
go get github.com/Purple-Skittles/streamCipherEcc/encryptor
go get github.com/Purple-Skittles/streamCipherEcc/decryptor
```

## Usage

### Basic Encryption/Decryption Flow

```go
package main

import (
    "fmt"
    "log"
	  "github.com/Purple-Skittles/streamCipherEcc/encryptor"
	  "github.com/Purple-Skittles/streamCipherEcc/decryptor"
)

func main() {
    // Alice generates her key pair
    alicePriv, alicePub := encryptor.GenerateKeyPair()
    
    // Bob generates his key pair
    bobPriv, bobPub := decryptor.GenerateKeyPair()
    
    // Alice computes shared secret using her private key and Bob's public key
    aliceShared, err := encryptor.GetSharedSecret(alicePriv, bobPub)
    if err != nil {
        log.Fatal(err)
    }
    
    // Bob computes the same shared secret using his private key and Alice's public key
    bobShared, err := decryptor.GetSharedSecret(bobPriv, alicePub)
    if err != nil {
        log.Fatal(err)
    }
    
    // Encrypt a message
    plaintext := []byte("Hello, Bob!")
    ciphertext := encryptor.Encrypt(aliceShared, plaintext)
    
    // Decrypt the message
    decrypted, err := decryptor.Decrypt(bobShared, ciphertext)
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Printf("Decrypted: %s\n", decrypted)
}
```

### Loading Keys from Embedded Files

```go
package main

import (
    "embed"
    "log"
	  "github.com/Purple-Skittles/streamCipherEcc/encryptor"
)

//go:embed keys/*
var keyFiles embed.FS

func main() {
    privateKey, err := encryptor.LoadKey(keyFiles, "keys/private.key")
    if err != nil {
        log.Fatal(err)
    }
    
    publicKey, err := encryptor.LoadKey(keyFiles, "keys/public.key")
    if err != nil {
        log.Fatal(err)
    }
    
    // Use keys...
}
```

## API Reference

### Encryptor Package

#### `GenerateKeyPair() ([32]byte, [32]byte)`
Generates a new Curve25519 key pair. Returns `(privateKey, publicKey)`.

#### `GetSharedSecret(privKey [32]byte, pubKey [32]byte) ([32]byte, error)`
Performs X25519 key exchange to derive a shared secret from your private key and the other party's public key.

#### `Encrypt(sharedSecret [32]byte, plaintext []byte) []byte`
Encrypts plaintext using ChaCha20-Poly1305 AEAD. The returned ciphertext includes the nonce prepended.

#### `LoadKey(keyFiles embed.FS, filename string) ([32]byte, error)`
Loads a 32-byte key from an embedded filesystem. Returns an error if the file is not exactly 32 bytes.

### Decryptor Package

#### `GenerateKeyPair() ([32]byte, [32]byte)`
Generates a new Curve25519 key pair. Returns `(privateKey, publicKey)`.

#### `GetSharedSecret(privKey [32]byte, pubKey [32]byte) ([32]byte, error)`
Performs X25519 key exchange to derive a shared secret from your private key and the other party's public key.

#### `Decrypt(sharedSecret [32]byte, ciphertext []byte) ([]byte, error)`
Decrypts ciphertext using ChaCha20-Poly1305 AEAD. Expects the nonce to be prepended to the ciphertext.

#### `LoadKey(keyFiles embed.FS, filename string) ([32]byte, error)`
Loads a 32-byte key from an embedded filesystem. Returns an error if the file is not exactly 32 bytes.

## Security Considerations

- **Key Management**: Store private keys securely. Never commit them to version control.
- **Nonce Uniqueness**: Each encryption generates a random nonce. Never reuse a shared secret with the same nonce.
- **Authentication**: ChaCha20-Poly1305 provides authenticated encryption, protecting against tampering.

## Dependencies

```
golang.org/x/crypto/chacha20poly1305
golang.org/x/crypto/curve25519
```

## License

MIT License - See LICENSE file for details.

## Contributing

Contributions welcome! Please open an issue or submit a pull request.
