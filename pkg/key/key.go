package key

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

func GenerateECDH() (*ecdh.PrivateKey, error) {
	return ecdh.X25519().GenerateKey(rand.Reader)
}

func GenerateIV() ([]byte, error) {
	iv := make([]byte, aes.BlockSize)

	if _, err := rand.Read(iv); err != nil {
		return nil, fmt.Errorf("rand.Read: %w", err)
	}

	return iv, nil
}

func DecodeECDHPublic(
	key []byte,
) (*ecdh.PublicKey, error) {
	block, _ := pem.Decode(key)
	if block == nil {
		return nil, fmt.Errorf("pem.Decode: block is nil")
	}
	if block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("pem.Decode: block.Type is not PUBLIC KEY")
	}

	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("x509.ParsePKIXPublicKey: %w", err)
	}

	pub, ok := parsed.(*ecdh.PublicKey)
	if !ok {
		return nil, fmt.Errorf("x509.ParsePKIXPublicKey: parsed is not *ecdh.PublicKey")
	}

	return pub, nil
}

func EncodeECDHPublic(
	key *ecdh.PublicKey,
) ([]byte, error) {
	encoded, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, fmt.Errorf("x509.MarshalPKIXPublicKey: %w", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: encoded}), nil
}

func Encrypt(
	plain []byte,
	key []byte,
	iv []byte,
) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes.NewCipher: %w", err)
	}

	padded := pad(plain)

	encrypted := make([]byte, len(padded))

	ce := cipher.NewCBCEncrypter(c, iv)

	ce.CryptBlocks(encrypted, padded)

	return encrypted, nil
}

func Decrypt(
	encrypted []byte,
	key []byte,
	iv []byte,
) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes.NewCipher: %w", err)
	}

	decrypted := make([]byte, aes.BlockSize)

	cd := cipher.NewCBCDecrypter(c, iv)

	cd.CryptBlocks(decrypted, encrypted)

	return unpad(decrypted), nil
}

func pad(data []byte) []byte {
	length := aes.BlockSize - (len(data) % aes.BlockSize)
	trailing := bytes.Repeat([]byte{byte(length)}, length)
	return append(data, trailing...)
}

func unpad(data []byte) []byte {
	length := len(data)
	pad := int(data[length-1])
	return data[:length-pad]
}
