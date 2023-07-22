package cache

import (
	"crypto/ecdh"
	"fmt"

	"diffie-hellman-key-exchange/pkg/key"
)

type Cache struct {
	MasterKey *ecdh.PrivateKey
	Secret    map[string][]byte
	IV        map[string][]byte
}

func New() (*Cache, error) {
	mk, err := key.GenerateECDH()
	if err != nil {
		return nil, fmt.Errorf("key.Generate: %w", err)
	}

	return &Cache{
		MasterKey: mk,
		Secret:    make(map[string][]byte),
		IV:        make(map[string][]byte),
	}, nil
}

func (cc *Cache) SetSecret(
	id string,
	secret []byte,
) {
	cc.Secret[id] = secret
}

func (cc *Cache) GetSecret(
	id string,
) []byte {
	return cc.Secret[id]
}

func (cc *Cache) DeleteSecret(
	id string,
) {
	delete(cc.Secret, id)
}

func (cc *Cache) SetIV(
	id string,
	iv []byte,
) {
	cc.IV[id] = iv
}

func (cc *Cache) GetIV(
	id string,
) []byte {
	return cc.IV[id]
}

func (cc *Cache) DeleteIV(
	id string,
) {
	delete(cc.IV, id)
}
