package vault

import (
	"golang.org/x/crypto/argon2"
)

type keyGenerator interface {
	Name() string
	GenerateKey(secret, salt []byte, timeCost, memoryCost uint32, threads uint8, len uint32) []byte
}

type argon2id string

func (argon2id) Name() string {
	return KDFAlgorithmArgon2id
}

func (argon2id) GenerateKey(secret, salt []byte, timeCost, memoryCost uint32, threads uint8, len uint32) []byte {
	return argon2.IDKey(secret, salt, timeCost, memoryCost, threads, len)
}

// TODO: implement argon2d
// type argon2d struct {}

// func (a2d argon2d) GenerateKey(secret, salt []byte, timeCost, memoryCost uint32, threads uint8, len uint32) []byte {
// 	return []byte{}
// }

func NewKeyGenerator(alg string) keyGenerator {
	// TODO: implement factory validations
	return argon2id(alg)
}
