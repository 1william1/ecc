package ecc

import (
	"crypto/elliptic"
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/hkdf"
)

const (
	//VERSION uses semantic versioning
	VERSION = "v1.0.1"
)

func pad(input []byte, length int, char byte) []byte {
	if len(input) >= length {
		return input
	}

	for i := 0; i < length-len(input); i++ {
		input = append([]byte{char}, input...)
	}

	return input
}

//HKDFSHA256 generates a secure key from a secret using hkdf and sha256
func HKDFSHA256(secret []byte) (key []byte, err error) {
	key = make([]byte, 32)
	kdf := hkdf.New(sha256.New, secret, nil, nil)

	_, err = io.ReadFull(kdf, key)
	return key, err
}

func curveSize(curve elliptic.Curve) int {

	size := curve.Params().BitSize
	if size%8 > 0 {
		size = size + (8 - size%8)
	}

	return size / 8
}
