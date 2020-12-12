package ecc

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"hash"
	"io"
	"math/big"
)

var (

	//RandReader is a cryptographic random number generator default is crypto/rand
	RandReader io.Reader = rand.Reader

	//ErrTooShort is returned when the input is shorter than a real possible ciphertext
	ErrTooShort = errors.New("ecc/ecies: invalid ciphertext, too short")

	//ErrWrongKeyLength is returned when parsing a public or private key when the input length does not match the expected length based on the curve
	ErrWrongKeyLength = errors.New("ecc/key: could not parse key, wrong length")
)

//Private represents a elliptic curve private key
type Private struct {
	//D is the private part of the elliptic curve and acts as the key
	D *big.Int

	Public *Public
}

//Public is a public elliptic curve key
type Public struct {
	Curve elliptic.Curve
	X     *big.Int
	Y     *big.Int
}

//Bytes returns the public key in raw bytes
//
// Bytes() acts similarly to elliptic.Marshal()
//
// byte{4} | x | y
// x and y are equal in length and can be split in half to extract each
// cordinate when popping index 0.
func (public *Public) Bytes() []byte {

	keySize := curveSize(public.Curve)

	x := public.X.Bytes()
	if len(x) < keySize {
		x = append(make([]byte, keySize-len(x)), x...)
	}

	y := public.Y.Bytes()
	if len(y) < keySize {
		y = append(make([]byte, keySize-len(y)), y...)
	}

	return bytes.Join([][]byte{{4}, x, y}, nil)
}

//GenerateKey generates a new elliptic curve key pair
func GenerateKey(curve elliptic.Curve) (*Private, error) {
	priv, x, y, err := elliptic.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, err
	}

	private := &Private{
		D: new(big.Int).SetBytes(priv),
		Public: &Public{
			Curve: curve,
			X:     x,
			Y:     y,
		},
	}

	return private, nil
}

//ParsePublicKey takes in a array of bytes containing the public key
//
//This implements a parser for the public.Bytes() method's format
func ParsePublicKey(curve elliptic.Curve, rawBytes []byte) (*Public, error) {

	curveLen := curveSize(curve)

	if len(rawBytes) != (curveLen*2)+1 {
		return nil, ErrWrongKeyLength
	}

	return &Public{
		Curve: curve,
		X:     new(big.Int).SetBytes(rawBytes[1 : curveLen+1]),
		Y:     new(big.Int).SetBytes(rawBytes[curveLen+1:]),
	}, nil
}

//Equal securely comparses two public keys in constant time
//to minigate timing attacks.
func (public *Public) Equal(key *Public) bool {
	if subtle.ConstantTimeCompare(public.Bytes(), key.Bytes()) == 1 {
		return true
	}

	return false
}

//Fingerprint returns a hash digest of X | Y
//
//Custom hash algorithm example:
//
//public.Fingerprint(sha256.New())
func (public *Public) Fingerprint(Hash ...hash.Hash) []byte {

	var hasher hash.Hash
	if len(Hash) > 0 {
		hasher = Hash[0]
	} else {
		hasher = sha256.New()
	}

	hasher.Write(public.Bytes())
	return hasher.Sum(nil)
}
