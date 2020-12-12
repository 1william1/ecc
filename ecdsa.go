package ecc

import (
	"crypto/ecdsa"
	"math/big"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

//Sign will perform a ECDSA
func (private *Private) Sign(digest []byte) (r *big.Int, s *big.Int, err error) {
	return ecdsa.Sign(RandReader, private.ToECDSA(), digest)
}

//SignToASN1 will perform a ECDSA and encoded to using ASN1
func (private *Private) SignToASN1(digest []byte) ([]byte, error) {
	r, s, err := ecdsa.Sign(RandReader, private.ToECDSA(), digest)
	if err != nil {
		return nil, err
	}

	var b cryptobyte.Builder
	b.AddASN1(asn1.SEQUENCE, func(child *cryptobyte.Builder) {
		child.AddASN1BigInt(r)
		child.AddASN1BigInt(s)
	})

	return b.Bytes()
}

//Verify will verify the digest was signed from this key
func (public *Public) Verify(digest []byte, r *big.Int, s *big.Int) bool {
	return ecdsa.Verify(public.ToECDSA(), digest, r, s)
}

//VerifyASN1 will verify this ASN1 encoded signature was signed from this key
//
//Digest is the output hash from the input of the signature
func (public *Public) VerifyASN1(digest []byte, signature []byte) bool {
	return ecdsa.VerifyASN1(public.ToECDSA(), digest, signature)
}

//ToECDSA will convert the private key into a ECDSA compatable private key
func (private *Private) ToECDSA() *ecdsa.PrivateKey {
	return &ecdsa.PrivateKey{
		D:         private.D,
		PublicKey: *private.Public.ToECDSA(),
	}
}

//ToECDSA will convert the public key into a ECDSA compatable public key
func (public *Public) ToECDSA() *ecdsa.PublicKey {
	return &ecdsa.PublicKey{
		Curve: public.Curve,
		X:     public.X,
		Y:     public.Y,
	}
}
