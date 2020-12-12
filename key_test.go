package ecc_test

import (
	"bytes"
	"crypto/elliptic"
	"crypto/sha512"
	"testing"

	"github.com/1william1/ecc"
)

func TestParsePublicKey(t *testing.T) {

	k1, err := ecc.GenerateKey(elliptic.P384())
	if err != nil {
		t.Fatal(err)
	}

	rawPub := k1.Public.Bytes()

	pub, err := ecc.ParsePublicKey(k1.Public.Curve, rawPub)
	if err != nil {
		t.Fatal(err)
	}

	if !k1.Public.Equal(pub) {
		t.Errorf("keys do not match")
	}

}

func TestFingerprintMatch(t *testing.T) {

	k1, err := ecc.GenerateKey(elliptic.P384())
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(k1.Public.Fingerprint(), k1.Public.Fingerprint()) {
		t.Errorf("public key fingerprints did not match on the same key")
	}

}

func TestFingerprintMatchCustomHash(t *testing.T) {

	k1, err := ecc.GenerateKey(elliptic.P384())
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(k1.Public.Fingerprint(sha512.New()), k1.Public.Fingerprint(sha512.New())) {
		t.Errorf("public key fingerprints did not match on the same key")
	}

}

func TestFingerprintDifferentKeys(t *testing.T) {

	k1, err := ecc.GenerateKey(elliptic.P384())
	if err != nil {
		t.Fatal(err)
	}

	k2, err := ecc.GenerateKey(elliptic.P384())
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(k1.Public.Fingerprint(), k2.Public.Fingerprint()) {
		t.Errorf("public key fingerprints matched to different keys")
	}
}

func TestEqualsNoMatch(t *testing.T) {

	k1, err := ecc.GenerateKey(elliptic.P384())
	if err != nil {
		t.Fatal(err)
	}

	k2, err := ecc.GenerateKey(elliptic.P384())
	if err != nil {
		t.Fatal(err)
	}

	if k1.Public.Equal(k2.Public) {
		t.Errorf("public key fingerprints matched to different keys")
	}
}
