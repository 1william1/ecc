package ecc_test

import (
	"bytes"
	"crypto/elliptic"
	"crypto/sha256"
	"errors"
	"runtime"
	"sync"
	"testing"

	"github.com/william1/ecc"

	"github.com/fomichev/secp256k1"
)

func TestP256Encrypt(t *testing.T) {

	testCurve := func(wg *sync.WaitGroup) {
		for i := 1; i <= 5000/runtime.NumCPU(); i++ {
			k1, err := ecc.GenerateKey(elliptic.P256())
			if err != nil {
				t.Fatal(err)
			}

			msg := "Test must have worked1"
			c, err := k1.Public.Encrypt([]byte(msg))
			if err != nil {
				t.Fatal(err)
			}

			m, err := k1.Decrypt(c, k1.Public.Curve)
			if err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal([]byte(msg), m) {
				t.Errorf("messages do not match")
			}
		}

		wg.Done()
	}

	var wg sync.WaitGroup
	for i := 1; i < runtime.NumCPU(); i++ {
		wg.Add(1)
		go testCurve(&wg)
	}

	wg.Wait()
}

func TestP521Encrypt(t *testing.T) {

	testCurve := func(wg *sync.WaitGroup) {
		for i := 1; i <= 1000/runtime.NumCPU(); i++ {
			k1, err := ecc.GenerateKey(elliptic.P521())
			if err != nil {
				t.Fatal(err)
			}

			msg := "Test must have worked1"
			c, err := k1.Public.Encrypt([]byte(msg))
			if err != nil {
				t.Fatal(err)
			}

			m, err := k1.Decrypt(c, k1.Public.Curve)
			if err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal([]byte(msg), m) {
				t.Errorf("messages do not match")
			}
		}

		wg.Done()
	}

	var wg sync.WaitGroup
	for i := 1; i < runtime.NumCPU(); i++ {
		wg.Add(1)
		go testCurve(&wg)
	}

	wg.Wait()

}

func TestP384Encrypt(t *testing.T) {

	testCurve := func(wg *sync.WaitGroup) {
		for i := 1; i <= 2000/runtime.NumCPU(); i++ {
			k1, err := ecc.GenerateKey(elliptic.P384())
			if err != nil {
				t.Fatal(err)
			}

			msg := "Test must have worked1"
			c, err := k1.Public.Encrypt([]byte(msg))
			if err != nil {
				t.Fatal(err)
			}

			m, err := k1.Decrypt(c, k1.Public.Curve)
			if err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal([]byte(msg), m) {
				t.Errorf("messages do not match")
			}
		}

		wg.Done()
	}

	var wg sync.WaitGroup
	for i := 1; i < runtime.NumCPU(); i++ {
		wg.Add(1)
		go testCurve(&wg)
	}

	wg.Wait()

}

func TestP224Encrypt(t *testing.T) {

	testCurve := func(wg *sync.WaitGroup) {
		for i := 1; i <= 5000/runtime.NumCPU(); i++ {
			k1, err := ecc.GenerateKey(elliptic.P224())
			if err != nil {
				t.Fatal(err)
			}

			msg := "Test must have worked1"
			c, err := k1.Public.Encrypt([]byte(msg))
			if err != nil {
				t.Fatal(err)
			}

			m, err := k1.Decrypt(c, k1.Public.Curve)
			if err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal([]byte(msg), m) {
				t.Errorf("messages do not match")
			}
		}

		wg.Done()
	}

	var wg sync.WaitGroup
	for i := 1; i < runtime.NumCPU(); i++ {
		wg.Add(1)
		go testCurve(&wg)
	}

	wg.Wait()
}

func TestP256k1Encrypt(t *testing.T) {

	testCurve := func(wg *sync.WaitGroup) {
		for i := 1; i <= 5000/runtime.NumCPU(); i++ {
			k1, err := ecc.GenerateKey(secp256k1.SECP256K1())
			if err != nil {
				t.Fatal(err)
			}

			msg := "Test must have worked1"
			c, err := k1.Public.Encrypt([]byte(msg))
			if err != nil {
				t.Fatal(err)
			}

			m, err := k1.Decrypt(c, k1.Public.Curve)
			if err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal([]byte(msg), m) {
				t.Errorf("messages do not match")
			}
		}

		wg.Done()
	}

	var wg sync.WaitGroup
	for i := 1; i < runtime.NumCPU(); i++ {
		wg.Add(1)
		go testCurve(&wg)
	}

	wg.Wait()

}

func TestEncryptCustomKDF(t *testing.T) {
	k1, err := ecc.GenerateKey(elliptic.P256())
	if err != nil {
		t.Fatal(err)
	}

	kdf := ecc.NewOptionKDF(func(secret []byte) ([]byte, error) {
		hash := sha256.New()
		hash.Write(secret)

		return hash.Sum(nil), nil
	})

	msg := "Test must have worked1"
	c, err := k1.Public.Encrypt([]byte(msg), kdf)
	if err != nil {
		t.Fatal(err)
	}

	m, err := k1.Decrypt(c, k1.Public.Curve, kdf)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal([]byte(msg), m) {
		t.Errorf("messages do not match")
	}
}

func TestEncryptCustomKDFFail(t *testing.T) {
	k1, err := ecc.GenerateKey(elliptic.P256())
	if err != nil {
		t.Fatal(err)
	}

	kdf := ecc.NewOptionKDF(func(secret []byte) ([]byte, error) {
		hash := sha256.New()
		hash.Write(secret)

		return hash.Sum(nil), nil
	})

	msg := "Test must have worked1"
	c, err := k1.Public.Encrypt([]byte(msg), kdf)
	if err != nil {
		t.Fatal(err)
	}

	_, err = k1.Decrypt(c, k1.Public.Curve)
	if err != nil {
		t.SkipNow()
	}

	t.Fatal(errors.New("different kdf used but no error returned"))

}
