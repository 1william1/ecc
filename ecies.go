package ecc

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"
	"errors"
	"math/big"
)

const (
	//OperationModeGCM will set the cipher operation mode to GCM
	OperationModeGCM OperationMode = 0
	//OperationModeCBC will set the cipher operation mode to CBC
	OperationModeCBC OperationMode = 1

	//PropertyOperationMode sets the cipher operation mode
	PropertyOperationMode OptionProperty = 1
	//PropertyKDF allows you to set a custom KDF
	PropertyKDF OptionProperty = 2
)

var (
	//OptionAESGCM will set the operation mode as GCM
	OptionAESGCM EncryptOption = EncryptOption{1, OperationModeGCM}

	//ErrUnknownOption is returned when a unknown EncryptionOption is provided
	ErrUnknownOption = errors.New("ecc/ecies: unknown encryption option")
	//ErrUnexpectedOptionDataType is returned when a unexpected datatype is used for the EncryptionOption.Value
	ErrUnexpectedOptionDataType = errors.New("ecc/ecies: unexpected option value data type")
)

//OperationMode sets which operation mode to use
type OperationMode uint8

//OptionProperty is used as the "property" in a EncryptionOption
type OptionProperty uint8

//EncryptOption allows you set set options such as the KDF and cipher
type EncryptOption struct {
	Property OptionProperty
	Value    interface{}
}

type eciesOptions struct {
	KDF func(secret []byte) ([]byte, error)
}

//Encrypt uses ECIES to encrypt a message to the given public key
//
// AES256 (depending on the KDF) GCM
func (public *Public) Encrypt(message []byte, options ...*EncryptOption) ([]byte, error) {

	config, err := parseEncryptionOptions(options)
	if err != nil {
		return nil, err
	}

	//Generate a ephemeral key
	ePriv, err := GenerateKey(public.Curve)
	if err != nil {
		return nil, err
	}

	//Generate a shared secret
	var key bytes.Buffer
	key.Write(ePriv.Public.Bytes())
	sx, sy := public.Curve.ScalarMult(public.X, public.Y, ePriv.D.Bytes())

	key.WriteByte(4)
	length := curveSize(public.Curve)

	key.Write(pad(sx.Bytes(), length, 0))
	key.Write(pad(sy.Bytes(), length, 0))

	//Secret is a key which both the sender and receiver know
	secret, err := config.KDF(key.Bytes())
	if err != nil {
		return nil, err
	}

	//secret with the default KDF is a 256bit key resulting in AES256
	aesCipher, err := aes.NewCipher(secret)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, 16)
	if _, err := RandReader.Read(nonce); err != nil {
		return nil, err
	}

	var output bytes.Buffer
	output.Write(ePriv.Public.Bytes())
	output.Write(nonce)

	gcm, err := cipher.NewGCMWithNonceSize(aesCipher, 16)
	if err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nil, nonce, message, nil)

	tag := ciphertext[len(ciphertext)-gcm.NonceSize():]
	output.Write(tag)

	output.Write(ciphertext[:len(ciphertext)-len(tag)])

	return output.Bytes(), nil
}

//Decrypt will decrypt a ECIES message
func (private *Private) Decrypt(m []byte, curve elliptic.Curve, options ...*EncryptOption) ([]byte, error) {

	keySize := curveSize(curve.Params())

	//Checks if the ciphertext is long enough to contain the information needed
	if len(m) <= 32+(keySize*2) {
		return nil, ErrTooShort
	}

	config, err := parseEncryptionOptions(options)
	if err != nil {
		return nil, err
	}

	//Get the public key of the sender from the ciphertext
	sender := &Public{
		Curve: curve,
		X:     new(big.Int).SetBytes(m[1 : keySize+1]),
		Y:     new(big.Int).SetBytes(m[keySize+1 : (keySize*2)+1]),
	}

	m = m[(keySize*2)+1:]

	//Calculate the shared secret
	var key bytes.Buffer
	key.Write(sender.Bytes())

	sx, sy := private.Public.Curve.ScalarMult(sender.X, sender.Y, private.D.Bytes())

	key.WriteByte(4)

	// length := curveSize(curve.Params())
	key.Write(pad(sx.Bytes(), keySize, 0))
	key.Write(pad(sy.Bytes(), keySize, 0))

	//Secret is a key which both the sender and receiver know
	secret, err := config.KDF(key.Bytes())
	if err != nil {
		return nil, err
	}

	nonce := m[:16]
	tag := m[16:32]

	ciphertext := bytes.Join([][]byte{m[32:], tag}, nil)

	aescipher, err := aes.NewCipher(secret)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCMWithNonceSize(aescipher, 16)
	if err != nil {
		return nil, err
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)

	return plaintext, err
}

//NewOptionKDF allows you so set a custom KDF when encrypting and decryting
func NewOptionKDF(kdf func(secret []byte) ([]byte, error)) *EncryptOption {
	return &EncryptOption{
		Property: PropertyKDF,
		Value:    kdf,
	}
}

func parseEncryptionOptions(options []*EncryptOption) (*eciesOptions, error) {

	//Set defaults
	config := eciesOptions{
		KDF: HKDFSHA256,
	}

	for _, option := range options {
		switch option.Property {
		case PropertyKDF:
			kdf, ok := option.Value.(func(secret []byte) ([]byte, error))
			if ok == false {
				return nil, ErrUnexpectedOptionDataType
			}

			config.KDF = kdf

			break
		default:
			return nil, ErrUnknownOption
		}
	}

	return &config, nil
}
