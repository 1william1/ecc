package main

import (
	"bytes"
	"crypto/elliptic"
	"fmt"
	"log"

	"github.com/william1/ecc"
)

func main() {
	k1, err := ecc.GenerateKey(elliptic.P256())
	if err != nil {
		log.Fatalln(err)
	}

	msg := "Test must have worked"
	c, err := k1.Public.Encrypt([]byte(msg))
	if err != nil {
		log.Fatalln(err)
	}

	m, err := k1.Decrypt(c, k1.Public.Curve)
	if err != nil {
		log.Fatalln(err)
	}

	if !bytes.Equal([]byte(msg), m) {
		log.Fatalln("messages do not match")
	}

	fmt.Printf("Cipher text: %x\n", c)
	fmt.Printf("Plain text: %s\n", string(m))
}
