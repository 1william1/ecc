# Elliptic Curve Cryptography

ECC is a Golang package which provides a uniform API for using Elliptic curves with one single key pair, instead of having to use specific libraries with different key structs e.g. ECDSA's key. Supporting any elliptic.curve with easy capabilities to switch it out. Even P521 is supported! I won't even comment on the struggles of that one. 

### Features
- ECDSA (Elliptic curve digital signature algorithm)
- ECIES (Elliptic curve integrated encryption scheme)
- Mutlicurve support (unlike many other libs we support any elliptic.Curve)
- Single EC key rather than separate per curve or lib

### Todo
- Implement more curves
    - Curve25519
    - K-233
    - M-383 

# Examples

Encrypt using AES256 GCM HKDF-SHA256 to a public key then decrypt it using the private key:

```go
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
```