package main

import (
	"crypto"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/user"

	"github.com/aead/ecdh"
)

func main() {
	c25519 := ecdh.X25519()
	// var p crypto.PublicKey
	var s crypto.PrivateKey
	po := os.Args[1:]
	usr, err := user.Current()
	if err != nil {
		log.Fatal(err)
	}

	f := usr.HomeDir + "/xchange-sekret"
	s, err = ioutil.ReadFile(f)
	if err != nil {
		// log.Fatal(err)

		s, p, err := c25519.GenerateKey(rand.Reader)
		if err != nil {
			log.Fatal(err)
		}
		ss := s.([32]byte)
		err = ioutil.WriteFile(f, ss[:], 0644)
		if err != nil {
			log.Fatal(err)
		}
		pp := p.([32]byte)
		fmt.Println("Saving sekret key, public key is", hex.EncodeToString(pp[:]))
	} else {
		p := c25519.PublicKey(s)
		pp := p.([32]byte)
		fmt.Println("Sekret key found, public key is", hex.EncodeToString(pp[:]))

	}
	if len(po) > 0 {
		ps, err := hex.DecodeString(po[0])
		if err != nil {
			log.Fatal(err)
		}
		sh := c25519.ComputeSecret(s, ps)
		fmt.Println("shared sekret is", hex.EncodeToString(sh), "use this as your password")
	}
}
