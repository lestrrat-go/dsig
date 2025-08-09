package examples_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"

	"github.com/lestrrat-go/dsig"
)

func Example() {
	payload := []byte("hello world")

	// RSA signing and verification
	{
		privKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			fmt.Printf("failed to generate RSA key: %s\n", err)
			return
		}

		// Sign with RSA-PSS SHA256
		signature, err := dsig.Sign(privKey, dsig.RSAPSSWithSHA256, payload, nil)
		if err != nil {
			fmt.Printf("failed to sign with RSA: %s\n", err)
			return
		}

		// Verify with RSA-PSS SHA256
		err = dsig.Verify(&privKey.PublicKey, dsig.RSAPSSWithSHA256, payload, signature)
		if err != nil {
			fmt.Printf("failed to verify RSA signature: %s\n", err)
			return
		}
	}

	// ECDSA signing and verification
	{
		privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			fmt.Printf("failed to generate ECDSA key: %s\n", err)
			return
		}

		// Sign with ECDSA P-256 SHA256
		signature, err := dsig.Sign(privKey, dsig.ECDSAWithP256AndSHA256, payload, nil)
		if err != nil {
			fmt.Printf("failed to sign with ECDSA: %s\n", err)
			return
		}

		// Verify with ECDSA P-256 SHA256
		err = dsig.Verify(&privKey.PublicKey, dsig.ECDSAWithP256AndSHA256, payload, signature)
		if err != nil {
			fmt.Printf("failed to verify ECDSA signature: %s\n", err)
			return
		}
	}

	// EdDSA signing and verification
	{
		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			fmt.Printf("failed to generate Ed25519 key: %s\n", err)
			return
		}

		// Sign with EdDSA
		signature, err := dsig.Sign(privKey, dsig.EdDSA, payload, nil)
		if err != nil {
			fmt.Printf("failed to sign with EdDSA: %s\n", err)
			return
		}

		// Verify with EdDSA
		err = dsig.Verify(pubKey, dsig.EdDSA, payload, signature)
		if err != nil {
			fmt.Printf("failed to verify EdDSA signature: %s\n", err)
			return
		}
	}

	// HMAC signing and verification
	{
		key := []byte("secret-key")

		// Sign with HMAC SHA256
		signature, err := dsig.Sign(key, dsig.HMACWithSHA256, payload, nil)
		if err != nil {
			fmt.Printf("failed to sign with HMAC: %s\n", err)
			return
		}

		// Verify with HMAC SHA256
		err = dsig.Verify(key, dsig.HMACWithSHA256, payload, signature)
		if err != nil {
			fmt.Printf("failed to verify HMAC signature: %s\n", err)
			return
		}
	}
	// OUTPUT:
}