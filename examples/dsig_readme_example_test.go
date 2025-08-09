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
		signature, err := dsig.Sign(privKey, "PS256", payload, nil)
		if err != nil {
			fmt.Printf("failed to sign with RSA: %s\n", err)
			return
		}

		// Verify with RSA-PSS SHA256
		err = dsig.Verify(&privKey.PublicKey, "PS256", payload, signature)
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
		signature, err := dsig.Sign(privKey, "ES256", payload, nil)
		if err != nil {
			fmt.Printf("failed to sign with ECDSA: %s\n", err)
			return
		}

		// Verify with ECDSA P-256 SHA256
		err = dsig.Verify(&privKey.PublicKey, "ES256", payload, signature)
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
		signature, err := dsig.Sign(privKey, "EdDSA", payload, nil)
		if err != nil {
			fmt.Printf("failed to sign with EdDSA: %s\n", err)
			return
		}

		// Verify with EdDSA
		err = dsig.Verify(pubKey, "EdDSA", payload, signature)
		if err != nil {
			fmt.Printf("failed to verify EdDSA signature: %s\n", err)
			return
		}
	}

	// HMAC signing and verification
	{
		key := []byte("secret-key")

		// Sign with HMAC SHA256
		signature, err := dsig.Sign(key, "HS256", payload, nil)
		if err != nil {
			fmt.Printf("failed to sign with HMAC: %s\n", err)
			return
		}

		// Verify with HMAC SHA256
		err = dsig.Verify(key, "HS256", payload, signature)
		if err != nil {
			fmt.Printf("failed to verify HMAC signature: %s\n", err)
			return
		}
	}

	// Using generic interfaces
	{
		privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			fmt.Printf("failed to generate ECDSA key: %s\n", err)
			return
		}

		// Create a signer instance
		signer := dsig.NewECDSASigner()

		// Sign using the generic interface
		signature, err := signer.Sign(privKey, payload)
		if err != nil {
			fmt.Printf("failed to sign with generic signer: %s\n", err)
			return
		}

		// Create a verifier instance
		verifier := dsig.NewECDSAVerifier()

		// Verify using the generic interface
		err = verifier.Verify(&privKey.PublicKey, payload, signature)
		if err != nil {
			fmt.Printf("failed to verify with generic verifier: %s\n", err)
			return
		}
	}
	// OUTPUT:
}