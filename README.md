# github.com/lestrrat-go/dsig [![CI](https://github.com/lestrrat-go/dsig/actions/workflows/ci.yml/badge.svg)](https://github.com/lestrrat-go/dsig/actions/workflows/ci.yml) [![Go Reference](https://pkg.go.dev/badge/github.com/lestrrat-go/dsig.svg)](https://pkg.go.dev/github.com/lestrrat-go/dsig) [![codecov.io](https://codecov.io/github/lestrrat-go/dsig/coverage.svg?branch=main)](https://codecov.io/github/lestrrat-go/dsig?branch=main)

Go module providing low-level digital signature operations.

# Features

* RSA signatures (PKCS1v15 and PSS)
* ECDSA signatures (P-256, P-384, P-521)
* EdDSA signatures (Ed25519, Ed448)
* HMAC signatures (SHA-256, SHA-384, SHA-512)
* Generic Signer/Verifier interfaces
* Support for crypto.Signer interface

# SYNOPSIS

<!-- INCLUDE(examples/dsig_readme_example_test.go) -->
```go
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
```
source: [examples/dsig_readme_example_test.go](https://github.com/lestrrat-go/dsig/blob/main/examples/dsig_readme_example_test.go)
<!-- END INCLUDE -->

# Supported Algorithms

| Algorithm | Description | Key Type |
|-----------|-------------|----------|
| HS256 | HMAC using SHA-256 | []byte |
| HS384 | HMAC using SHA-384 | []byte |
| HS512 | HMAC using SHA-512 | []byte |
| RS256 | RSA PKCS1v15 using SHA-256 | *rsa.PrivateKey / *rsa.PublicKey |
| RS384 | RSA PKCS1v15 using SHA-384 | *rsa.PrivateKey / *rsa.PublicKey |
| RS512 | RSA PKCS1v15 using SHA-512 | *rsa.PrivateKey / *rsa.PublicKey |
| PS256 | RSA PSS using SHA-256 | *rsa.PrivateKey / *rsa.PublicKey |
| PS384 | RSA PSS using SHA-384 | *rsa.PrivateKey / *rsa.PublicKey |
| PS512 | RSA PSS using SHA-512 | *rsa.PrivateKey / *rsa.PublicKey |
| ES256 | ECDSA using P-256 and SHA-256 | *ecdsa.PrivateKey / *ecdsa.PublicKey |
| ES384 | ECDSA using P-384 and SHA-384 | *ecdsa.PrivateKey / *ecdsa.PublicKey |
| ES512 | ECDSA using P-521 and SHA-512 | *ecdsa.PrivateKey / *ecdsa.PublicKey |
| EdDSA | EdDSA using Ed25519 or Ed448 | ed25519.PrivateKey / ed25519.PublicKey |

# Description

This library provides low-level digital signature operations. It does minimal parameter validation for performance, uses strongly typed APIs, and has minimal dependencies.

The generic `Signer[K]` and `Verifier[K]` interfaces provide type-safe operations for different key types.

# Contributions

## Issues

For bug reports and feature requests, please include failing tests when possible.

## Pull Requests

Please include tests that exercise your changes.

# Related Libraries

* [github.com/lestrrat-go/jwx](https://github.com/lestrrat-go/jwx) - JOSE (JWA/JWE/JWK/JWS/JWT) implementation