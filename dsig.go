// Package dsig provides digital signature operations for Go.
// It contains low-level signature generation and verification tools that can be used
// by multiple signing libraries, including JWS, JWT, and other digital signature formats.
//
// This package provides building blocks for digital signature operations and should be
// thought of as a low-level API for power-users who need efficient signature operations
// without the overhead of higher-level packages.
//
// The package follows these design principles:
// 1. Does minimal checking of input parameters (for performance); callers need to ensure that the parameters are valid.
// 2. All exported functions are strongly typed (i.e. they do not take `any` types unless they absolutely have to).
// 3. Does not rely on other high-level packages (standalone, except for internal packages).
package dsig

// Signer is a generic interface that defines the method for signing payloads.
// The type parameter K represents the key type (e.g., []byte for HMAC keys,
// *rsa.PrivateKey for RSA keys, *ecdsa.PrivateKey for ECDSA keys).
type Signer[K any] interface {
	Sign(key K, payload []byte) ([]byte, error)
}

// Verifier is a generic interface that defines the method for verifying signatures.
// The type parameter K represents the key type (e.g., []byte for HMAC keys,
// *rsa.PublicKey for RSA keys, *ecdsa.PublicKey for ECDSA keys).
type Verifier[K any] interface {
	Verify(key K, buf []byte, signature []byte) error
}
