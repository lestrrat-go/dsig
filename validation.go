package dsig

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
)

// isValidRSAKey validates that the provided key type is appropriate for RSA algorithms.
// It returns false if the key is clearly incompatible (e.g., ECDSA or EdDSA keys).
func isValidRSAKey(key any) bool {
	switch key.(type) {
	case
		ecdsa.PrivateKey, *ecdsa.PrivateKey,
		ed25519.PrivateKey:
		// these are NOT ok for RSA algorithms
		return false
	}
	return true
}

// isValidECDSAKey validates that the provided key type is appropriate for ECDSA algorithms.
// It returns false if the key is clearly incompatible (e.g., RSA or EdDSA keys).
func isValidECDSAKey(key any) bool {
	switch key.(type) {
	case
		ed25519.PrivateKey,
		rsa.PrivateKey, *rsa.PrivateKey:
		// these are NOT ok for ECDSA algorithms
		return false
	}
	return true
}

// isValidEDDSAKey validates that the provided key type is appropriate for EdDSA algorithms.
// It returns false if the key is clearly incompatible (e.g., RSA or ECDSA keys).
func isValidEDDSAKey(key any) bool {
	switch key.(type) {
	case
		ecdsa.PrivateKey, *ecdsa.PrivateKey,
		rsa.PrivateKey, *rsa.PrivateKey:
		// these are NOT ok for EdDSA algorithms
		return false
	}
	return true
}
