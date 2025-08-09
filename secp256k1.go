//go:build dsig_secp256k1

package dsig

import (
	"crypto"
	"crypto/ecdsa"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// init adds secp256k1 support when the dsig_secp256k1 build tag is used.
func init() {
	// Register ES256K (secp256k1 + SHA256) support
	RegisterECDSACurve(ECDSAWithSecp256k1AndSHA256, crypto.SHA256)
}

// secp256k1Curve returns the secp256k1 curve.
func secp256k1Curve() *secp256k1.KoblitzCurve {
	return secp256k1.S256()
}

// isSecp256k1Key checks if the given key uses the secp256k1 curve.
func isSecp256k1Key(key any) bool {
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		return k.Curve == secp256k1Curve()
	case *ecdsa.PublicKey:
		return k.Curve == secp256k1Curve()
	case ecdsa.PrivateKey:
		return k.Curve == secp256k1Curve()
	case ecdsa.PublicKey:
		return k.Curve == secp256k1Curve()
	}
	return false
}

// GetSecp256k1Curve returns the secp256k1 curve for tests.
func GetSecp256k1Curve() *secp256k1.KoblitzCurve {
	return secp256k1.S256()
}
