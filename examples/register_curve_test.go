package examples_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/lestrrat-go/dsig"
	"github.com/stretchr/testify/require"
)

func TestRegisterECDSACurve(t *testing.T) {
	// Define a custom algorithm name
	customAlg := "CUSTOM_P256_WITH_SHA256"
	
	// Register P-256 as a "custom" algorithm (for demonstration)
	dsig.RegisterECDSACurve(customAlg, crypto.SHA256)

	// Test that our custom algorithm now works
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	payload := []byte("test message")

	// Sign with our custom algorithm
	sig, err := dsig.Sign(privKey, customAlg, payload, nil)
	require.NoError(t, err, "Should be able to sign with registered custom algorithm")

	// Verify with our custom algorithm
	err = dsig.Verify(&privKey.PublicKey, customAlg, payload, sig)
	require.NoError(t, err, "Should be able to verify with registered custom algorithm")

	// Test with different curve - this will work but may not be interoperable
	// with systems expecting P-256 for this algorithm name
	p384Key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	// This will work at the crypto level but may not be what you want for interoperability
	sig2, err := dsig.Sign(p384Key, customAlg, payload, nil)
	require.NoError(t, err, "Sign works with any ECDSA key at crypto level")

	// Verify will work too
	err = dsig.Verify(&p384Key.PublicKey, customAlg, payload, sig2)
	require.NoError(t, err, "Verify works with matching curve")

	// Cross-curve verification will fail naturally
	err = dsig.Verify(&privKey.PublicKey, customAlg, payload, sig2)
	require.Error(t, err, "Cross-curve verification fails naturally")
}