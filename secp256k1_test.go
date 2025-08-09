//go:build dsig_secp256k1

package dsig_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/lestrrat-go/dsig"
	"github.com/stretchr/testify/require"
)

func TestSecp256k1(t *testing.T) {
	t.Parallel()

	// Generate secp256k1 key
	privKey, err := ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
	require.NoError(t, err, "secp256k1 key generation should not error")

	payload := []byte("hello world")

	// Test direct ECDSA functions with secp256k1
	sig, err := dsig.SignECDSA(privKey, payload, crypto.SHA256, nil)
	require.NoError(t, err, "SignECDSA with secp256k1 should not return error")
	require.NoError(t, dsig.VerifyECDSA(&privKey.PublicKey, payload, sig, crypto.SHA256), "VerifyECDSA with secp256k1 should succeed for a valid signature")
	require.Error(t, dsig.VerifyECDSA(&privKey.PublicKey, payload, sig[:len(sig)-1], crypto.SHA256), "VerifyECDSA with secp256k1 should fail for an invalid signature")

	// Test generic Sign/Verify functions with ES256K
	sig2, err := dsig.Sign(privKey, dsig.ECDSAWithSecp256k1AndSHA256, payload, nil)
	require.NoError(t, err, "Sign with ES256K should not return error")
	require.NoError(t, dsig.Verify(&privKey.PublicKey, dsig.ECDSAWithSecp256k1AndSHA256, payload, sig2), "Verify with ES256K should succeed for a valid signature")

	// Test that secp256k1 curve is accepted
	secp256k1Key, err := ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
	require.NoError(t, err)
	
	// This should work since it's secp256k1
	_, err = dsig.Sign(secp256k1Key, dsig.ECDSAWithSecp256k1AndSHA256, payload, nil)
	require.NoError(t, err, "secp256k1 key should work with ES256K algorithm")
}

func TestSecp256k1CurveValidation(t *testing.T) {
	t.Parallel()

	payload := []byte("test")

	// Test that secp256k1 key works with ES256K
	secp256k1Key, err := ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
	require.NoError(t, err)

	// This should succeed because we're using the right curve
	sig, err := dsig.Sign(secp256k1Key, dsig.ECDSAWithSecp256k1AndSHA256, payload, nil)
	require.NoError(t, err, "secp256k1 key should work with ES256K")

	// Test verification should work
	err = dsig.Verify(&secp256k1Key.PublicKey, dsig.ECDSAWithSecp256k1AndSHA256, payload, sig)
	require.NoError(t, err, "secp256k1 verification should work")
}