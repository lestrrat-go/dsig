package dsig_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"testing"

	"github.com/lestrrat-go/dsig"
	"github.com/stretchr/testify/require"
)

func TestHMAC(t *testing.T) {
	t.Parallel()
	tests := []struct {
		alg   string
		hfunc func() hash.Hash
	}{
		{dsig.HMACWithSHA256, sha256.New},
		{dsig.HMACWithSHA384, sha512.New384},
		{dsig.HMACWithSHA512, sha512.New},
	}

	for _, tc := range tests {
		t.Run(tc.alg, func(t *testing.T) {
			payload := []byte("hello world")
			key := []byte("secretkey")

			// Test direct HMAC functions
			sig, err := dsig.SignHMAC(key, payload, tc.hfunc)
			require.NoError(t, err, "SignHMAC should not return error")
			require.NoError(t, dsig.VerifyHMAC(key, payload, sig, tc.hfunc), "VerifyHMAC should succeed for a valid signature")
			require.Error(t, dsig.VerifyHMAC(key, payload, sig[:len(sig)-1], tc.hfunc), "VerifyHMAC should fail for an invalid signature")

			// Test generic Sign/Verify functions
			sig2, err := dsig.Sign(key, tc.alg, payload, nil)
			require.NoError(t, err, "Sign should not return error")
			require.NoError(t, dsig.Verify(key, tc.alg, payload, sig2), "Verify should succeed for a valid signature")
		})
	}
}

func TestRSA(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, "RSA key generation should not error")

	testcases := []struct {
		name string
		alg  string
		h    crypto.Hash
		pss  bool
	}{
		{"RSA_PKCS1v15_WITH_SHA256", dsig.RSAPKCS1v15WithSHA256, crypto.SHA256, false},
		{"RSA_PKCS1v15_WITH_SHA384", dsig.RSAPKCS1v15WithSHA384, crypto.SHA384, false},
		{"RSA_PKCS1v15_WITH_SHA512", dsig.RSAPKCS1v15WithSHA512, crypto.SHA512, false},
		{"RSA_PSS_WITH_SHA256", dsig.RSAPSSWithSHA256, crypto.SHA256, true},
		{"RSA_PSS_WITH_SHA384", dsig.RSAPSSWithSHA384, crypto.SHA384, true},
		{"RSA_PSS_WITH_SHA512", dsig.RSAPSSWithSHA512, crypto.SHA512, true},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			payload := []byte("hello world")

			// Test direct RSA functions
			sig, err := dsig.SignRSA(priv, payload, tc.h, tc.pss, nil)
			require.NoError(t, err, "SignRSA should not return error")
			require.NoError(t, dsig.VerifyRSA(&priv.PublicKey, payload, sig, tc.h, tc.pss), "VerifyRSA should succeed for a valid signature")
			require.Error(t, dsig.VerifyRSA(&priv.PublicKey, payload, sig[:len(sig)-1], tc.h, tc.pss), "VerifyRSA should fail for an invalid signature")

			// Test generic Sign/Verify functions
			sig2, err := dsig.Sign(priv, tc.alg, payload, nil)
			require.NoError(t, err, "Sign should not return error")
			require.NoError(t, dsig.Verify(&priv.PublicKey, tc.alg, payload, sig2), "Verify should succeed for a valid signature")
		})
	}
}

func TestECDSA(t *testing.T) {
	table := []struct {
		name  string
		alg   string
		curve elliptic.Curve
		h     crypto.Hash
	}{
		{"ECDSA_WITH_P256_AND_SHA256", dsig.ECDSAWithP256AndSHA256, elliptic.P256(), crypto.SHA256},
		{"ECDSA_WITH_P384_AND_SHA384", dsig.ECDSAWithP384AndSHA384, elliptic.P384(), crypto.SHA384},
		{"ECDSA_WITH_P521_AND_SHA512", dsig.ECDSAWithP521AndSHA512, elliptic.P521(), crypto.SHA512},
	}

	// secp256k1 tests are now only available with build tag in separate test file

	for _, tc := range table {
		t.Run(tc.name, func(t *testing.T) {
			payload := []byte("hello world")
			priv, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
			require.NoError(t, err, "ECDSA key generation should not error")

			// Test direct ECDSA functions
			sig, err := dsig.SignECDSA(priv, payload, tc.h, nil)
			require.NoError(t, err, "SignECDSA should not return error")
			require.NoError(t, dsig.VerifyECDSA(&priv.PublicKey, payload, sig, tc.h), "VerifyECDSA should succeed for a valid signature")
			require.Error(t, dsig.VerifyECDSA(&priv.PublicKey, payload, sig[:len(sig)-1], tc.h), "VerifyECDSA should fail for an invalid signature")

			// Test generic Sign/Verify functions
			sig2, err := dsig.Sign(priv, tc.alg, payload, nil)
			require.NoError(t, err, "Sign should not return error")
			require.NoError(t, dsig.Verify(&priv.PublicKey, tc.alg, payload, sig2), "Verify should succeed for a valid signature")
		})
	}
}

func TestEdDSA(t *testing.T) {
	payload := []byte("hello world")
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err, "EdDSA key generation should not error")

	// Test direct EdDSA functions
	sig, err := dsig.SignEdDSA(priv, payload)
	require.NoError(t, err, "SignEdDSA should not return error")
	require.NoError(t, dsig.VerifyEdDSA(pub, payload, sig), "VerifyEdDSA should succeed for a valid signature")
	require.Error(t, dsig.VerifyEdDSA(pub, payload, sig[:len(sig)-1]), "VerifyEdDSA should fail for an invalid signature")

	// Test generic Sign/Verify functions
	sig2, err := dsig.Sign(priv, dsig.EdDSA, payload, nil)
	require.NoError(t, err, "Sign should not return error")
	require.NoError(t, dsig.Verify(pub, dsig.EdDSA, payload, sig2), "Verify should succeed for a valid signature")
}
