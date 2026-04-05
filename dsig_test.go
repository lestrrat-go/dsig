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

func TestVerifyHMACDigest(t *testing.T) {
	payload := []byte("hello world")
	key := []byte("secretkey")

	// Sign via dsig.Sign to get an actual HMAC signature
	signature, err := dsig.Sign(key, dsig.HMACWithSHA256, payload, nil)
	require.NoError(t, err)

	// Compute the MAC separately (what a streaming caller would do)
	computedMAC, err := dsig.SignHMAC(key, payload, sha256.New)
	require.NoError(t, err)

	require.NoError(t, dsig.VerifyHMACDigest(computedMAC, signature), "VerifyHMACDigest should succeed")
	require.Error(t, dsig.VerifyHMACDigest(computedMAC, signature[:len(signature)-1]), "VerifyHMACDigest should fail for tampered signature")
	require.Error(t, dsig.VerifyHMACDigest(computedMAC[:len(computedMAC)-1], signature), "VerifyHMACDigest should fail for tampered MAC")
}

func TestVerifyRSADigest(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	testcases := []struct {
		name string
		alg  string
		h    crypto.Hash
		pss  bool
	}{
		{"PKCS1v15_SHA256", dsig.RSAPKCS1v15WithSHA256, crypto.SHA256, false},
		{"PSS_SHA256", dsig.RSAPSSWithSHA256, crypto.SHA256, true},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			payload := []byte("hello world")

			sig, err := dsig.SignRSA(priv, payload, tc.h, tc.pss, nil)
			require.NoError(t, err)

			hasher := tc.h.New()
			hasher.Write(payload)
			digest := hasher.Sum(nil)

			require.NoError(t, dsig.VerifyRSADigest(&priv.PublicKey, digest, sig, tc.h, tc.pss), "VerifyRSADigest should succeed")
			require.Error(t, dsig.VerifyRSADigest(&priv.PublicKey, digest, sig[:len(sig)-1], tc.h, tc.pss), "VerifyRSADigest should fail for tampered signature")

			badDigest := make([]byte, len(digest))
			copy(badDigest, digest)
			badDigest[0] ^= 0xff
			require.Error(t, dsig.VerifyRSADigest(&priv.PublicKey, badDigest, sig, tc.h, tc.pss), "VerifyRSADigest should fail for tampered digest")
		})
	}
}

func TestVerifyECDSADigest(t *testing.T) {
	payload := []byte("hello world")
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	sig, err := dsig.SignECDSA(priv, payload, crypto.SHA256, nil)
	require.NoError(t, err)

	hasher := crypto.SHA256.New()
	hasher.Write(payload)
	digest := hasher.Sum(nil)

	require.NoError(t, dsig.VerifyECDSADigest(&priv.PublicKey, digest, sig), "VerifyECDSADigest should succeed")
	require.Error(t, dsig.VerifyECDSADigest(&priv.PublicKey, digest, sig[:len(sig)-1]), "VerifyECDSADigest should fail for tampered signature")

	badDigest := make([]byte, len(digest))
	copy(badDigest, digest)
	badDigest[0] ^= 0xff
	require.Error(t, dsig.VerifyECDSADigest(&priv.PublicKey, badDigest, sig), "VerifyECDSADigest should fail for tampered digest")
}

func TestVerifyDigest(t *testing.T) {
	payload := []byte("hello world")

	t.Run("HMAC", func(t *testing.T) {
		key := []byte("secretkey")

		signature, err := dsig.Sign(key, dsig.HMACWithSHA256, payload, nil)
		require.NoError(t, err)

		computedMAC, err := dsig.SignHMAC(key, payload, sha256.New)
		require.NoError(t, err)

		require.NoError(t, dsig.VerifyDigest(key, dsig.HMACWithSHA256, computedMAC, signature))
	})

	t.Run("RSA with PublicKey", func(t *testing.T) {
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		sig, err := dsig.Sign(priv, dsig.RSAPKCS1v15WithSHA256, payload, nil)
		require.NoError(t, err)

		hasher := crypto.SHA256.New()
		hasher.Write(payload)
		digest := hasher.Sum(nil)

		require.NoError(t, dsig.VerifyDigest(&priv.PublicKey, dsig.RSAPKCS1v15WithSHA256, digest, sig))

		// Tampered digest should fail
		badDigest := make([]byte, len(digest))
		copy(badDigest, digest)
		badDigest[0] ^= 0xff
		require.Error(t, dsig.VerifyDigest(&priv.PublicKey, dsig.RSAPKCS1v15WithSHA256, badDigest, sig), "tampered digest should fail")
	})

	t.Run("RSA PSS", func(t *testing.T) {
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		sig, err := dsig.Sign(priv, dsig.RSAPSSWithSHA256, payload, nil)
		require.NoError(t, err)

		hasher := crypto.SHA256.New()
		hasher.Write(payload)
		digest := hasher.Sum(nil)

		require.NoError(t, dsig.VerifyDigest(&priv.PublicKey, dsig.RSAPSSWithSHA256, digest, sig))
	})

	t.Run("RSA via crypto.Signer", func(t *testing.T) {
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		sig, err := dsig.Sign(priv, dsig.RSAPKCS1v15WithSHA256, payload, nil)
		require.NoError(t, err)

		hasher := crypto.SHA256.New()
		hasher.Write(payload)
		digest := hasher.Sum(nil)

		// Pass *rsa.PrivateKey which implements crypto.Signer
		require.NoError(t, dsig.VerifyDigest(priv, dsig.RSAPKCS1v15WithSHA256, digest, sig))
	})

	t.Run("ECDSA with PublicKey", func(t *testing.T) {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		sig, err := dsig.Sign(priv, dsig.ECDSAWithP256AndSHA256, payload, nil)
		require.NoError(t, err)

		hasher := crypto.SHA256.New()
		hasher.Write(payload)
		digest := hasher.Sum(nil)

		require.NoError(t, dsig.VerifyDigest(&priv.PublicKey, dsig.ECDSAWithP256AndSHA256, digest, sig))

		// Tampered digest should fail
		badDigest := make([]byte, len(digest))
		copy(badDigest, digest)
		badDigest[0] ^= 0xff
		require.Error(t, dsig.VerifyDigest(&priv.PublicKey, dsig.ECDSAWithP256AndSHA256, badDigest, sig), "tampered digest should fail")
	})

	t.Run("ECDSA via crypto.Signer", func(t *testing.T) {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		sig, err := dsig.Sign(priv, dsig.ECDSAWithP256AndSHA256, payload, nil)
		require.NoError(t, err)

		hasher := crypto.SHA256.New()
		hasher.Write(payload)
		digest := hasher.Sum(nil)

		// Pass *ecdsa.PrivateKey which implements crypto.Signer
		require.NoError(t, dsig.VerifyDigest(priv, dsig.ECDSAWithP256AndSHA256, digest, sig))
	})

	t.Run("EdDSA returns error", func(t *testing.T) {
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		require.Error(t, dsig.VerifyDigest(pub, dsig.EdDSA, []byte("digest"), []byte("sig")))
	})

	t.Run("Unknown algorithm returns error", func(t *testing.T) {
		require.Error(t, dsig.VerifyDigest(nil, "UNKNOWN_ALG", []byte("digest"), []byte("sig")))
	})

	t.Run("RSA with wrong key type", func(t *testing.T) {
		ecPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		// Pass an ECDSA key where RSA is expected
		require.Error(t, dsig.VerifyDigest(&ecPriv.PublicKey, dsig.RSAPKCS1v15WithSHA256, []byte("digest"), []byte("sig")))
	})

	t.Run("ECDSA with wrong key type", func(t *testing.T) {
		rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		// Pass an RSA key where ECDSA is expected
		require.Error(t, dsig.VerifyDigest(&rsaPriv.PublicKey, dsig.ECDSAWithP256AndSHA256, []byte("digest"), []byte("sig")))
	})
}
