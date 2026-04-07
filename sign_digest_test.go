package dsig_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"testing"

	"github.com/lestrrat-go/dsig"
	"github.com/stretchr/testify/require"
)

func TestSignDigest(t *testing.T) {
	t.Parallel()
	payload := []byte("hello world")

	t.Run("HMAC returns digest unchanged", func(t *testing.T) {
		t.Parallel()
		key := []byte("secretkey")

		mac := hmac.New(sha256.New, key)
		mac.Write(payload)
		digest := mac.Sum(nil)

		sig, err := dsig.SignDigest(key, dsig.HMACWithSHA256, digest, nil)
		require.NoError(t, err)
		require.Equal(t, digest, sig, "HMAC SignDigest should return digest as-is")

		require.NoError(t, dsig.VerifyDigest(key, dsig.HMACWithSHA256, digest, sig))
	})

	t.Run("RSA PKCS1v15", func(t *testing.T) {
		t.Parallel()
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		hasher := crypto.SHA256.New()
		hasher.Write(payload)
		digest := hasher.Sum(nil)

		sig, err := dsig.SignDigest(priv, dsig.RSAPKCS1v15WithSHA256, digest, nil)
		require.NoError(t, err)

		require.NoError(t, dsig.VerifyDigest(&priv.PublicKey, dsig.RSAPKCS1v15WithSHA256, digest, sig))
	})

	t.Run("RSA PSS", func(t *testing.T) {
		t.Parallel()
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		hasher := crypto.SHA256.New()
		hasher.Write(payload)
		digest := hasher.Sum(nil)

		sig, err := dsig.SignDigest(priv, dsig.RSAPSSWithSHA256, digest, nil)
		require.NoError(t, err)

		require.NoError(t, dsig.VerifyDigest(&priv.PublicKey, dsig.RSAPSSWithSHA256, digest, sig))
	})

	t.Run("RSA via crypto.Signer", func(t *testing.T) {
		t.Parallel()
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		hasher := crypto.SHA256.New()
		hasher.Write(payload)
		digest := hasher.Sum(nil)

		// *rsa.PrivateKey implements crypto.Signer — this exercises the crypto.Signer path
		sig, err := dsig.SignDigest(priv, dsig.RSAPKCS1v15WithSHA256, digest, nil)
		require.NoError(t, err)

		require.NoError(t, dsig.VerifyDigest(&priv.PublicKey, dsig.RSAPKCS1v15WithSHA256, digest, sig))
	})

	t.Run("ECDSA", func(t *testing.T) {
		t.Parallel()
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		hasher := crypto.SHA256.New()
		hasher.Write(payload)
		digest := hasher.Sum(nil)

		sig, err := dsig.SignDigest(priv, dsig.ECDSAWithP256AndSHA256, digest, nil)
		require.NoError(t, err)

		require.NoError(t, dsig.VerifyDigest(&priv.PublicKey, dsig.ECDSAWithP256AndSHA256, digest, sig))
	})

	t.Run("ECDSA via crypto.Signer", func(t *testing.T) {
		t.Parallel()
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		hasher := crypto.SHA256.New()
		hasher.Write(payload)
		digest := hasher.Sum(nil)

		// *ecdsa.PrivateKey implements crypto.Signer but ecdsaGetSignerKey
		// optimizes to the non-crypto.Signer path for *ecdsa.PrivateKey.
		// This test confirms the end result is the same.
		sig, err := dsig.SignDigest(priv, dsig.ECDSAWithP256AndSHA256, digest, nil)
		require.NoError(t, err)

		require.NoError(t, dsig.VerifyDigest(&priv.PublicKey, dsig.ECDSAWithP256AndSHA256, digest, sig))
	})

	t.Run("EdDSA returns error", func(t *testing.T) {
		t.Parallel()
		_, err := dsig.SignDigest(nil, dsig.EdDSA, []byte("digest"), nil)
		require.Error(t, err)
	})

	t.Run("Unknown algorithm returns error", func(t *testing.T) {
		t.Parallel()
		_, err := dsig.SignDigest(nil, "UNKNOWN_ALG", []byte("digest"), nil)
		require.Error(t, err)
	})
}
