package dsig_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"testing"

	"github.com/lestrrat-go/dsig"
	"github.com/stretchr/testify/require"
)

func TestECDSADER(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		curve elliptic.Curve
		h     crypto.Hash
		hfunc func() hash.Hash
	}{
		{"P256/SHA256", elliptic.P256(), crypto.SHA256, sha256.New},
		{"P384/SHA384", elliptic.P384(), crypto.SHA384, sha512.New384},
		{"P521/SHA512", elliptic.P521(), crypto.SHA512, sha512.New},
	}

	payload := []byte("the quick brown fox jumps over the lazy dog")

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			key, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
			require.NoError(t, err, "generate key")

			digest := func() []byte {
				h := tc.hfunc()
				h.Write(payload)
				return h.Sum(nil)
			}

			t.Run("round trip", func(t *testing.T) {
				sig, err := dsig.SignECDSADER(key, payload, tc.h, nil)
				require.NoError(t, err, "SignECDSADER")
				require.NoError(t, dsig.VerifyECDSADER(&key.PublicKey, payload, sig, tc.h), "VerifyECDSADER")
			})

			t.Run("dsig sign, stdlib verify", func(t *testing.T) {
				sig, err := dsig.SignECDSADER(key, payload, tc.h, nil)
				require.NoError(t, err, "SignECDSADER")
				require.True(t, ecdsa.VerifyASN1(&key.PublicKey, digest(), sig), "stdlib VerifyASN1 must accept dsig DER output")
			})

			t.Run("stdlib sign, dsig verify", func(t *testing.T) {
				sig, err := ecdsa.SignASN1(rand.Reader, key, digest())
				require.NoError(t, err, "ecdsa.SignASN1")
				require.NoError(t, dsig.VerifyECDSADER(&key.PublicKey, payload, sig, tc.h), "VerifyECDSADER must accept stdlib DER output")
			})

			t.Run("format isolation", func(t *testing.T) {
				derSig, err := dsig.SignECDSADER(key, payload, tc.h, nil)
				require.NoError(t, err, "SignECDSADER")
				jwsSig, err := dsig.SignECDSA(key, payload, tc.h, nil)
				require.NoError(t, err, "SignECDSA")

				require.Error(t, dsig.VerifyECDSA(&key.PublicKey, payload, derSig, tc.h), "JWS verifier must reject DER signature")
				require.Error(t, dsig.VerifyECDSADER(&key.PublicKey, payload, jwsSig, tc.h), "DER verifier must reject JWS signature")
			})

			t.Run("tamper detection", func(t *testing.T) {
				sig, err := dsig.SignECDSADER(key, payload, tc.h, nil)
				require.NoError(t, err, "SignECDSADER")
				tampered := make([]byte, len(sig))
				copy(tampered, sig)
				tampered[len(tampered)/2] ^= 0xFF
				require.Error(t, dsig.VerifyECDSADER(&key.PublicKey, payload, tampered, tc.h), "tampered signature must fail")
			})

			t.Run("wrong key", func(t *testing.T) {
				sig, err := dsig.SignECDSADER(key, payload, tc.h, nil)
				require.NoError(t, err, "SignECDSADER")
				other, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
				require.NoError(t, err, "generate other key")
				require.Error(t, dsig.VerifyECDSADER(&other.PublicKey, payload, sig, tc.h), "wrong key must fail")
			})
		})
	}
}
