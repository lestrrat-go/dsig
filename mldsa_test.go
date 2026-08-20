//go:build go1.27

package dsig_test

import (
	"crypto"
	"crypto/mldsa"
	"crypto/sha3"
	"testing"

	"github.com/lestrrat-go/dsig"
	"github.com/stretchr/testify/require"
)

func mldsaAlgorithms() []struct {
	name   string
	params mldsa.Parameters
} {
	return []struct {
		name   string
		params mldsa.Parameters
	}{
		{dsig.MLDSA44, mldsa.MLDSA44()},
		{dsig.MLDSA65, mldsa.MLDSA65()},
		{dsig.MLDSA87, mldsa.MLDSA87()},
	}
}

func TestMLDSARegistration(t *testing.T) {
	t.Parallel()

	// The constants must agree with crypto/mldsa, because the registry is keyed
	// by Parameters.String and callers compare against the constants.
	t.Run("constants match crypto/mldsa", func(t *testing.T) {
		t.Parallel()
		for _, tc := range mldsaAlgorithms() {
			require.Equal(t, tc.name, tc.params.String())
		}
	})

	// ML-DSA has its own family. Custom means "dsig knows nothing about this
	// algorithm", which is false here and leads callers that switch on Family
	// to describe ML-DSA as unknowable.
	t.Run("registered as its own family", func(t *testing.T) {
		t.Parallel()
		for _, tc := range mldsaAlgorithms() {
			info, ok := dsig.GetAlgorithmInfo(tc.name)
			require.True(t, ok, "%s must be registered", tc.name)
			require.Equal(t, dsig.MLDSAFamily, info.Family)
			require.NotEqual(t, dsig.Custom, info.Family)
		}
		require.Equal(t, "ML-DSA", dsig.MLDSAFamily.String())
	})

	t.Run("meta implements the opts-aware interfaces", func(t *testing.T) {
		t.Parallel()
		for _, tc := range mldsaAlgorithms() {
			info, ok := dsig.GetAlgorithmInfo(tc.name)
			require.True(t, ok)
			require.Implements(t, (*dsig.SignerWithOpts)(nil), info.Meta)
			require.Implements(t, (*dsig.VerifierWithOpts)(nil), info.Meta)
		}
	})

	t.Run("cannot be unregistered", func(t *testing.T) {
		t.Parallel()
		require.Error(t, dsig.UnregisterAlgorithm(dsig.MLDSA44))
		_, ok := dsig.GetAlgorithmInfo(dsig.MLDSA44)
		require.True(t, ok, "ML-DSA-44 must survive an unregister attempt")
	})
}

func TestMLDSASignVerify(t *testing.T) {
	t.Parallel()

	payload := []byte("Hello, post-quantum world!")

	for _, tc := range mldsaAlgorithms() {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			sk, err := mldsa.GenerateKey(tc.params)
			require.NoError(t, err)
			pk := sk.PublicKey()

			t.Run("through the registry", func(t *testing.T) {
				t.Parallel()
				sig, err := dsig.Sign(sk, tc.name, payload, nil)
				require.NoError(t, err)
				require.Len(t, sig, tc.params.SignatureSize())
				require.NoError(t, dsig.Verify(pk, tc.name, payload, sig))
			})

			t.Run("through the typed helpers", func(t *testing.T) {
				t.Parallel()
				sig, err := dsig.SignMLDSA(sk, payload, nil)
				require.NoError(t, err)
				require.NoError(t, dsig.VerifyMLDSA(pk, payload, sig, nil))
			})

			t.Run("a private key verifies too", func(t *testing.T) {
				t.Parallel()
				sig, err := dsig.Sign(sk, tc.name, payload, nil)
				require.NoError(t, err)
				require.NoError(t, dsig.Verify(sk, tc.name, payload, sig))
			})

			t.Run("a tampered payload fails", func(t *testing.T) {
				t.Parallel()
				sig, err := dsig.Sign(sk, tc.name, payload, nil)
				require.NoError(t, err)
				require.Error(t, dsig.Verify(pk, tc.name, []byte("different payload"), sig))
			})
		})
	}
}

func TestMLDSANilKey(t *testing.T) {
	t.Parallel()

	require.Error(t, func() error {
		_, err := dsig.SignMLDSA(nil, []byte("payload"), nil)
		return err
	}())
	require.Error(t, dsig.VerifyMLDSA(nil, []byte("payload"), []byte("sig"), nil))
}

func TestMLDSAWrongKeyType(t *testing.T) {
	t.Parallel()

	_, err := dsig.Sign("not a key", dsig.MLDSA44, []byte("payload"), nil)
	require.Error(t, err)
	require.ErrorContains(t, err, "expected *mldsa.PrivateKey")

	err = dsig.Verify("not a key", dsig.MLDSA44, []byte("payload"), []byte("sig"))
	require.Error(t, err)
	require.ErrorContains(t, err, "expected *mldsa.PublicKey")
}

// TestMLDSAParamSetMismatch covers a key whose parameter set disagrees with the
// algorithm the caller named. The key binds its own parameter set, so without
// this check the operation would succeed under a set the caller never asked
// for, and anything reading the algorithm name to judge security level would be
// misled.
func TestMLDSAParamSetMismatch(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		routeAlg string
		keyGen   mldsa.Parameters
	}{
		{"ML-DSA-65-as-ML-DSA-44", dsig.MLDSA44, mldsa.MLDSA65()},
		{"ML-DSA-87-as-ML-DSA-44", dsig.MLDSA44, mldsa.MLDSA87()},
		{"ML-DSA-87-as-ML-DSA-65", dsig.MLDSA65, mldsa.MLDSA87()},
		{"ML-DSA-44-as-ML-DSA-65", dsig.MLDSA65, mldsa.MLDSA44()},
		{"ML-DSA-44-as-ML-DSA-87", dsig.MLDSA87, mldsa.MLDSA44()},
		{"ML-DSA-65-as-ML-DSA-87", dsig.MLDSA87, mldsa.MLDSA65()},
	}

	payload := []byte("parameter set confusion")

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			sk, err := mldsa.GenerateKey(tc.keyGen)
			require.NoError(t, err)
			pk := sk.PublicKey()

			_, err = dsig.Sign(sk, tc.routeAlg, payload, nil)
			require.Error(t, err)
			require.ErrorContains(t, err, "parameter set mismatch")

			_, err = dsig.SignWithOpts(sk, tc.routeAlg, payload, nil, nil)
			require.Error(t, err)
			require.ErrorContains(t, err, "parameter set mismatch")

			// A real signature made under the key's own set must still be
			// refused when it arrives labelled as a different one.
			sig, err := dsig.Sign(sk, tc.keyGen.String(), payload, nil)
			require.NoError(t, err)

			err = dsig.Verify(pk, tc.routeAlg, payload, sig)
			require.Error(t, err)
			require.ErrorContains(t, err, "parameter set mismatch")

			err = dsig.VerifyWithOpts(pk, tc.routeAlg, payload, sig, nil)
			require.Error(t, err)
			require.ErrorContains(t, err, "parameter set mismatch")
		})
	}
}

func TestMLDSAOptions(t *testing.T) {
	t.Parallel()

	sk, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)
	pk := sk.PublicKey()

	payload := []byte("context handling")

	t.Run("context binds signature to its value", func(t *testing.T) {
		t.Parallel()
		opts := &mldsa.Options{Context: "dsig-test-ctx"}

		sig, err := dsig.SignWithOpts(sk, dsig.MLDSA65, payload, opts, nil)
		require.NoError(t, err)
		require.NoError(t, dsig.VerifyWithOpts(pk, dsig.MLDSA65, payload, sig, opts))

		require.Error(t, dsig.VerifyWithOpts(pk, dsig.MLDSA65, payload, sig, &mldsa.Options{Context: "other"}),
			"a different context must not verify")
		require.Error(t, dsig.VerifyWithOpts(pk, dsig.MLDSA65, payload, sig, nil),
			"an absent context must not verify a context-bound signature")
	})

	t.Run("nil opts is accepted", func(t *testing.T) {
		t.Parallel()
		sig, err := dsig.SignWithOpts(sk, dsig.MLDSA65, payload, nil, nil)
		require.NoError(t, err)
		require.NoError(t, dsig.VerifyWithOpts(pk, dsig.MLDSA65, payload, sig, nil))
	})

	// Dropping an unrecognized opts would let a caller believe their Context
	// was honored while an empty one was actually used.
	t.Run("a foreign opts type is rejected", func(t *testing.T) {
		t.Parallel()
		_, err := dsig.SignWithOpts(sk, dsig.MLDSA65, payload, crypto.SHA256, nil)
		require.Error(t, err)
		require.ErrorContains(t, err, "expected *mldsa.Options")

		sig, err := dsig.Sign(sk, dsig.MLDSA65, payload, nil)
		require.NoError(t, err)

		err = dsig.VerifyWithOpts(pk, dsig.MLDSA65, payload, sig, crypto.SHA256)
		require.Error(t, err)
		require.ErrorContains(t, err, "expected *mldsa.Options")
	})
}

// mldsaExternalMu derives the μ message representative that FIPS 204 computes
// internally, so the test can hand a pre-hashed μ to the signer.
//
//	tr = SHAKE256(pk, 64)
//	mu = SHAKE256(tr || 0x00 || len(ctx) || ctx || M, 64)
//
// The two zero bytes are the pure-mode domain separator and an empty context.
func mldsaExternalMu(pk *mldsa.PublicKey, msg []byte) []byte {
	tr := make([]byte, 64)
	h := sha3.NewSHAKE256()
	h.Write(pk.Bytes())
	h.Read(tr)

	mu := make([]byte, 64)
	h2 := sha3.NewSHAKE256()
	h2.Write(tr)
	h2.Write([]byte{0x00, 0x00})
	h2.Write(msg)
	h2.Read(mu)
	return mu
}

// TestMLDSAExternalMu pins the reason SignMLDSA accepts a crypto.SignerOpts.
// crypto.MLDSAMu selects ML-DSA's pre-hashed signing mode, and an
// *mldsa.Options parameter could not express it. The mode is a signer-side
// shortcut, so what it produces is an ordinary signature that VerifyMLDSA
// checks against the original message.
func TestMLDSAExternalMu(t *testing.T) {
	t.Parallel()

	sk, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)
	pk := sk.PublicKey()

	msg := []byte("external mu round trip")
	mu := mldsaExternalMu(pk, msg)
	require.Len(t, mu, crypto.MLDSAMu.Size())

	sig, err := dsig.SignMLDSA(sk, mu, crypto.MLDSAMu)
	require.NoError(t, err)
	require.Len(t, sig, mldsa.MLDSA65().SignatureSize())

	// Verified against the original message, with no opts.
	require.NoError(t, dsig.VerifyMLDSA(pk, msg, sig, nil))

	// A signature over the message directly must also verify, so the two modes
	// agree on what they are signing.
	direct, err := dsig.SignMLDSA(sk, msg, nil)
	require.NoError(t, err)
	require.NoError(t, dsig.VerifyMLDSA(pk, msg, direct, nil))
}

// TestMLDSADigestUnsupported pins that the digest entry points name ML-DSA in
// their refusal. Inheriting the Custom family's blanket message would tell the
// caller dsig knows nothing about the algorithm. ML-DSA signs the message, and
// its pre-hashed mode takes a mu representative derived from the public key
// too, so these entry points cannot serve it.
func TestMLDSADigestUnsupported(t *testing.T) {
	t.Parallel()

	sk, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)

	digest := make([]byte, 32)

	_, err = dsig.SignDigest(sk, dsig.MLDSA65, digest, nil)
	require.Error(t, err)
	require.ErrorContains(t, err, "ML-DSA does not support digest-based signing")
	require.NotContains(t, err.Error(), "custom algorithms")

	err = dsig.VerifyDigest(sk.PublicKey(), dsig.MLDSA65, digest, []byte("sig"))
	require.Error(t, err)
	require.ErrorContains(t, err, "ML-DSA does not support digest-based verification")
	require.NotContains(t, err.Error(), "custom algorithms")
}
