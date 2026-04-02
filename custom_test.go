package dsig_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"io"
	"testing"

	"github.com/lestrrat-go/dsig"
	"github.com/stretchr/testify/require"
)

// testSigner implements dsig.Signer using HMAC-SHA256 for testing purposes.
type testSigner struct{}

func (testSigner) Sign(key any, payload []byte, _ io.Reader) ([]byte, error) {
	k, ok := key.([]byte)
	if !ok {
		return nil, dsig.NewVerificationError("invalid key type")
	}
	mac := hmac.New(sha256.New, k)
	mac.Write(payload)
	return mac.Sum(nil), nil
}

// testVerifier implements dsig.Verifier using HMAC-SHA256 for testing purposes.
type testVerifier struct{}

func (testVerifier) Verify(key any, payload, signature []byte) error {
	k, ok := key.([]byte)
	if !ok {
		return dsig.NewVerificationError("invalid key type")
	}
	mac := hmac.New(sha256.New, k)
	mac.Write(payload)
	expected := mac.Sum(nil)
	if !hmac.Equal(expected, signature) {
		return dsig.NewVerificationError("signature mismatch")
	}
	return nil
}

const testCustomAlg = "TEST_CUSTOM_ALG"

func registerTestCustomAlgorithm(t *testing.T, name string, signer dsig.Signer, verifier dsig.Verifier) {
	t.Helper()
	err := dsig.RegisterAlgorithm(name, dsig.AlgorithmInfo{
		Family: dsig.Custom,
		Meta: dsig.CustomFamilyMeta{
			Signer:   signer,
			Verifier: verifier,
		},
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = dsig.UnregisterAlgorithm(name)
	})
}

func TestCustomSignVerify(t *testing.T) {
	registerTestCustomAlgorithm(t, testCustomAlg, testSigner{}, testVerifier{})

	key := []byte("test-secret-key")
	payload := []byte("hello world")

	sig, err := dsig.Sign(key, testCustomAlg, payload, nil)
	require.NoError(t, err)

	err = dsig.Verify(key, testCustomAlg, payload, sig)
	require.NoError(t, err)

	// Tampered signature should fail
	sig[0] ^= 0xff
	err = dsig.Verify(key, testCustomAlg, payload, sig)
	require.Error(t, err)
}

func TestCustomRegisterSignerOnly(t *testing.T) {
	registerTestCustomAlgorithm(t, "TEST_SIGNER_ONLY", testSigner{}, nil)

	key := []byte("test-secret-key")
	payload := []byte("hello world")

	sig, err := dsig.Sign(key, "TEST_SIGNER_ONLY", payload, nil)
	require.NoError(t, err)
	require.NotEmpty(t, sig)

	// Verify should fail because no verifier is registered
	err = dsig.Verify(key, "TEST_SIGNER_ONLY", payload, sig)
	require.Error(t, err)
}

func TestCustomRegisterVerifierOnly(t *testing.T) {
	registerTestCustomAlgorithm(t, "TEST_VERIFIER_ONLY", nil, testVerifier{})

	key := []byte("test-secret-key")
	payload := []byte("hello world")

	// Sign should fail because no signer is registered
	_, err := dsig.Sign(key, "TEST_VERIFIER_ONLY", payload, nil)
	require.Error(t, err)
}

func TestCustomRegisterBothNil(t *testing.T) {
	err := dsig.RegisterAlgorithm("TEST_BOTH_NIL", dsig.AlgorithmInfo{
		Family: dsig.Custom,
		Meta: dsig.CustomFamilyMeta{
			Signer:   nil,
			Verifier: nil,
		},
	})
	require.Error(t, err)
}

func TestCustomRegisterWrongMeta(t *testing.T) {
	err := dsig.RegisterAlgorithm("TEST_WRONG_META", dsig.AlgorithmInfo{
		Family: dsig.Custom,
		Meta:   "not a CustomFamilyMeta",
	})
	require.Error(t, err)
}

func TestRegisterDuplicate(t *testing.T) {
	registerTestCustomAlgorithm(t, "TEST_DUPLICATE", testSigner{}, testVerifier{})

	// Re-registration should fail
	err := dsig.RegisterAlgorithm("TEST_DUPLICATE", dsig.AlgorithmInfo{
		Family: dsig.Custom,
		Meta: dsig.CustomFamilyMeta{
			Signer:   testSigner{},
			Verifier: testVerifier{},
		},
	})
	require.Error(t, err)
}

func TestUnregisterAndReregister(t *testing.T) {
	registerTestCustomAlgorithm(t, "TEST_UNREG", testSigner{}, testVerifier{})

	err := dsig.UnregisterAlgorithm("TEST_UNREG")
	require.NoError(t, err)

	// After unregister, Sign should fail
	_, err = dsig.Sign([]byte("key"), "TEST_UNREG", []byte("payload"), nil)
	require.Error(t, err)

	// Re-registration should succeed
	err = dsig.RegisterAlgorithm("TEST_UNREG", dsig.AlgorithmInfo{
		Family: dsig.Custom,
		Meta: dsig.CustomFamilyMeta{
			Signer:   testSigner{},
			Verifier: testVerifier{},
		},
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = dsig.UnregisterAlgorithm("TEST_UNREG")
	})
}

func TestUnregisterBuiltinAlgorithm(t *testing.T) {
	err := dsig.UnregisterAlgorithm(dsig.HMACWithSHA256)
	require.Error(t, err)
}

func TestUnregisterNonexistent(t *testing.T) {
	// Should be a no-op, no error
	err := dsig.UnregisterAlgorithm("DOES_NOT_EXIST")
	require.NoError(t, err)
}
