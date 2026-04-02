package dsig_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"io"
	"testing"

	"github.com/lestrrat-go/dsig"
	"github.com/stretchr/testify/require"
)

// testCustomAlgorithm implements both dsig.Signer and dsig.Verifier using HMAC-SHA256.
type testCustomAlgorithm struct{}

func (testCustomAlgorithm) Sign(key any, payload []byte, _ io.Reader) ([]byte, error) {
	k, ok := key.([]byte)
	if !ok {
		return nil, dsig.NewVerificationError("invalid key type")
	}
	mac := hmac.New(sha256.New, k)
	mac.Write(payload)
	return mac.Sum(nil), nil
}

func (testCustomAlgorithm) Verify(key any, payload, signature []byte) error {
	k, ok := key.([]byte)
	if !ok {
		return dsig.NewVerificationError("invalid key type")
	}
	mac := hmac.New(sha256.New, k)
	mac.Write(payload)
	if !hmac.Equal(mac.Sum(nil), signature) {
		return dsig.NewVerificationError("signature mismatch")
	}
	return nil
}

// testSignerOnly implements only dsig.Signer.
type testSignerOnly struct{}

func (testSignerOnly) Sign(key any, payload []byte, _ io.Reader) ([]byte, error) {
	k, ok := key.([]byte)
	if !ok {
		return nil, dsig.NewVerificationError("invalid key type")
	}
	mac := hmac.New(sha256.New, k)
	mac.Write(payload)
	return mac.Sum(nil), nil
}

// testVerifierOnly implements only dsig.Verifier.
type testVerifierOnly struct{}

func (testVerifierOnly) Verify(key any, payload, signature []byte) error {
	k, ok := key.([]byte)
	if !ok {
		return dsig.NewVerificationError("invalid key type")
	}
	mac := hmac.New(sha256.New, k)
	mac.Write(payload)
	if !hmac.Equal(mac.Sum(nil), signature) {
		return dsig.NewVerificationError("signature mismatch")
	}
	return nil
}

const testCustomAlgName = "TEST_CUSTOM_ALG"

func registerTestCustomAlgorithm(t *testing.T, name string, meta any) {
	t.Helper()
	err := dsig.RegisterAlgorithm(name, dsig.AlgorithmInfo{
		Family: dsig.Custom,
		Meta:   meta,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = dsig.UnregisterAlgorithm(name)
	})
}

func TestCustomSignVerify(t *testing.T) {
	registerTestCustomAlgorithm(t, testCustomAlgName, testCustomAlgorithm{})

	key := []byte("test-secret-key")
	payload := []byte("hello world")

	sig, err := dsig.Sign(key, testCustomAlgName, payload, nil)
	require.NoError(t, err)

	err = dsig.Verify(key, testCustomAlgName, payload, sig)
	require.NoError(t, err)

	// Tampered signature should fail
	sig[0] ^= 0xff
	err = dsig.Verify(key, testCustomAlgName, payload, sig)
	require.Error(t, err)
}

func TestCustomRegisterSignerOnly(t *testing.T) {
	registerTestCustomAlgorithm(t, "TEST_SIGNER_ONLY", testSignerOnly{})

	key := []byte("test-secret-key")
	payload := []byte("hello world")

	sig, err := dsig.Sign(key, "TEST_SIGNER_ONLY", payload, nil)
	require.NoError(t, err)
	require.NotEmpty(t, sig)

	// Verify should fail because Meta does not implement Verifier
	err = dsig.Verify(key, "TEST_SIGNER_ONLY", payload, sig)
	require.Error(t, err)
}

func TestCustomRegisterVerifierOnly(t *testing.T) {
	registerTestCustomAlgorithm(t, "TEST_VERIFIER_ONLY", testVerifierOnly{})

	key := []byte("test-secret-key")
	payload := []byte("hello world")

	// Sign should fail because Meta does not implement Signer
	_, err := dsig.Sign(key, "TEST_VERIFIER_ONLY", payload, nil)
	require.Error(t, err)
}

func TestCustomRegisterNoInterface(t *testing.T) {
	// Meta implements neither Signer nor Verifier
	err := dsig.RegisterAlgorithm("TEST_NO_IFACE", dsig.AlgorithmInfo{
		Family: dsig.Custom,
		Meta:   "not an implementation",
	})
	require.Error(t, err)
}

func TestRegisterDuplicate(t *testing.T) {
	registerTestCustomAlgorithm(t, "TEST_DUPLICATE", testCustomAlgorithm{})

	err := dsig.RegisterAlgorithm("TEST_DUPLICATE", dsig.AlgorithmInfo{
		Family: dsig.Custom,
		Meta:   testCustomAlgorithm{},
	})
	require.Error(t, err)
}

func TestUnregisterAndReregister(t *testing.T) {
	registerTestCustomAlgorithm(t, "TEST_UNREG", testCustomAlgorithm{})

	err := dsig.UnregisterAlgorithm("TEST_UNREG")
	require.NoError(t, err)

	// After unregister, Sign should fail
	_, err = dsig.Sign([]byte("key"), "TEST_UNREG", []byte("payload"), nil)
	require.Error(t, err)

	// Re-registration should succeed
	err = dsig.RegisterAlgorithm("TEST_UNREG", dsig.AlgorithmInfo{
		Family: dsig.Custom,
		Meta:   testCustomAlgorithm{},
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
	err := dsig.UnregisterAlgorithm("DOES_NOT_EXIST")
	require.NoError(t, err)
}
