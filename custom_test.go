package dsig_test

import (
	"crypto"
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

// ctxOpts encodes a "context" in the per-call opts that the test custom
// signer mixes into its MAC. This stands in for the real ML-DSA
// context-string parameter.
type ctxOpts struct {
	context []byte
}

func (ctxOpts) HashFunc() crypto.Hash { return 0 }

// optsAwareSigner implements both Signer/Verifier (so the plain Sign /
// Verify paths still work) and SignerWithOpts/VerifierWithOpts (so the
// dispatcher can route per-call opts through). The opts byte slice is
// prepended to the MAC input — that way a signature produced with one
// context will not verify under another, mirroring the real ML-DSA
// domain-separation behavior.
type optsAwareSigner struct{}

func (optsAwareSigner) macKey(key any) ([]byte, error) {
	k, ok := key.([]byte)
	if !ok {
		return nil, dsig.NewVerificationError("invalid key type")
	}
	return k, nil
}

func (s optsAwareSigner) signWithCtx(key any, payload, ctx []byte) ([]byte, error) {
	k, err := s.macKey(key)
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, k)
	mac.Write(ctx)
	mac.Write([]byte{0})
	mac.Write(payload)
	return mac.Sum(nil), nil
}

func (s optsAwareSigner) verifyWithCtx(key any, payload, sig, ctx []byte) error {
	want, err := s.signWithCtx(key, payload, ctx)
	if err != nil {
		return err
	}
	if !hmac.Equal(want, sig) {
		return dsig.NewVerificationError("signature mismatch")
	}
	return nil
}

func (s optsAwareSigner) Sign(key any, payload []byte, _ io.Reader) ([]byte, error) {
	return s.signWithCtx(key, payload, nil)
}

func (s optsAwareSigner) Verify(key any, payload, sig []byte) error {
	return s.verifyWithCtx(key, payload, sig, nil)
}

func (s optsAwareSigner) SignWithOpts(key any, payload []byte, opts crypto.SignerOpts, _ io.Reader) ([]byte, error) {
	var ctx []byte
	if o, ok := opts.(ctxOpts); ok {
		ctx = o.context
	}
	return s.signWithCtx(key, payload, ctx)
}

func (s optsAwareSigner) VerifyWithOpts(key any, payload, sig []byte, opts crypto.SignerOpts) error {
	var ctx []byte
	if o, ok := opts.(ctxOpts); ok {
		ctx = o.context
	}
	return s.verifyWithCtx(key, payload, sig, ctx)
}

func TestSignWithOptsRoutesToOptsAwareSigner(t *testing.T) {
	const algName = "TEST_OPTS_AWARE"
	registerTestCustomAlgorithm(t, algName, optsAwareSigner{})

	key := []byte("secret")
	payload := []byte("hello")
	opts := ctxOpts{context: []byte("CTX-A")}

	// SignWithOpts must call the SignerWithOpts path.
	sig, err := dsig.SignWithOpts(key, algName, payload, opts, nil)
	require.NoError(t, err, "SignWithOpts")

	// Same opts must verify.
	require.NoError(t, dsig.VerifyWithOpts(key, algName, payload, sig, opts), "VerifyWithOpts with matching ctx")

	// Different context must fail — proves the opts are flowing through.
	require.Error(t,
		dsig.VerifyWithOpts(key, algName, payload, sig, ctxOpts{context: []byte("CTX-B")}),
		"VerifyWithOpts with different ctx must fail",
	)

	// Plain Verify (no opts) corresponds to ctx=nil and must also fail
	// because the signature was computed with CTX-A.
	require.Error(t, dsig.Verify(key, algName, payload, sig), "plain Verify must fail when sig was produced with non-empty ctx")
}

// signerOnlyNoOpts implements only the plain Signer interface. SignWithOpts
// must fall back to Sign and silently drop the opts argument.
type signerOnlyNoOpts struct{}

func (signerOnlyNoOpts) Sign(key any, payload []byte, _ io.Reader) ([]byte, error) {
	k, ok := key.([]byte)
	if !ok {
		return nil, dsig.NewVerificationError("invalid key type")
	}
	mac := hmac.New(sha256.New, k)
	mac.Write(payload)
	return mac.Sum(nil), nil
}

func (signerOnlyNoOpts) Verify(key any, payload, sig []byte) error {
	want, err := signerOnlyNoOpts{}.Sign(key, payload, nil)
	if err != nil {
		return err
	}
	if !hmac.Equal(want, sig) {
		return dsig.NewVerificationError("signature mismatch")
	}
	return nil
}

func TestSignWithOptsFallsBackToPlainSigner(t *testing.T) {
	const algName = "TEST_PLAIN_FALLBACK"
	registerTestCustomAlgorithm(t, algName, signerOnlyNoOpts{})

	key := []byte("secret")
	payload := []byte("hello")

	// Even though we pass non-nil opts, the plain Sign path is called
	// because signerOnlyNoOpts does not implement SignerWithOpts. The
	// resulting signature must verify under both VerifyWithOpts (which
	// also falls back) and plain Verify.
	sig, err := dsig.SignWithOpts(key, algName, payload, ctxOpts{context: []byte("ignored")}, nil)
	require.NoError(t, err, "SignWithOpts fallback")

	require.NoError(t, dsig.VerifyWithOpts(key, algName, payload, sig, ctxOpts{context: []byte("also-ignored")}),
		"VerifyWithOpts fallback")
	require.NoError(t, dsig.Verify(key, algName, payload, sig),
		"plain Verify after SignWithOpts fallback")
}
