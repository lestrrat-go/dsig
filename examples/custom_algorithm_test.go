package examples_test

import (
	"crypto/hmac"
	"crypto/sha512"
	"fmt"
	"io"

	"github.com/lestrrat-go/dsig"
)

// hmac512Algorithm implements both dsig.Signer and dsig.Verifier using HMAC-SHA512.
// The implementation struct carries its own metadata — in this case, none is needed,
// but real implementations could include hash functions, curves, or other parameters.
type hmac512Algorithm struct{}

func (hmac512Algorithm) Sign(key any, payload []byte, _ io.Reader) ([]byte, error) {
	k, ok := key.([]byte)
	if !ok {
		return nil, fmt.Errorf("expected []byte key, got %T", key)
	}
	mac := hmac.New(sha512.New, k)
	mac.Write(payload)
	return mac.Sum(nil), nil
}

func (hmac512Algorithm) Verify(key any, payload, signature []byte) error {
	k, ok := key.([]byte)
	if !ok {
		return fmt.Errorf("expected []byte key, got %T", key)
	}
	mac := hmac.New(sha512.New, k)
	mac.Write(payload)
	if !hmac.Equal(mac.Sum(nil), signature) {
		return dsig.NewVerificationError("signature mismatch")
	}
	return nil
}

func Example_customAlgorithm() {
	const algName = "MY_HMAC_SHA512"

	// Register a custom algorithm — Meta is the implementation itself
	err := dsig.RegisterAlgorithm(algName, dsig.AlgorithmInfo{
		Family: dsig.Custom,
		Meta:   hmac512Algorithm{},
	})
	if err != nil {
		fmt.Printf("register: %v\n", err)
		return
	}
	defer func() {
		_ = dsig.UnregisterAlgorithm(algName)
	}()

	key := []byte("my-secret-key")
	payload := []byte("hello world")

	// Sign using the custom algorithm through dsig.Sign
	sig, err := dsig.Sign(key, algName, payload, nil)
	if err != nil {
		fmt.Printf("sign: %v\n", err)
		return
	}

	// Verify using the custom algorithm through dsig.Verify
	err = dsig.Verify(key, algName, payload, sig)
	if err != nil {
		fmt.Printf("verify: %v\n", err)
		return
	}

	fmt.Println("OK")
	// Output:
	// OK
}
