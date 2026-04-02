package examples_test

import (
	"crypto/hmac"
	"crypto/sha512"
	"fmt"
	"io"

	"github.com/lestrrat-go/dsig"
)

// hmac512Signer implements dsig.Signer using HMAC-SHA512.
type hmac512Signer struct{}

func (hmac512Signer) Sign(key any, payload []byte, _ io.Reader) ([]byte, error) {
	k, ok := key.([]byte)
	if !ok {
		return nil, fmt.Errorf("expected []byte key, got %T", key)
	}
	mac := hmac.New(sha512.New, k)
	mac.Write(payload)
	return mac.Sum(nil), nil
}

// hmac512Verifier implements dsig.Verifier using HMAC-SHA512.
type hmac512Verifier struct{}

func (hmac512Verifier) Verify(key any, payload, signature []byte) error {
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

	// Register a custom algorithm with its own sign/verify implementations
	err := dsig.RegisterAlgorithm(algName, dsig.AlgorithmInfo{
		Family: dsig.Custom,
		Meta: dsig.CustomFamilyMeta{
			Signer:   hmac512Signer{},
			Verifier: hmac512Verifier{},
		},
	})
	if err != nil {
		fmt.Printf("register: %v\n", err)
		return
	}
	defer dsig.UnregisterAlgorithm(algName)

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
