// Package dsig provides digital signature operations for Go.
// It contains low-level signature generation and verification tools that
// can be used by other signing libraries
//
// The package follows these design principles:
// 1. Does minimal checking of input parameters (for performance); callers need to ensure that the parameters are valid.
// 2. All exported functions are strongly typed (i.e. they do not take `any` types unless they absolutely have to).
// 3. Does not rely on other high-level packages (standalone, except for internal packages).
package dsig

