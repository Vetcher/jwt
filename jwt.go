// Package jwt is a barebones JWT implementation that supports just the bare necessities.
package jwt

// Header contains important information for encrypting / decrypting
type Header struct {
	Typ string // Token Type
	Alg string // Message Authentication Code Algorithm - The issuer can freely set an algorithm to verify the signature on the token. However, some asymmetrical algorithms pose security concerns
	Cty string // Content Type - This claim should always be JWT
}
