/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package server

import (
	"github.com/pkg/errors"
	"github.com/square/go-jose"
	"github.com/trustbloc/hub-store/internal/crypto"
)

const (

	// DidAccessTokenKey is the JWS Header key for the DID Access Token
	DidAccessTokenKey = "did-access-token"

	// DidAccessNonceKey is the JWS Header key for the client's nonce
	DidAccessNonceKey = "did-requester-nonce"

	// KidKey is the did fragment which is pointing to the public key in the DID doc
	KidKey = "kid"

	// HubIssuerID represents the ID of the hub (TODO: in the future this should be made configurable for each instance)
	HubIssuerID = "did:hub:id"
)

// Authenticator authenticates the JWE message
type Authenticator struct {
	KeyProvider crypto.KeyProvider
}

// AuthenticationResult is the authentication validation result returned by Authenticate() call
type AuthenticationResult struct {
	// AccessToken is the 'did-access-token' JWS header content of the HTTP request
	AccessToken string
	// IsNewToken states if 'did-access-token' JWS header was empty in the client http request (false) or not (true, ie newly generated token by the server)
	IsNewToken bool
	// Payload holds the verified payload of the request
	Payload string
}

// Authenticate will take a JWE Base64URL encoded as a string argument and will do the following steps in order:
// 1. Base64Url Decode the JWE string
// 2. Will decrypt the JWE using the server's private key to get a signed JWS
// 3. Will verify the JWS signature(s) using the client's public key pulled from the received (resolved) DID's kid
// 4. once verified, the rest of the JWT token will be verified by reading 'did-access-token' JWS header and validating it, ie token issuer, expiry and nonce
// 5. if 'did-access-token' JWS header is missing, the function must return a new token to be returned to the client for future requests.
// 6. The payload is then parsed to create the Request object.
// returns:
// 1. AuthenticationResult that has 2 fields:
// 		a. accessToken to be sent back to the client
// 		b. bool to state if access token is created by server (new token returns true) or read from 'did-access-token' header (existing token returns false)
// 2. The actual Request object
// 2. error to indicate if authentication failed
func (a *Authenticator) Authenticate(jweStr string) (*AuthenticationResult, error) {
	jwe, err := jose.ParseEncrypted(jweStr)
	if err != nil {
		return nil, errors.Wrapf(err, "Crypto [Warning]: could not parse JWE")
	}

	pvKey, err := a.KeyProvider.GetPrivateKey()
	if err != nil {
		return nil, err
	}

	jweDecr, err := jwe.Decrypt(pvKey)
	if err != nil {
		return nil, errors.Wrapf(err, "Crypto [Warning]: could not decrypt JWE")
	}

	jws, err := jose.ParseSigned(string(jweDecr))
	if err != nil {
		return nil, errors.Wrapf(err, "Crypto [Warning]: could not decrypt JWE: square/go-jose: error in cryptographic primitive")
	}

	publicKey, err := a.KeyProvider.GetRemotePublicKey(jws.Signatures[0].Header.KeyID)
	if err != nil {
		return nil, err
	}

	verifiedPayload, err := validateJWSHeader(jws, publicKey)
	if err != nil {
		return nil, err
	}

	accessToken, newToken, err := validateJWS(jws, pvKey)
	if err != nil {
		return nil, err
	}

	return &AuthenticationResult{
		AccessToken: accessToken,
		IsNewToken:  newToken,
		Payload:     string(verifiedPayload),
	}, nil
}
