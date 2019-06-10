/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package server

import (
	"crypto/ecdsa"
	"fmt"
	"time"

	"github.com/trustbloc/hub-store/internal/crypto"

	"github.com/pkg/errors"
	"github.com/square/go-jose"
	"github.com/square/go-jose/jwt"
)

type staticNonceSource string

func (sns staticNonceSource) Nonce() (string, error) {
	return string(sns), nil
}

// createNewAccessToken will generate a new access token with the given nonce and using publicKey
func createNewAccessToken(nonce, subject string, pvKey *ecdsa.PrivateKey) (string, error) {
	// for now creating keys with ECDSA using P-256 and SHA-256
	key := jose.SigningKey{Algorithm: jose.ES256, Key: pvKey}
	var signerOpts = jose.SignerOptions{NonceSource: staticNonceSource(nonce)} // using passed in nonce
	signerOpts.WithType("JWT")

	signer, err := jose.NewSigner(key, &signerOpts)
	if err != nil {
		return "", errors.Wrapf(err, "Failed to create new signer for new access token JWS")
	}

	builder := jwt.Signed(signer)

	issuedTime := time.Now().UTC()
	expiryTime := issuedTime.Add(5 * time.Minute)
	claims := jwt.Claims{
		Issuer:    HubIssuerID,
		Subject:   subject,
		ID:        "id", // TODO: to create a generated id
		Audience:  jwt.Audience{HubIssuerID},
		NotBefore: jwt.NewNumericDate(issuedTime),
		IssuedAt:  jwt.NewNumericDate(issuedTime),
		Expiry:    jwt.NewNumericDate(expiryTime),
	}

	return builder.Claims(claims).CompactSerialize()
}

func validateAccessToken(accessToken *jwt.JSONWebToken, ecKey *ecdsa.PrivateKey, subject string) error {
	resultClaims := jwt.Claims{}
	err := accessToken.Claims(&ecKey.PublicKey, &resultClaims)
	if err != nil {
		return err
	}

	err = resultClaims.Validate(jwt.Expected{
		Issuer:   HubIssuerID,
		Audience: jwt.Audience{HubIssuerID},
		Subject:  subject,
		ID:       "id", // TODO: To validate against generated ID
		Time:     time.Now().UTC(),
	})
	if err != nil {
		return errors.Wrapf(err, "Access Token validation failed")
	}
	return nil
}

// validateJWSHeader will validate the JWS header. It must be called before validateJWS()
func validateJWSHeader(jws *jose.JSONWebSignature, publicKey interface{}) ([]byte, error) {
	_, _, verifiedPayload, err := jws.VerifyMulti(publicKey)
	if err != nil {
		return nil, errors.Wrapf(err, "Crypto [Warning]: could not verify JWS")
	}

	// validate nonce
	nonce, ok := jws.Signatures[0].Header.ExtraHeaders[jose.HeaderKey(DidAccessNonceKey)]
	if !ok || nonce == "" {
		return nil, errors.New("Crypto [Warning]: Invalid token - missing nonce")
	}
	return verifiedPayload, nil
}

// validateJWS will validate the did-access-token in the JWS message. It will create a new token if not found.
// this call assumes validateJWSHeader() was called and returned a successful AuthenticationResult
func validateJWS(jws *jose.JSONWebSignature, pvKey interface{}) (string, bool, error) {
	var key *ecdsa.PrivateKey
	var ok bool
	if key, ok = pvKey.(*ecdsa.PrivateKey); !ok {
		return "", false, errors.New("Only private keys of type ECDSA is supported")
	}
	kid := jws.Signatures[0].Header.KeyID

	accessTokenJwe := jws.Signatures[0].Header.ExtraHeaders[jose.HeaderKey(DidAccessTokenKey)]
	accessTknJweStr := fmt.Sprintf("%v", accessTokenJwe) // convert interface{} to string

	// for existing access token, return it back as is along with IsNewToken=false
	if accessTokenJwe != nil && accessTknJweStr != "" {
		authJWT, err := jwt.ParseSigned(accessTknJweStr)
		if err != nil {
			return "", false, errors.Wrapf(err, "Crypto [Warning]: could not parse Access Token")
		}

		err = validateAccessToken(authJWT, key, kid)
		if err != nil {
			return "", false, err
		}
		// since VerifyMulti is called before this function and hence the payload is already verified
		// against it's signature. Hence we just take the payload.
		return accessTknJweStr, false, nil
	}

	// else create new token, return it along with IsNewToken=true
	nonce := jws.Signatures[0].Header.ExtraHeaders[jose.HeaderKey(DidAccessNonceKey)]

	accessTknJweStr, err := createNewAccessToken(
		fmt.Sprintf("%v", nonce),
		kid,
		key)
	if err != nil {
		return "", false, errors.Wrapf(err, "Crypto [Warning]: could not create Access Token")
	}

	return accessTknJweStr, true, nil
}

// GetJWS creates a JSON Web signature object from the payload
func GetJWS(headerAttrs map[string]interface{}, payload string, algStr string, kp crypto.KeyProvider) (*jose.JSONWebSignature, error) {
	signingKey, err := kp.GetPrivateKey()
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to load Private Key")
	}
	alg := jose.SignatureAlgorithm(algStr)
	signerOpts := &jose.SignerOptions{}
	for k, v := range headerAttrs {
		signerOpts.WithHeader(jose.HeaderKey(k), v)
	}

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: signingKey}, signerOpts)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to create new Signer")
	}
	// now sign a payload (JWT) to create a JWS and its serialized version
	jws, err := signer.Sign([]byte(payload))
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to Sign JWT into JWS")
	}
	return jws, nil
}

// CompactSerialize signs a payload (any string format) with the given privateKeyPath and alg.
// Returns a serialized JWS string
func CompactSerialize(headerAttrs map[string]interface{}, payload string, algStr string, kp crypto.KeyProvider) (string, error) {
	jws, err := GetJWS(headerAttrs, payload, algStr, kp)
	if err != nil {
		return "", err
	}
	serializedJws, err := jws.CompactSerialize()
	if err != nil {
		return "", errors.Wrapf(err, "Failed to serialize JWS")
	}

	return serializedJws, err
}

// encryptJWS will encrypt serializedJws (serialized JWS) with publicKeyPath key using algStr key algorithm and encStr content encryption.
// Returns a serialized JWE string
func encryptJWS(serializedJws string, encryptingKey interface{}, algStr, encStr string) (string, error) {
	crypter, err := jose.NewEncrypter(
		jose.ContentEncryption(encStr),
		jose.Recipient{
			Algorithm: jose.KeyAlgorithm(algStr),
			Key:       encryptingKey}, nil)
	if err != nil {
		return "", errors.Wrapf(err, "Failed to get new Encrypter")
	}
	// now encrypt the serialized JWS into a JWE and its serialized version
	jwe, err := crypter.Encrypt([]byte(serializedJws))
	if err != nil {
		return "", errors.Wrapf(err, "Failed to Encrypt JWS into JWE")
	}
	authToken, err := jwe.CompactSerialize()
	if err != nil {
		return "", errors.Wrapf(err, "Failed to serialized JWE")
	}

	return authToken, nil
}
