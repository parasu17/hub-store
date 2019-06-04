package server

import (
	"crypto/ecdsa"
	"testing"
	"time"

	"github.com/square/go-jose"
	"github.com/square/go-jose/jwt"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/hub-store/internal/crypto"
)

func TestGetJWSForInvalidAlgorithm(t *testing.T) {
	headerAttrs := make(map[string]interface{})
	_, err := GetJWS(headerAttrs, "payload", "Invalid-ES256",
		&crypto.KeyProviderFromFile{PrivKeyPath: "../../tests/keys/did-client/ec-key.pem"})
	require.Error(t, err)
	require.Equal(t, "Failed to create new Signer: square/go-jose: unknown/unsupported algorithm", err.Error())
}

func TestCreateNewAccessToken(t *testing.T) {
	_, err := createNewAccessToken("", "", nil)
	require.Error(t, err)
	require.Equal(t, "Failed to create new signer for new access token JWS: invalid private key", err.Error())
}

func TestValidateAccessToken(t *testing.T) {
	kp := &crypto.KeyProviderFromFile{PrivKeyPath: "../../tests/keys/did-client/ec-key.pem"}
	pvKey, _ := kp.GetPrivateKey()
	ecdsaKey := pvKey.(*ecdsa.PrivateKey)
	key := jose.SigningKey{Algorithm: jose.ES256, Key: ecdsaKey}
	var signerOpts = jose.SignerOptions{NonceSource: staticNonceSource("nonce")} // using passed in nonce
	signer, _ := jose.NewSigner(key, signerOpts.WithType("JWT"))
	builder := jwt.Signed(signer)

	issuedTime := time.Now().UTC()
	expiryTime := issuedTime.Add(5 * time.Minute)
	claims := jwt.Claims{
		Issuer:    "Issuer", // the Issuer is given wrong
		Subject:   "subject",
		ID:        "id",
		Audience:  jwt.Audience{HubIssuerID},
		NotBefore: jwt.NewNumericDate(issuedTime),
		IssuedAt:  jwt.NewNumericDate(issuedTime),
		Expiry:    jwt.NewNumericDate(expiryTime),
	}
	tok, _ := builder.Claims(claims).CompactSerialize()
	authJWT, _ := jwt.ParseSigned(tok)
	err := validateAccessToken(authJWT, ecdsaKey, "subject")
	require.Error(t, err)
}

func TestEncryptJWSWithWrongEncAlgorithm(t *testing.T) {
	kp := &crypto.KeyProviderFromFile{PubKeyPath: "../../tests/keys/did-server/ec-pubKey.pem"}
	pubKey, _ := kp.GetPublicKey()
	_, err := encryptJWS("test", pubKey, "ECDH-ES", "A128GCM-wrong")
	require.Error(t, err)
}
