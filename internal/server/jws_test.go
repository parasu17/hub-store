package server

import (
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
	_, err := createNewAccessToken("", "", "", "", "", nil)
	require.Error(t, err)
	require.Equal(t, "Failed to create new signer for new access token JWS: square/go-jose: unsupported key type/format", err.Error())
}

func TestValidateAccessToken(t *testing.T) {
	kp := &crypto.KeyProviderFromFile{PrivKeyPath: "../../tests/keys/did-client/ec-key.pem"}
	pvKey, _ := kp.GetPrivateKey()
	key := jose.SigningKey{Algorithm: jose.ES256, Key: pvKey}
	var signerOpts = jose.SignerOptions{NonceSource: staticNonceSource("nonce")} // using passed in nonce
	signer, _ := jose.NewSigner(key, signerOpts.WithType("JWT"))
	builder := jwt.Signed(signer)

	issuedTime := time.Now().UTC()
	expiryTime := issuedTime.Add(5 * time.Minute)
	claims := jwt.Claims{
		Issuer:    "issuer",
		Subject:   "subject",
		ID:        "id",
		Audience:  jwt.Audience{"aud"},
		NotBefore: jwt.NewNumericDate(issuedTime),
		IssuedAt:  jwt.NewNumericDate(issuedTime),
		Expiry:    jwt.NewNumericDate(expiryTime),
	}
	tok, _ := builder.Claims(claims).CompactSerialize()
	authJWT, _ := jwt.ParseSigned(tok)
	err := validateAccessToken(authJWT, pvKey, "subject", "id", "aud")
	require.Error(t, err)
}

func TestEncryptJWSWithWrongEncAlgorithm(t *testing.T) {
	kp := &crypto.KeyProviderFromFile{PubKeyPath: "../../tests/keys/did-server/ec-pubKey.pem"}
	pubKey, _ := kp.GetPublicKey()
	_, err := encryptJWS("test", pubKey, "ECDH-ES", "A128GCM-wrong")
	require.Error(t, err)
}
