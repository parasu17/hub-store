package crypto

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/square/go-jose"
	"github.com/stretchr/testify/require"
)

func TestKeyProviderFromFile(t *testing.T) {
	plainText := "This is the plain text which needs to be encrypted."
	encryptKey := &KeyProviderFromFile{PubKeyPath: "../../tests/keys/did-server/ec-pubKey.pem"}
	encryptingKey, err := encryptKey.GetPublicKey()
	require.NoError(t, err, "Failed to load public key")

	crypter, err := jose.NewEncrypter(
		jose.ContentEncryption("A128GCM"),
		jose.Recipient{
			Algorithm: jose.KeyAlgorithm("ECDH-ES"),
			Key:       encryptingKey,
		},
		nil)
	require.NoError(t, err, "Failed to get new Encrypter")

	// now encrypt the serialized JWS into a JWE and its serialized version
	jwe, err := crypter.Encrypt([]byte(plainText))
	require.NoError(t, err, "Failed to Encrypt JWS into JWE")
	cryptText, err := jwe.CompactSerialize()
	require.NoError(t, err, "Failed to serialized JWE")

	// Decrypt the encrypted JWE
	decryptKey := &KeyProviderFromFile{PrivKeyPath: "../../tests/keys/did-server/ec-key.pem"}
	parsedJWE, err := jose.ParseEncrypted(cryptText)
	require.NoError(t, err, fmt.Sprintf("Error parsing the encrypted text; err=%s", err))

	pvKey, err := decryptKey.GetPrivateKey()
	require.NoError(t, err, fmt.Sprintf("Error getting the private key; err=%s", err))

	jweDecr, err := parsedJWE.Decrypt(pvKey)
	require.NoError(t, err, fmt.Sprintf("Error decrypting the text; err=%s", err))

	// validate the payload
	require.Equal(t, plainText, string(jweDecr))
}

func TestCachingOfParsedKeys(t *testing.T) {
	pubKeyPath := "../../tests/keys/did-client/ec-pubKey.pem"
	privKeyPath := "../../tests/keys/did-server/ec-key.pem"

	newPubPath := pubKeyPath + ".copy"
	newPrivPath := privKeyPath + ".copy"

	kp := &KeyProviderFromFile{
		PubKeyPath:  newPubPath,
		PrivKeyPath: newPrivPath,
	}
	copyFile(t, pubKeyPath, newPubPath)
	copyFile(t, privKeyPath, newPrivPath)
	// This is just to be careful that it does not leave behind these files once test is done
	defer deleteFile(t, newPubPath, newPrivPath)

	pk, err := kp.GetPrivateKey()
	require.Nil(t, err)
	require.NotNil(t, pk)

	// delete the privKeyFile.copy
	deleteFile(t, newPrivPath)
	// do it once again, so that it picks from the cache
	pk, err = kp.GetPrivateKey()
	require.Nil(t, err)
	require.NotNil(t, pk)

	pk, err = kp.GetPublicKey()
	require.Nil(t, err)
	require.NotNil(t, pk)

	// delete the publicKey.copy
	deleteFile(t, newPubPath)

	// do it once again, so that it picks from the cache
	pk, err = kp.GetPublicKey()
	require.Nil(t, err)
	require.NotNil(t, pk)
}

func TestWrongPaths(t *testing.T) {
	pubPath := "../../tests/keys/did-client/ec-pubKey.pem.wrong"
	privPath := "../../tests/keys/did-server/ec-key.pem.wrong"
	kp := &KeyProviderFromFile{
		PubKeyPath:  pubPath,
		PrivKeyPath: privPath,
	}

	pk, err := kp.GetPrivateKey()
	require.Nil(t, pk)
	require.NotNil(t, err)
	errMsg := fmt.Sprintf("Crypto [Warning]: could not read private Key: open %s: no such file or directory", privPath)
	require.Equal(t, errMsg, err.Error())

	pk, err = kp.GetPublicKey()
	require.Nil(t, pk)
	require.NotNil(t, err)
	errMsg = fmt.Sprintf("Crypto [Warning]: could not read public Key: open %s: no such file or directory", pubPath)
	require.Equal(t, errMsg, err.Error())
}

func TestMalformattedKeys(t *testing.T) {
	origPubPath := "../../tests/keys/did-client/ec-pubKey.pem"
	origPrivPath := "../../tests/keys/did-server/ec-key.pem"
	wrongPubPath := origPubPath + ".wrong.key"
	wrongPrivPath := origPrivPath + ".wrong.key"
	kp := &KeyProviderFromFile{
		PubKeyPath:  wrongPubPath,
		PrivKeyPath: wrongPrivPath,
	}
	changeFileContentAndPersist(t, origPubPath, wrongPubPath)
	defer deleteFile(t, wrongPubPath)
	changeFileContentAndPersist(t, origPrivPath, wrongPrivPath)
	defer deleteFile(t, wrongPrivPath)

	privKey, err := kp.GetPrivateKey()
	require.Nil(t, privKey)
	require.NotNil(t, err)
	require.True(t, strings.HasPrefix(err.Error(), "Crypto [Warning]: could not parse private Key"))

	pubKey, err := kp.GetPublicKey()
	require.Nil(t, pubKey)
	require.NotNil(t, err)
	require.True(t, strings.HasPrefix(err.Error(), "Crypto [Warning]: could not parse public Key"))
}

func copyFile(t *testing.T, origFile, newFile string) {
	keyBytes, err := ioutil.ReadFile(filepath.Clean(origFile))
	require.NoError(t, err)
	err = ioutil.WriteFile(newFile, keyBytes, 0755)
	require.NoError(t, err)
}

func changeFileContentAndPersist(t *testing.T, origFile, newFile string) {
	keyBytes, err := ioutil.ReadFile(filepath.Clean(origFile))
	require.Nil(t, err)
	err = ioutil.WriteFile(newFile, keyBytes[0:len(keyBytes)/2], 0755)
	require.Nil(t, err)
}

func deleteFile(t *testing.T, fileNames ...string) {
	for i := 0; i < len(fileNames); i++ {
		if _, err := os.Stat(fileNames[i]); err == nil {
			_ = os.Remove(fileNames[i])
		}
	}
}
