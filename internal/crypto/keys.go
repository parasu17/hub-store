package crypto

import (
	"fmt"
	"io/ioutil"
	"path/filepath"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

var logger = logrus.New()

// KeyProvider is a common interface which provides the public/private keys
type KeyProvider interface {
	GetPrivateKey() (interface{}, error)
	GetPublicKey() (interface{}, error)
	GetRemotePublicKey(keyID string) (interface{}, error)
}

// KeyProviderFromFile is an implementation of KeyProvider interface which
// reads the keys from files
type KeyProviderFromFile struct {
	PrivKeyPath  string
	PubKeyPath   string
	BasePath     string
	pvtKey       interface{}
	pubKey       interface{}
	publicKeyMap map[string]interface{}
}

// AddPublicKeyPath adds the keyID-publicKey pair to this provider
// If it is an unknown path or if the file is corrupted then an error is returned
func (p *KeyProviderFromFile) AddPublicKeyPath(keyID, publicKeyPath string) error {
	publicKey, err := p.getPublicKeyFromFile(publicKeyPath)
	if err == nil {
		if p.publicKeyMap == nil {
			p.publicKeyMap = make(map[string]interface{})
		}
		p.publicKeyMap[keyID] = publicKey
		return nil
	}
	return err
}

// GetPrivateKey gets the private key of the server
func (p *KeyProviderFromFile) GetPrivateKey() (interface{}, error) {
	if p.pvtKey != nil {
		return p.pvtKey, nil
	}

	pvKey, err := p.getPrivateKeyFromFile(
		filepath.Join(p.BasePath, filepath.Clean(p.PrivKeyPath)))
	if err != nil {
		return nil, err
	}

	p.pvtKey = pvKey
	return pvKey, nil
}

// GetPublicKey gets the client public key
func (p *KeyProviderFromFile) GetPublicKey() (interface{}, error) {
	if p.pubKey != nil {
		return p.pubKey, nil
	}

	filePath := filepath.Join(p.BasePath, filepath.Clean(p.PubKeyPath))
	pubKey, err := p.getPublicKeyFromFile(filePath)
	if err != nil {
		return nil, err
	}
	p.pubKey = pubKey
	return pubKey, nil
}

// GetRemotePublicKey gets the public key of a remote entity
func (p *KeyProviderFromFile) GetRemotePublicKey(keyID string) (interface{}, error) {
	if p.publicKeyMap != nil {
		if key, ok := p.publicKeyMap[keyID]; ok {
			return key, nil
		}
	}
	return nil, errors.New(fmt.Sprintf("Public Key not found for KeyID=%s", keyID))
}

// getPrivateKeyFromFile gets the private key from a file
func (p *KeyProviderFromFile) getPrivateKeyFromFile(filePath string) (interface{}, error) {
	keyBytes, err := ioutil.ReadFile(filepath.Clean(filePath))
	if err != nil {
		return nil, errors.Wrapf(err, "Crypto [Warning]: could not read private Key")
	}

	pvKey, err := ParsePrivateKey(keyBytes)
	if err != nil {
		return nil, errors.Wrapf(err, "Crypto [Warning]: could not parse private Key")
	}

	return pvKey, nil
}

// getPublicKeyFromFile gets the client public key from a file
func (p *KeyProviderFromFile) getPublicKeyFromFile(filePath string) (interface{}, error) {
	keyBytes, err := ioutil.ReadFile(filepath.Clean(filePath))
	if err != nil {
		logger.Warnf("Crypto [Warning]: could not read client's public key: %+v", err)
		return nil, errors.Wrapf(err, "Crypto [Warning]: could not read public Key")
	}
	pubKey, err := ParsePublicKey(keyBytes)
	if err != nil {
		logger.Warnf("Crypto [Warning]: could not parse public Key: %+v", err)
		return nil, errors.Wrapf(err, "Crypto [Warning]: could not parse public Key")
	}
	return pubKey, nil
}
