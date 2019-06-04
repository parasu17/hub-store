/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package server

import (
	"crypto/ecdsa"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/hub-store/internal/crypto"
)

type testCase struct {
	Name              string
	Success           bool
	JwtStr            string
	kp                crypto.KeyProvider
	genNewAccessToken bool
}

var clientPubKey = "/did-client/ec-pubKey.pem"
var clientPrivKey = "/did-client/ec-key.pem"
var serverPubKey = "/did-server/ec-pubKey.pem"
var serverPrivKey = "/did-server/ec-key.pem"
var basePath = "../../tests/keys"

var clientKeys crypto.KeyProvider
var serverKeys crypto.KeyProvider

func init() {
	if clientKeys == nil {
		ck := &crypto.KeyProviderFromFile{
			BasePath:    basePath,
			PubKeyPath:  clientPubKey,
			PrivKeyPath: clientPrivKey,
		}
		ck.AddPublicKeyPath("serverPubKey", basePath+serverPubKey)
		clientKeys = ck
	}
	if serverKeys == nil {
		sk := &crypto.KeyProviderFromFile{
			BasePath:    basePath,
			PubKeyPath:  serverPubKey,
			PrivKeyPath: serverPrivKey,
		}
		sk.AddPublicKeyPath("did:example:123456789abcdefghi#keys-1", basePath+clientPubKey)
		serverKeys = sk
	}
}

func TestValidateJWT(t *testing.T) {
	jweStructs, err := loadJWEs()
	require.NoError(t, err, "Loading JWEs for testing should not fail")
	testCases := []testCase{
		{
			Name:              "Success case for Authentication (create new did access token prior to validate, AuthenticationResult.IsNewToken should be false)",
			Success:           true,
			JwtStr:            jweStructs.validWithNewAuthTkn,
			kp:                serverKeys,
			genNewAccessToken: true,
		}, {
			Name:              "Success case for Authentication (don't create new did access token prior to validate, AuthenticationResult.IsNewToken should be true)",
			Success:           true,
			JwtStr:            jweStructs.validWithoutAuthTkn,
			kp:                serverKeys,
			genNewAccessToken: false,
		}, {
			Name:    "Fail validation with Parse JWE format case",
			Success: false,
			JwtStr:  jweStructs.invalidJWEParse,
			kp:      serverKeys,
		}, {
			Name:    "Fail validation with invalid ID Hub's Private Key case",
			Success: false,
			JwtStr:  jweStructs.invalidPvtKey,
			kp:      &crypto.KeyProviderFromFile{PrivKeyPath: "invalidPath"},
		}, { // must be a non key file to force a parse private key error
			Name:    "Fail validation with Parse ID Hub's Private Key case",
			Success: false,
			JwtStr:  jweStructs.invalidPvtKeyParse,
			kp:      &crypto.KeyProviderFromFile{BasePath: basePath, PubKeyPath: "/did-client/ec-pubKey.pem", PrivKeyPath: "/ec-cacert.pem"},
		}, { // use a different key than ID Hub's server to force a decryption error
			Name:    "Fail validation with invalid JWE decryption case",
			Success: false,
			JwtStr:  jweStructs.invalidJWEDecrypt,
			kp:      &crypto.KeyProviderFromFile{BasePath: basePath, PubKeyPath: "/did-client/ec-pubKey.pem", PrivKeyPath: "/ec-cakey.pem"},
		}, {
			Name:    "Fail validation with invalid JWS parse case",
			Success: false,
			JwtStr:  jweStructs.invalidJWSParse,
			kp:      serverKeys,
		}, { // use a different key than Client's public key to force a signature verification error
			Name:    "Fail validation with JWS signature verification case due to bad client's public key parsing",
			Success: false,
			JwtStr:  jweStructs.invalidJWSVerify,
			kp:      &crypto.KeyProviderFromFile{BasePath: basePath, PubKeyPath: "/ec-cakey.pem", PrivKeyPath: "/did-server/ec-key.pem"},
		}, { // use a different key than Client's public key to force a signature verification error
			Name:    "Fail validation with JWS signature verification case due to wrong public key",
			Success: false,
			JwtStr:  jweStructs.invalidJWSVerify,
			kp:      &crypto.KeyProviderFromFile{BasePath: basePath, PubKeyPath: "/did-server/ec-pubKey.pem", PrivKeyPath: "/did-server/ec-key.pem"},
		}, {
			Name:    "Fail validation with invalid (missing) nonce case",
			Success: false,
			JwtStr:  jweStructs.invalidNonce,
			kp:      serverKeys,
		}, {
			Name:    "Fail validation with invalid (missing) client's public Key ID case",
			Success: false,
			JwtStr:  jweStructs.invalidKid,
			kp:      serverKeys,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			auth := Authenticator{KeyProvider: tc.kp}
			ar, err := auth.Authenticate(tc.JwtStr)
			validateTC(t, tc, ar, err)
		})
	}
}

func validateTC(t *testing.T, tc testCase, authenticationResult *AuthenticationResult, err error) { // nolint: gocyclo
	validateJWTErr := err

	if tc.Success {
		require.NoError(t, validateJWTErr, "expecting Authenticate() to return no error for a valid encrypted and signed JWT string")
		require.NotNil(t, authenticationResult, "expecting Authenticate() to return a non nil result for a valid encrypted and signed JWT string")
		isNewJWTToken := authenticationResult.IsNewToken
		if !tc.genNewAccessToken {
			require.True(t, isNewJWTToken, "expecting to generate a new did access token")
			return
		}
		require.False(t, isNewJWTToken, "not expecting to generate a new did access token")
		return
	}
	require.Nil(t, authenticationResult, "expecting Authenticate() to return a nil result")
	require.Error(t, validateJWTErr, "expecting error")
}

// jweStrings is a struct holding JWEs in string format
type jweStrings struct {
	validWithNewAuthTkn string
	validWithoutAuthTkn string
	invalidJWEParse     string
	invalidPvtKey       string
	invalidPvtKeyParse  string
	invalidJWEDecrypt   string
	invalidJWSParse     string
	invalidJWSVerify    string
	//invalidMultiJWSIdx string
	invalidNonce string
	invalidKid   string
}

func loadJWEs() (*jweStrings, error) {
	j := &jweStrings{}
	// load a valid JWE string
	a, err := generateValidJWSAndJWE(true, true, false)
	if err != nil {
		return nil, err
	}
	j.validWithoutAuthTkn = a

	// load an invalid JWE string
	j.invalidJWEParse = "badJWEFormat"

	// load a valid JWE string (test case must pass parsing the JWE, it will fail at loading the private key)
	j.invalidPvtKey = a

	// load a valid JWE string (test case must pass parsing the JWE, it will fail at parsing the private key)
	j.invalidPvtKeyParse = a

	// load a valid JWE string (test case must pass parsing the JWE, it will fail at decrypting, must use a different private key)
	j.invalidJWEDecrypt = a

	b, err := generateBadJWSAndValidJWE()
	if err != nil {
		return nil, err
	}
	// load an invalid JWS format that is properly encrypted into a JWE
	j.invalidJWSParse = b

	// load a valid JWE string (test case must pass parsing and encrypting the JWE, it will fail at JWS signature validation, must use a different public key)
	j.invalidJWSVerify = a

	// TODO uncomment when test is ready
	//j.invalidMultiJWSIdx = a

	c, err := generateValidJWSAndJWE(false, true, false)
	if err != nil {
		return nil, err
	}
	j.invalidNonce = c

	d, err := generateValidJWSAndJWE(true, false, false)
	if err != nil {
		return nil, err
	}
	j.invalidKid = d

	e, err := generateValidJWSAndJWE(true, true, true)
	if err != nil {
		return nil, err
	}
	j.validWithNewAuthTkn = e

	return j, nil
}

func generateValidJWSAndJWE(withNonce, withKid bool, withDidAccessToken bool) (string, error) {
	var err error
	kid := ""
	if withKid {
		kid = "did:example:123456789abcdefghi#keys-1"
	}
	nonce := ""
	if withNonce {
		nonce = "p6OLLpeRafCWbOAEYpuGVTKNkcq8l"
	}
	didAccessToken := ""
	if withDidAccessToken {
		didAccessToken, err = generateNewValidAccessToken(kid)
		if err != nil {
			return "", errors.Wrapf(err, "Failed generate a new Did Access Token")
		}
	}

	// 1. Signing - Sign a payload (JWT) into a JWS (using client's private key)
	headerAttrs := make(map[string]interface{})
	headerAttrs[KidKey] = kid
	headerAttrs[DidAccessNonceKey] = nonce
	headerAttrs[DidAccessTokenKey] = didAccessToken

	serializedJws, err := CompactSerialize(headerAttrs,
		"This is a test payload.",
		"ES256",
		clientKeys,
	)
	if err != nil {
		return "", errors.Wrapf(err, "Failed to sign payload")
	}

	serverPubKey, err := clientKeys.GetRemotePublicKey("serverPubKey")
	if err != nil {
		return "", err
	}

	// 2. Encrypting - Encrypt a JWS into a JWE (using server's public key)
	authToken, err := encryptJWS(serializedJws,
		serverPubKey,
		"ECDH-ES",
		"A128GCM")
	if err != nil {
		return "", errors.Wrapf(err, "Failed to encrypt JWS into JWE")
	}

	return authToken, nil
}

func generateBadJWSAndValidJWE() (string, error) {
	serverPubKey, err := clientKeys.GetRemotePublicKey("serverPubKey")
	if err != nil {
		return "", err
	}

	authToken, err := encryptJWS("invalidJWS", serverPubKey, "ECDH-ES", "A128GCM")
	if err != nil {
		return "", errors.Wrapf(err, "Failed to encrypt JWS into JWE")
	}
	return authToken, nil
}

func generateNewValidAccessToken(kid string) (string, error) {
	pvKey, _ := serverKeys.GetPrivateKey()
	ecdsaKey := pvKey.(*ecdsa.PrivateKey)
	didAccessToken, err := createNewAccessToken("p6OLLpeRafCWbOAEYpuGVTKNkcq8l", kid, ecdsaKey)
	return didAccessToken, err
}

func TestInvalidAccessToken(t *testing.T) {
	jwe := "eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTEyOEdDTSIsImVwayI6eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6IlJzMkdreFBZZTdwTGpVTEU2M1N1MU83anFEb3p0a2NicFBNQkpmY3d3RnciLCJ5IjoiQ2NlQ25HNjBVNzZ1RFU1REZ5TVUtT2xaM2tubGE2MTZmcHFKMm9kejRERSJ9fQ..Q0Y9BoOOopOUrx72.KL6id1BOq3U19cl8bq4krv58xNiABS_Rba2J-vvYxKTBjdS8vJcamLZ1EjJydIKutld4Ax6LEOTuSEi46yvimi2IwKVtt0L4_lEkwi8p2SNKQmMbn5_h_LxRa-IvSehJRYpgjAX8CfOF4rO4U9vQY17a5_IyBvh_cTRHgbwWlpPyJnNHjU7bfSDRtAvRFSluAR-qD17OkDn7oKMSRwZrOFoJ8iofJXtoC4-uYsEeMraHDBHdRG0l5yWktazi3QlG7LpQW1pLwaR8KRz-LWBA42lE3Z4paoyPGiSFyHSyKbrLNI24ouX-PUnZOHs368gLpnOm7PynzVEJ63UiZicS3ZCbH1njbPtyX3or_PMy4nkIYlL8ZlSWuEszlSsKEQSjUFv12rT-DA5LIa1sF66lRz2SpxPNGuMz5v9NqYfZTRadh1jpgYtw5_pvUw1jCkWXRcGjWsXscfadUDfuJKxkii58XRXcZE8qnY742JCuIrCFzexiRKGyJeYUovjIONaj1XBlNNZ3sVRy7VuJ2ZeG4PHbpilNGW9ivg2OQT8pVdYfvOFZDRLbTG6mJ1sbnSyr2x-jWmkhxIvxnCiE-Yll-tTpMYpje1-0-8_yCv4N-HEV6AzFJT3PJ6Oz2AZs5I-nG7LpHz8C4lUkj4oWYp-LMltf72BnArlLkAgLFXWQwUK4LyLgx77To0lArWYnegGins3FKZtEyDg7Z_UHk5d_CcAK4Xr79TeB4QuKV-xJHLg1VPd3i7zbGLLBzoHExYXr-FF3tVeBNivqZez871nAQ7Jdgd2sC4vkIN5W06iNI_QKLEShOOwfrGxN1GfV5oz9pmABOI9ThtTir0z_9FsRmhiLPAEmxWcVVok2hWKiCf3H8oTQIKiPOA1HffOOy1OLIGqPxfIiiIkRXryD3qyatJkmIcDIVVzaIT_BkfIbOTPNLVHgtw_oab7ujJ4ebLAqE9u7S0vqcmYDnED9n0qFgILByu-3BCmPGv_tXCym2FZXzgIt-4f3HB8HLiCKx9d2jT53lIwpBD_zmAe8ec_Y-lbCrSlkvol0o6PgMmjraSRU5rUpfJ7tgtQRHq9Uxy9OdPmJrXBk-NO1bGI2pvvU7rBEJPL1x5ZIBuLskvhvWW4A0kpbJtKNHMaiAEcePrBatDnNF8WMJeQ6SrasfrE8k5ZV_VBEM2pXb9PWRdNyop-Re3LoN85WNYCMPjhJ3tjm2XYfNNnkqV9HnWB-3m06kkJChmormDmqcR7LNcECYC2L9l2Xb0Vz7FsNbvSUELt_6Ja1omQbd4GcD4D77oigTSTn06vLLiTpvr3g3sJ3Yw0gl75d7X5JmBTjBxMoHyASGWf9GuTc2JJB76Pj8KF5WzxtqVNGpX5Sw5md3hp7P6GUxh2LWmudmMZVIkRnU6_3skiv_ZpHauP4_xliPOeX619ayigVvi7HnsExRkyjkle-G6v__TwKUaN9yNWPRMW91CsSRXzEnGLfyQNmIlex_MUENdVsPrkMCTI_5655BlugIJmnPX_4ylxUuLEb9HPbXhApsrmYObjsYCxebof-Mnrojjn8iajg9bYXTHagXoujPrP49Z9TbgB1LoEHYUgAd9zryIqikrEyhAUGROoRYwQ3zvivWNIByZaao881ZTknR9lC9hAe0Qp_WnEt_mWtG_rFf2F6r2QmrbGgHHuh75pZwbvW1LIwep_0NP-y_QltQA7A5Sm9G_aPwy3okz0Cpm7BB1nRTexC8JOpfxLy9MkCAFWALhzWBp3R-wOjSjRoxso3mjAz_xtiIAeqBz5-TvRDYMVbmC_ebLC7IGCQ_TX_O_9npJx3sU5N9Fb93j18H40xIZ4vfgCADGRFfYHk9kJOKkheKWZ1iPYmhp3L2VWoU2MMfBNBBNc59QhJ5GsYFYng-EiRM5jlnjnLYrj2j9DfVZvnz9bSKdRwh8RfdwA8luN_GlPKmDFpCHXvbf4_77byQqtTeYx1CDMgTZ2N9lwJ51DR9fh7HjFy7ZpMA9Hf5OCvi6vqBETANoo5YjppBoP_3AcJWXFKwKWIGBwkcRNwiAMYBmMuy06CbEQ1JwZzJTUFYVdaBrebpnJXB2sP-epAse4BfZ96pPgJUAYU1LrsTXevWnDisBxBeTWnSoLWkwsCLfptUNoOcdIzxcVMngv2O_FzVmJiHMH-d_XCYx5kTuGFZmR1jgYm7IxYi1RQBSMDaLM3AIdtSwrCSfsBPQwfGCwMVWDxBzzK_UilK8Y42bCJCO62vyQLPPMnZ3g8-kOpO0I2EmzYsWmNBJ01AsHjzRf9mq1nK66NtbV9bwH2SXDVa-Fl-nMWWh4ccgGx28e7squux_GcdYNqoDftjV1c5LZGV94yduEOVdKmThEmF8EqPalwzveSsDL7x9NsHpZZhimYOJUTYrNCapsrLWxxxue5SKkyOHsydeCXZkAW6oEIb-RPwzuFChtMsBgzxQqfaDkunoX-rt-0AJhvI8wPammf09FyDK6jt5NJyVD119t7plFIFa-DrkRLShL-jA5-iKz1cTwknPn0_xi_oNc-TvrpYPSgrAY3hV0qjCC-KoB6KCl0qXw0C4Y8Pbu6MbQPmKiVHbLvaPi8-AGPpulhXOmkEKT2ag1kM2MIYG7acaiWoC7N8fWx5h4_LVo.mCxPcKI4aThBKb4B6ffb-Q"
	auth := Authenticator{KeyProvider: serverKeys}
	_, err := auth.Authenticate(jwe)
	require.Error(t, err)
	require.Equal(t, "Crypto [Warning]: could not parse Access Token: illegal base64 data at input byte 86", err.Error())
}

func TestMalformedOuterJWTMessage(t *testing.T) {
	jwe := "eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTEyOEdDTSIsImVwayI6eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6IkxmMnN6Um92T0xHWHozTnZpUXh6OEt2TGsteS1LVEdsTEFrRy1mbDBVWU0iLCJ5IjoiODFqdVkyVkhGZzZlQnJPUHZWX3RCT25XWllBcDdWcmRoTDZ6R0llcTAyZyJ9fQ..he58uew-Z6ueYpa1.9dymF9pNGlUhw201zf-qIoVeq6Letldi-6ZttIINjjBcxK5YUsOKqO65JcKFYGKxH3HmtnlXtcBBk5Kw27oDhTkrMKlqWnGilml34Vk-MiL0mXUzpONkYeKm750vtLDUst0dOsQWaZ30YCssbkc8eebMfGyUVc81D8WJ-lLQC3BLW12PkngZjqYuC6hkOW3idGl69M012aejCeAAgMXBH42HGAk8CKhYdbzy8dpRGxXXh5c1NXLq6nmOikE3pGr38FhZ01B4j-QJa1KyuckqavWpy6nq_SmHeNKlEzBCf3pLmLGrhRVaZ_i0afFGOaJSc5yvLdvIWBl4qLsqeyChzOrKdU8vQ8hVrK-CrzfYRWv4OF39NJmylxOSyA4E_YtmWaj5yVZYbeJ-WtBOHEyL0v56I8c4GGIF6f9uNIIdGtYIuoTzEyOOjDXuaxXOFWR3Blj_XYk5axa7ACgMzD08CerKMVd3BOjNTB6ypz1Ec6EhU5wFi_E-nmGo9Vw6gT7mciJILS6vwIumm7Ai0d_fapAp13Aond57Pg4d0fCUc9Fhh2FuzUcG_LdMpAT2MN3B2slNNcCYk1WKGEsDH2u8czAgmM144qu7zSKm41P60jXbJeoUMzU7p4hdfc_tjR9NKkz1wGdoaHYMLybDz9db8VsLtWHpxgG4Vowk4BNEZLj2cw9TrlsJBbmHxTe9koBy2QFGJXMP0cU3vdVYxoJFQzJgqC5hmfWsLdW-hHjDfC5alzXEtQfyBq7-sVJ2R4Z9TKML_Fl_fHCxRujoTp93DYJN9Ye3dzYv4CGxoCBGWanJRomedcKRxWqDKKvsBugSImrdznLpKWn6lKxHrXe5wZQHT8AJ0k61FCC_bXw9z3SQaSTPKsgtBMfKKW0KpAfgHSwk6h1mlxa6WxobsICb3UdIk5kd_TbA6yCxqxfM9-zavuOtVuVtSeJX8Pejw4XCPeEPOtyxcusy-y7Ij_xxvBfUJzxTW9XNGhXLnzhRVW3VGYPTXLRhoC1uY7pdRb2520MhzA2KH5qjOLiOeMWiRD5QzPPgAf33bf_u1P5x2sdaYyIQEGDxqpyPkdDGf2Fex_ad_SWkdnKO47YtjLDixKYdq448ssFEOu4n9LDGj_i1EJh_G56bHN6axexfxBy_m3qzhwDmTJKiD7PZjHkL8r6Ix0PC9Jy7th1ZRDnyeM_Qjoc3bh30M0-ly-BVzLDejziCMFphmZ3ahz6YIF_0qerw-1LXWOujShcdWsjftuRWp0Ie3pf-4cRcEu2NADEeGEiMSsNIQKPq7mGSqpMuwIquh2uy-fXTbROCDh-LibrZ-6BEYtl1MHnvFG0p29zXKQDjG0958_u-dFEzFADozJ5DJnH8L4wCGbGuWuwKDdmTX8CRW56eb8MxDDeWqwukAgmrKzTqC7IUj6H0TxNkthUwsjfNbbSbU7jTnE3qB_c3U6ytrcUwbPYiJUmZfofQdiX1rttgYqQZY3prQhXt1eIxqzzHcHDpoEN4P1ogQaPNhzgpJ1jMLeadIS9zOu-GSqD4a8xfw3pJ8KteSSKh29e3JJZuiIPkFiuWKLpM9OYvcmtSyCYPLFvZHCeQngw0kdwPIqb3Sela5N2r7g1QXu5GK9ZvP_iFaE2SH0ADqDk75N5gzg70U4fwGIemq-R0aDtVEmXnipctIban_PEdr6rzEkmUI9I4lJfT_gbT36SXHIpHxmrvb0xZu0HGD3pPTlzz7ILaYS5HkTY3iBrHX2d71q7P7CVa4XhFrSWrBetHW1M8_m6FRBD2XNoDDP6Eq7pHhiP57kTbIWbLBVWHwkqdRHM745IZJZp3GIV2wlk2h2WEjGlduXiK_RWXyM2EWVCAvgKVgIzwDpnTPNlFRZBIgTnVMMwFHJ6AmFyq2u1OkrXjRnGr80hOSQTonXal7X1pDhn_kvQcg5S4CiRpT1FlZyEIVB6WHTrzeGjeBOIiY1vAApcalAElwV8StQppL1VQrPXBAndXVgKkPv5PUGJBXCeWHG5g7UxBB5j6GXNapSzV0oH3gxugYBe0yTKZ4u15t0hrqPuZ4z13i3hg9C0pdA83WyUVNzXHppqvLq9GJ4wLOGzDCEYGDIzaqvEX8uOC2oiCXXp6TcW_2-01YHH7pXnaSYdDtXLdFfWgpuHS_x9RLOretQcdAZ08WhuGKm35xG8s-3AGNUWgiaSZz8SS_afwRh8GUp25t9_39EDj1nvJ8P1ZaEp8jnGlvaczM_UX0RsOL8HcNqiAm33hHQ7yHSSfvEuEtNb9BO_4eICIJr4mW3ndQT2LLFW42PJ7Wa3qmdENAYBY2ERFmvXWDCx2R7A6ANtDb6knsvScbAe8soKhHU2cbshnBreQbwB0sM7qPgFZMJsDUHTVLEVPj6omMu5HFclYqmmrA0CyOpBDSVww-SHjmbGGGfF7k6UGoWmxiAZ0xwP8VFDln_OEyeO1A138rYV01fnxRc0UOzyGP_IAjY_ZF46HBfq9JWHPDzwtC7DPAdXqZgyJZap9bAO8l_zlazDHIzz_WBB7wLdVc9WOJ_veA9t65quWB1XHwA3FWoEObFhNW8TsjzuHDvYViCRbxfNtaL29TE8_EzSKrXzAzkvv1COvxvbtRkQXbzDBX67DcjOc.KSzYDLsJ9lU0gbXLIYWsEQ"
	auth := Authenticator{KeyProvider: serverKeys}
	_, err := auth.Authenticate(jwe)
	require.Error(t, err)
	require.Equal(t, "Crypto [Warning]: could not decrypt JWE: square/go-jose: error in cryptographic primitive: illegal base64 data at input byte 86", err.Error())
}
