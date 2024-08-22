package qaimservices

import (
	"crypto"
	"crypto/hmac"
	b64 "encoding/base64"
	json "encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

type Role uint

const (
	NONE           = iota
	SUPERUSER Role = 1 + iota // Superuser, can create and manage admins
	ADMIN                     // Admin User, can access admin functions only
	USER                      // User is the normal user of the application
	USER_SECP                 // User for the secp sandbox phase
	USER_BETA                 // Beta test user
)

/*
TODO: Once basic implementation is done, move from a secret based signing approach to a pub/private key approach
# JWT Setup
Header: {
(Algorithm) alg: algorithm used to sign token
(type) typ: type of token, ALWAYS jwt
}

	Payload: {
		(Issuer) iss: entity to generate and issue web token
		(Subject) sub: entity token is issued to, user id here
		(Audience) aud: Intended audience, for our case this can be (ADMIN, User, SandboxUser ... ${UserRole}{UserType})
		(Expiry) exp: timestamp after which tokens should not be accepted
		(Issued at) iat: token issuing date
	}

	Signature: {
		sign(b64Header + b64Payload + My_Secret_Key)
	}
*/
type JwtHeader struct {
	Alg string `json:"alg"` // (Algorithm) alg: algorithm used to sign token
	Typ string `json:"typ"` // (type) typ: type of token, ALWAYS jwt
}

type JwtPayload struct {
	Iss string `json:"iss"` // (Issuer) iss: entity to generate and issue web token
	Sub string `json:"sub"` // (Subject) sub: entity token is issued to, user id here
	Aud Role   `json:"aud"` // (Audience) aud: Intended audience, for our case this can be (ADMIN, User, SandboxUser ... ${UserRole}{UserType})
	Exp int64  `json:"exp"` // (Expiry) exp: timestamp after which tokens should not be accepted
	Iat int64  `json:"iat"` // (Issued at) iat: token issuing date
}

type JwtToken struct {
	Header     JwtHeader
	B64Header  string
	Payload    JwtPayload
	B64Payload string
	Token      string
}

/*
CreateJwtToken creates a b64encoded signed token
@param sub the subject (Unique User Id) for the token
@param aud the audience (User Role) for the token, used for restricting certain endpoints
*/
func CreateJwtToken(userIdentifier string, userType Role) (JwtToken, error) {
	var issueTime time.Time = time.Now()
	var hashFunc crypto.Hash
	var t JwtToken
	t.Header.Typ = "jwt"
	t.Payload.Sub = userIdentifier
	t.Payload.Aud = userType
	t.Payload.Iss = "qaim"
	t.Payload.Iat = issueTime.Unix()
	t.Payload.Exp = issueTime.Add(time.Minute * 30).Unix()
	if crypto.SHA256.Available() {
		hashFunc = crypto.SHA256
		t.Header.Alg = "HS256"
	} else {
		fmt.Println("User has no hash func")
		calcErr := errors.New("auth server does not support required hash function")
		return t, calcErr
	}
	// encode header
	jwt_header_b, err := json.Marshal(t.Header)
	if err != nil {
		fmt.Println("error signing token:", err)
	}
	t.B64Header = b64.RawURLEncoding.EncodeToString(jwt_header_b)
	// encode paylod
	jwt_payload_b, err := json.Marshal(t.Payload)
	if err != nil {
		fmt.Println("error signing token:", err)
	}
	t.B64Payload = b64.RawURLEncoding.EncodeToString(jwt_payload_b)
	// sign(eh,ep,sig)
	// using Hmac + Sha(256/224)
	secret := os.Getenv("JWTSECRET")
	encodedBody := t.B64Header + "." + t.B64Payload
	hmacFunc := hmac.New(hashFunc.New, []byte(secret))
	_, err = hmacFunc.Write([]byte(encodedBody))
	if err != nil {
		fmt.Println("Error signing jwt token")
		// TODO: Return err for no sign
		calcErr := errors.New("error signing jwt token, check header and payload")
		return t, calcErr
	}
	signature_b := hmacFunc.Sum(nil)
	b64Signature := b64.RawURLEncoding.EncodeToString(signature_b)
	t.Token = encodedBody + "." + b64Signature
	return t, nil
}

/*
VerifyJwtToken verifies a signed base64 encoded token
@param b64Token the signed base64 token to verify
*/
func VerifyJwtToken(b64Token string, userType Role) bool {
	var t JwtToken
	t.Token = b64Token
	splitToken := strings.Split(t.Token, ".")
	if len(splitToken) < 3 {
		// err = errors.New("invalid token")
		return false
	}
	t.B64Header = splitToken[0]
	header_b, err := b64.RawURLEncoding.DecodeString(t.B64Header)
	if err != nil {
		return false
	}
	err = json.Unmarshal(header_b, &t.Header)
	if err != nil {
		return false
	}
	t.B64Payload = splitToken[1]
	payload_b, err := b64.RawURLEncoding.DecodeString(t.B64Payload)
	if err != nil {
		return false
	}
	err = json.Unmarshal(payload_b, &t.Payload)
	if err != nil {
		return false
	}
	signature := splitToken[2]
	signature_b, err := b64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		return false
	}
	var hashFunc crypto.Hash
	if t.Header.Alg == "HS256" {
		hashFunc = crypto.SHA256
	} else {
		// err = errors.New("hash function not found")
		return false
	}
	secret := os.Getenv("JWTSECRET")
	hmacFunc := hmac.New(hashFunc.New, []byte(secret))
	encodedBody := t.B64Header + "." + t.B64Payload
	_, err = hmacFunc.Write([]byte(encodedBody))
	if err != nil {
		return false
	}
	genSign := hmacFunc.Sum(nil)

	// * STEP 1: verify jwt token
	eq := hmac.Equal(signature_b, genSign)
	if !eq {
		// err = errors.New("invalid token")
		return false
	}

	// * STEP 2: verify user role
	if t.Payload.Aud != userType {
		// err = errors.New("invalid token")
		return false
	}

	// * STEP 3: check if token expired
	unixTs := time.Now().Unix()
	return unixTs <= t.Payload.Exp
}

func GetJwtSubject(b64Token string) (string, error) {
	var t JwtToken
	t.Token = b64Token
	splitToken := strings.Split(t.Token, ".")
	if len(splitToken) < 3 {
		err := errors.New("invalid token")
		return "", err
	}
	t.B64Payload = splitToken[1]
	payload_b, err := b64.RawURLEncoding.DecodeString(t.B64Payload)
	if err != nil {
		return "", err
	}
	err = json.Unmarshal(payload_b, &t.Payload)
	if err != nil {
		return "", err
	}
	return t.Payload.Sub, nil
}
