package jwtld

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"testing"
	"time"

	"github.com/hpe-usp-spire/schoco"
)

// helper: marshal ECDSA public key to bytes
func x509MarshalPubKey(pub *ecdsa.PublicKey) []byte {
	b, _ := x509.MarshalPKIXPublicKey(pub)
	return b
}

// ----------------- TESTS -----------------

func TestCreateExtendValidateJWS_IDMode_Debug(t *testing.T) {
	fmt.Println("=== ID Mode Test ===")
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// root payload
	rootPayload := &Payload{
		Ver: 0,
		Iat: time.Now().Unix(),
		Iss: &IDClaim{
			CN: "root",
			PK: x509MarshalPubKey(&priv.PublicKey),
		},
		Data: map[string]interface{}{"msg": "root node"},
		List: []*LDNode{},
	}

	jws, err := CreateJWS(rootPayload, 0, priv)
	if err != nil {
		t.Fatalf("CreateJWS failed: %v", err)
	}
	fmt.Println("Root JWS:", jws)

	ok, err := ValidateJWS(jws, 0)
	if err != nil || !ok {
		t.Fatalf("ValidateJWS root failed: %v", err)
	}
	fmt.Println("Root JWS validation OK")

	// extension
	extPayload := &LDNode{
		Payload: &Payload{
			Ver: 0,
			Iat: time.Now().Unix(),
			Iss: &IDClaim{
				CN: "ext1",
				PK: x509MarshalPubKey(&priv.PublicKey),
			},
		},
	}

	jws2, err := ExtendJWS(jws, extPayload, 0, priv)
	if err != nil {
		t.Fatalf("ExtendJWS failed: %v", err)
	}
	fmt.Println("Extended JWS:", jws2)

	ok, err = ValidateJWS(jws2, 0)
	if err != nil || !ok {
		t.Fatalf("ValidateJWS extended failed: %v", err)
	}
	fmt.Println("Extended JWS validation OK")
}

func TestCreateExtendValidateJWS_SchoCoMode_Debug(t *testing.T) {
	fmt.Println("=== SchoCo Mode Test ===")
	rootPriv, rootPub := schoco.KeyPair("root")
	rootPKBytes, _ := schoco.PointToByte(rootPub)

	rootPayload := &Payload{
		Ver: 1,
		Iat: time.Now().Unix(),
		Iss: &IDClaim{
			CN: "root",
			PK: rootPKBytes,
		},
		Data: map[string]interface{}{"msg": "root node"},
		List: []*LDNode{},
	}

	jws, err := CreateJWS(rootPayload, 1, rootPriv)
	if err != nil {
		t.Fatalf("CreateJWS SchoCo failed: %v", err)
	}
	fmt.Println("Root JWS:", jws)

	ok, err := ValidateJWS(jws, 1)
	if err != nil || !ok {
		t.Fatalf("ValidateJWS SchoCo root failed: %v", err)
	}
	fmt.Println("Root JWS validation OK")

	// retrieve key to extend

	// first extension
	extPayload1 := &LDNode{
		Payload: &Payload{
			Ver: 1,
			Iat: time.Now().Unix(),
			Iss: &IDClaim{
				CN: "anonymousNode",
			},
		},
	}

	jws2, err := ExtendJWS(jws, extPayload1, 1)
	if err != nil {
		t.Fatalf("ExtendJWS SchoCo 1 failed: %v", err)
	}
	fmt.Println("After 1st extension JWS:", jws2)

	ok, err = ValidateJWS(jws2, 1)
	if err != nil || !ok {
		t.Fatalf("ValidateJWS SchoCo after 1st ext failed: %v", err)
	}
	fmt.Println("Validation after 1st extension OK")

	// second extension
	extPayload2 := &LDNode{
		Payload: &Payload{
			Ver: 1,
			Iat: time.Now().Unix(),
			Iss: &IDClaim{
				CN: "anonymousNode",
			},
		},
	}

	jws3, err := ExtendJWS(jws2, extPayload2, 1)
	if err != nil {
		t.Fatalf("ExtendJWS SchoCo 2 failed: %v", err)
	}
	fmt.Println("After 2nd extension JWS:", jws3)

	ok, err = ValidateJWS(jws3, 1)
	if err != nil || !ok {
		t.Fatalf("ValidateJWS SchoCo after 2nd ext failed: %v", err)
	}
	fmt.Println("Validation after 2nd extension OK")


	// third extension
	extPayload3 := &LDNode{
		Payload: &Payload{
			Ver: 1,
			Iat: time.Now().Unix(),
			Iss: &IDClaim{
				CN: "ThirdAnonymousNode",
			},
		},
	}

	jws4, err := ExtendJWS(jws3, extPayload3, 1)
	if err != nil {
		t.Fatalf("ExtendJWS SchoCo 3 failed: %v", err)
	}
	fmt.Println("After 3rd extension JWS:", jws4)
	ok, err = ValidateJWS(jws4, 1)
	if err != nil || !ok {
		t.Fatalf("ValidateJWS SchoCo after 3rd ext failed: %v", err)
	}
	fmt.Println("Validation after 3rd extension OK")

}

