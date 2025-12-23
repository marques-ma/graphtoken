package jwtld

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hpe-usp-spire/schoco"
	"go.dedis.ch/kyber/v3"
)

// ----------------------------
// JSON-LD structs (payload)
// ----------------------------

type Payload struct {
	Ver  int8                   `json:"ver,omitempty"`
	Iat  int64                  `json:"iat,omitempty"`
	Iss  *IDClaim               `json:"iss,omitempty"`
	Aud  *IDClaim               `json:"aud,omitempty"`
	Sub  *IDClaim               `json:"sub,omitempty"`
	Data map[string]interface{} `json:"data,omitempty"`
	List []*LDNode              `json:"@list,omitempty"`
}

type IDClaim struct {
	CN string  `json:"cn,omitempty"`
	PK []byte  `json:"pk,omitempty"`
	ID *string `json:"id,omitempty"`
}

type LDNode struct {
	ID      string   `json:"@id,omitempty"`
	Payload *Payload `json:"payload"`
}

// ----------------------------
// Helpers JWS (base64url w/o padding)
// ----------------------------
var b64 = base64.RawURLEncoding

func b64Encode(data []byte) string {
	return b64.EncodeToString(data)
}

func b64Decode(s string) ([]byte, error) {
	return b64.DecodeString(s)
}

func marshalCanonical(v interface{}) ([]byte, error) {
	return json.Marshal(v)
}

// ----------------------------
// Create / Extend / Validate
// ----------------------------

func CreateJWS(payload *Payload, version int8, key interface{}) (string, error) {
	payloadBytes, err := marshalCanonical(payload)
	if err != nil {
		return "", fmt.Errorf("marshal payload: %v", err)
	}

	header := map[string]interface{}{"version": version}
	headerBytes, _ := json.Marshal(header)

	var sigBytes []byte
	switch version {
	case 0:
		ecdsaKey, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return "", fmt.Errorf("version 0 requires *ecdsa.PrivateKey")
		}
		h := sha256.Sum256(payloadBytes)
		sigBytes, err = ecdsaKey.Sign(rand.Reader, h[:], crypto.SHA256)
		if err != nil {
			return "", fmt.Errorf("ecdsa sign: %v", err)
		}
	case 1:
		eddsaKey, ok := key.(kyber.Scalar)
		if !ok {
			return "", fmt.Errorf("version 1 requires kyber.Scalar")
		}
		sig := schoco.StdSign(string(payloadBytes), eddsaKey)
		sigBytes, err = sig.ToByte()
		if err != nil {
			return "", fmt.Errorf("schoco sign: %v", err)
		}
	default:
		return "", fmt.Errorf("unsupported version: %d", version)
	}

	return strings.Join([]string{b64Encode(headerBytes), b64Encode(payloadBytes), b64Encode(sigBytes)}, "."), nil
}

func ExtendJWS(jws string, newPayload *LDNode, version int8, key ...interface{}) (string, error) {
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid jws format")
	}
	headerB, _ := b64Decode(parts[0])
	payloadB, _ := b64Decode(parts[1])
	sigB, _ := b64Decode(parts[2])

	var doc Payload
	if err := json.Unmarshal(payloadB, &doc); err != nil {
		return "", fmt.Errorf("unmarshal payload: %v", err)
	}

	switch version {
	case 0:
		// ID mode: previous full signature becomes node @id (base64)
		newNodeID := b64Encode(sigB)
		newPayload.ID = newNodeID
		doc.List = append(doc.List, newPayload)

		if len(key) == 0 {
			return "", fmt.Errorf("ecdsa key required")
		}
		ecdsaKey, ok := key[0].(*ecdsa.PrivateKey)
		if !ok {
			return "", fmt.Errorf("key is not *ecdsa.PrivateKey")
		}

		newPayloadBytes, _ := marshalCanonical(&doc)
		h := sha256.Sum256(newPayloadBytes)
		newSig, _ := ecdsaKey.Sign(rand.Reader, h[:], crypto.SHA256)

		var hdr map[string]interface{}
		_ = json.Unmarshal(headerB, &hdr)
		hdr["version"] = version
		hdrB, _ := json.Marshal(hdr)

		return strings.Join([]string{b64Encode(hdrB), b64Encode(newPayloadBytes), b64Encode(newSig)}, "."), nil

	case 1:
		// SchoCo mode: extract aggKey + R from previous signature, put R as @id, sign whole doc with aggKey
		prevSig, err := schoco.ByteToSignature(sigB)
		if err != nil {
			return "", fmt.Errorf("invalid previous signature: %v", err)
		}
		aggKey, partSig := prevSig.ExtractAggKey()
		partSigBytes, err := schoco.PointToByte(partSig)
		if err != nil {
			return "", fmt.Errorf("PointToByte(partSig): %v", err)
		}
		newNodeID := b64Encode(partSigBytes)
		newPayload.ID = newNodeID

		doc.List = append(doc.List, newPayload)

		newPayloadBytes, _ := marshalCanonical(&doc)
		newSig := schoco.StdSign(string(newPayloadBytes), aggKey)
		newSigBytes, _ := newSig.ToByte()

		var hdr map[string]interface{}
		_ = json.Unmarshal(headerB, &hdr)
		hdr["version"] = version
		hdrB, _ := json.Marshal(hdr)

		return strings.Join([]string{b64Encode(hdrB), b64Encode(newPayloadBytes), b64Encode(newSigBytes)}, "."), nil

	default:
		return "", fmt.Errorf("unsupported version: %d", version)
	}
}

func ValidateJWS(jws string, version int8, bundle ...*Payload) (bool, error) {
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		return false, fmt.Errorf("invalid jws format")
	}
	// headerB, _ := b64Decode(parts[0])
	payloadB, _ := b64Decode(parts[1])
	sigB, _ := b64Decode(parts[2])

	var doc Payload
	if err := json.Unmarshal(payloadB, &doc); err != nil {
		return false, fmt.Errorf("unmarshal payload: %v", err)
	}

	switch version {
	case 0:
		N := len(doc.List)
		for k := 0; k < N; k++ {
			partial := &Payload{
				Ver:  doc.Ver,
				Iat:  doc.Iat,
				Iss:  doc.Iss,
				Aud:  doc.Aud,
				Sub:  doc.Sub,
				Data: doc.Data,
				List: doc.List[:k+1],
			}
			partialBytes, _ := marshalCanonical(partial)

			var sigToCheck []byte
			if k == N-1 {
				sigToCheck = sigB
			} else {
				sigToCheck, _ = b64Decode(doc.List[k+1].ID)
			}

			var pubKeyBytes []byte
			if doc.List[k].Payload.Iss != nil && len(doc.List[k].Payload.Iss.PK) > 0 {
				pubKeyBytes = doc.List[k].Payload.Iss.PK
			} else if len(bundle) > 0 {
				pubKeyBytes = bundle[0].List[0].Payload.Sub.PK
			}

			pub, _ := x509.ParsePKIXPublicKey(pubKeyBytes)
			h := sha256.Sum256(partialBytes)
			if !ecdsa.VerifyASN1(pub.(*ecdsa.PublicKey), h[:], sigToCheck) {
				return false, fmt.Errorf("signature failed at step %d", k)
			}
		}
		return true, nil

	case 1:
		N := len(doc.List)

		// non-extended (no nodes)
		if N == 0 {
			sig, err := schoco.ByteToSignature(sigB)
			if err != nil {
				return false, fmt.Errorf("byteToSignature: %v", err)
			}
			rootPK, err := schoco.ByteToPoint(doc.Iss.PK)
			if err != nil {
				return false, fmt.Errorf("byteToPoint rootPK: %v", err)
			}
			msgBytes, _ := marshalCanonical(&doc)
			if !schoco.StdVerify(string(msgBytes), sig, rootPK) {
				return false, fmt.Errorf("StdVerify failed for non-extended token")
			}
			return true, nil
		}

		// extended case:
		// build setMsg: OUTER (full list) -> ... -> INNER (empty list)
		var setMsg []string
		for i := N; i >= 0; i-- {
			partial := &Payload{
				Ver:  doc.Ver,
				Iat:  doc.Iat,
				Iss:  doc.Iss,
				Aud:  doc.Aud,
				Sub:  doc.Sub,
				Data: doc.Data,
				List: doc.List[:i], // i==0 -> empty slice
			}
			b, _ := marshalCanonical(partial)
			setMsg = append(setMsg, string(b))
		}

		// build setPartSig: R_{N-1}, R_{N-2}, ..., R_0  (reverse order of doc.List)
		var setPartSig []kyber.Point
		for i := N - 1; i >= 0; i-- {
			idBytes, err := b64Decode(doc.List[i].ID)
			if err != nil {
				return false, fmt.Errorf("decoding node ID to point (i=%d): %v", i, err)
			}
			pt, err := schoco.ByteToPoint(idBytes)
			if err != nil {
				return false, fmt.Errorf("ByteToPoint node ID (i=%d): %v", i, err)
			}
			setPartSig = append(setPartSig, pt)
		}

		// final aggregated signature
		lastSig, err := schoco.ByteToSignature(sigB)
		if err != nil {
			return false, fmt.Errorf("byteToSignature final: %v", err)
		}

		// root public key = Iss.PK of the overall payload (doc.Iss)
		// Note: in your earlier designs root issuer was in the "payload.Iss" (top-level),
		// but in some variants you used first node. We follow the version where top-level Iss is the root.
		rootPK, err := schoco.ByteToPoint(doc.Iss.PK)
		if err != nil {
			return false, fmt.Errorf("byteToPoint rootPK: %v", err)
		}

		// verify
		if !schoco.Verify(rootPK, setMsg, setPartSig, lastSig) {
			return false, fmt.Errorf("schoco verification failed")
		}
		return true, nil

	default:
		return false, fmt.Errorf("unsupported version: %d", version)
	}
}
