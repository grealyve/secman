package vulnjwt

import (
	"crypto"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/grealyve/secman/logger"
)

// VerifiedToken, zafiyetli doğrulamadan geçen bir token'ın çıktısıdır.
type VerifiedToken struct {
	Header    map[string]interface{}
	Claims    map[string]interface{}
	Alg       string
	RawSigLen int
}

var (
	ErrMalformed = errors.New("malformed token")
	ErrBadSig    = errors.New("signature verification failed")
)

// httpClient: jku/x5u fetch için — BİLEREK hiçbir SSRF koruması yok.
var httpClient = &http.Client{Timeout: 5 * time.Second}

// VerifyVulnerable, bir JWT'yi doğrular ama BİRÇOK saldırı vektörüne açıktır.
//
// Doğru davranış (baseline & negative control'ün çalışması için):
//   - RS256 + sunucu private key imzası  -> KABUL (baseline)
//   - RS256 + yanlış imza                -> RET   (negative control -> 401)
//
// Zafiyetli davranışlar (her biri // VULN-NN):
//   - alg:none                            -> imza atlanır          (VULN-01)
//   - alg header'ına güven / allow-list yok                        (VULN-02)
//   - HS256 + RSA public key = HMAC secret (algorithm confusion)   (VULN-03)
//   - HS256 + zayıf sözlük secret'i                                (VULN-03b)
//   - kid -> dosya yolu / SQLi / kid-as-key                        (VULN-04)
//   - header.jwk / header.x5c gömülü anahtar                       (VULN-05)
//   - header.jku / header.x5u uzak URL fetch (SSRF + attacker key) (VULN-06)
//   - exp / nbf / iat zaman claim'leri doğrulanmaz                 (VULN-07)
//   - aud / iss claim'leri doğrulanmaz                             (VULN-08)
//   - typ / cty tip doğrulaması yok (nested JWT unwrap)            (VULN-09)
func VerifyVulnerable(tokenString string) (*VerifiedToken, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 && len(parts) != 2 {
		return nil, ErrMalformed
	}

	headerJSON, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[0], "="))
	if err != nil {
		return nil, ErrMalformed
	}
	var header map[string]interface{}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, ErrMalformed
	}

	payloadJSON, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return nil, ErrMalformed
	}
	var claims map[string]interface{}
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return nil, ErrMalformed
	}

	// VULN-02: `alg` doğrudan token header'ından okunur; sabit bir allow-list'e
	// kilitlenmez. Saldırgan hangi doğrulama yolunun seçileceğini kontrol eder.
	alg, _ := header["alg"].(string)
	signingInput := parts[0] + "." + parts[1]

	var sig []byte
	if len(parts) == 3 {
		sig, _ = base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[2], "="))
	}

	vt := &VerifiedToken{Header: header, Claims: claims, Alg: alg, RawSigLen: len(sig)}

	// VULN-09: cty:"JWT" ise payload iç içe (nested) bir JWT olarak unwrap edilir ve
	// iç token'ın claim'lerine güvenilir — iç token alg:none olabilir.
	if cty, _ := header["cty"].(string); strings.EqualFold(cty, "JWT") {
		if inner, ok := claims["_"].(string); ok {
			if innerVT, err := VerifyVulnerable(inner); err == nil {
				logger.Log.Debugln("vulnjwt: nested JWT unwrap edildi (cty:JWT).")
				return innerVT, nil
			}
		}
	}

	switch {
	// VULN-01: alg:none -> imza segmenti hiç kontrol edilmez.
	case strings.EqualFold(alg, "none"):
		logger.Log.Debugln("vulnjwt: alg:none kabul edildi, imza atlandı.")
		return vt, nil

	// VULN-06: header.jku / x5u -> saldırgan-kontrollü URL'den anahtar indirilir.
	case header["jku"] != nil:
		key, err := fetchRSAFromJKU(fmt.Sprintf("%v", header["jku"]))
		if err != nil {
			return nil, ErrBadSig
		}
		if err := verifyRS256(signingInput, sig, key); err != nil {
			return nil, ErrBadSig
		}
		return vt, nil
	case header["x5u"] != nil:
		key, err := fetchRSAFromX5U(fmt.Sprintf("%v", header["x5u"]))
		if err != nil {
			return nil, ErrBadSig
		}
		if err := verifyRS256(signingInput, sig, key); err != nil {
			return nil, ErrBadSig
		}
		return vt, nil

	// VULN-05: header.jwk / x5c -> doğrulama anahtarı token'ın KENDİSİNDEN alınır.
	case header["jwk"] != nil:
		key, err := rsaFromJWK(header["jwk"])
		if err != nil {
			return nil, ErrBadSig
		}
		if err := verifyRS256(signingInput, sig, key); err != nil {
			return nil, ErrBadSig
		}
		logger.Log.Debugln("vulnjwt: gömülü jwk ile doğrulandı (embedded-key forgery).")
		return vt, nil
	case header["x5c"] != nil:
		key, err := rsaFromX5C(header["x5c"])
		if err != nil {
			return nil, ErrBadSig
		}
		if err := verifyRS256(signingInput, sig, key); err != nil {
			return nil, ErrBadSig
		}
		return vt, nil

	// VULN-04: kid varsa doğrulama anahtarı kid'den türetilir (path/SQLi/kid-as-key).
	case header["kid"] != nil && strings.HasPrefix(strings.ToUpper(alg), "HS"):
		key := resolveKidKey(fmt.Sprintf("%v", header["kid"]))
		if !verifyHMAC(signingInput, sig, key) {
			return nil, ErrBadSig
		}
		logger.Log.Debugln("vulnjwt: kid'den türetilen anahtarla doğrulandı.")
		return vt, nil

	// VULN-03: HS256 -> algorithm confusion. Sunucu asimetrik RS256 beklerken, token
	// HS256 dediği için RSA PUBLIC KEY baytları HMAC secret olarak kullanılır.
	case strings.EqualFold(alg, "HS256"):
		// (a) public-key-as-HMAC-secret varyantları (PEM/DER)
		for _, secret := range algConfusionSecrets() {
			if verifyHMAC(signingInput, sig, secret) {
				logger.Log.Debugln("vulnjwt: algorithm confusion (pubkey-as-HMAC) kabul edildi.")
				return vt, nil
			}
		}
		// VULN-03b: zayıf/sözlük secret'i
		for _, w := range WeakHMACWordlist {
			if verifyHMAC(signingInput, sig, []byte(w)) {
				logger.Log.Debugln("vulnjwt: zayıf HMAC secret kabul edildi.")
				return vt, nil
			}
		}
		return nil, ErrBadSig

	// Baseline + negative control: RS256 sunucu anahtarıyla doğrulanır.
	case strings.EqualFold(alg, "RS256"):
		if err := verifyRS256(signingInput, sig, serverPublicKey()); err != nil {
			return nil, ErrBadSig
		}
		return vt, nil

	default:
		return nil, ErrBadSig
	}

	// NOT: VULN-07 (exp/nbf/iat) ve VULN-08 (aud/iss) — buraya kadar hiçbir claim
	// zaman/hedef doğrulaması YAPILMAZ. Süresi dolmuş, gelecek-nbf'li, yanlış aud/iss
	// taşıyan token'lar imza geçerli olduğu sürece kabul edilir.
}

// algConfusionSecrets, RSA public key'in olası serileştirme varyantlarını HMAC
// secret adayı olarak döner (PEM PKIX, PEM string, DER ham).
func algConfusionSecrets() [][]byte {
	pub := serverPublicKey()
	der, _ := x509.MarshalPKIXPublicKey(pub)
	pemBytes := PublicPEM()
	return [][]byte{
		pemBytes,                                   // variant 0: PEM PKIX (sonda \n dahil)
		[]byte(strings.TrimRight(string(pemBytes), "\n")), // variant 1: PEM, sondaki newline yok
		der, // variant 2: DER ham baytlar
		[]byte(base64.StdEncoding.EncodeToString(der)), // variant 3: base64(DER)
	}
}

func verifyRS256(signingInput string, sig []byte, pub *rsa.PublicKey) error {
	h := sha256.Sum256([]byte(signingInput))
	return rsa.VerifyPKCS1v15(pub, crypto.SHA256, h[:], sig)
}

func verifyHMAC(signingInput string, sig, key []byte) bool {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(signingInput))
	return hmac.Equal(mac.Sum(nil), sig)
}

// rsaFromJWK, header'a gömülü JWK'den RSA public key üretir (VULN-05).
func rsaFromJWK(raw interface{}) (*rsa.PublicKey, error) {
	m, ok := raw.(map[string]interface{})
	if !ok {
		return nil, ErrBadSig
	}
	nStr, _ := m["n"].(string)
	eStr, _ := m["e"].(string)
	nBytes, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(nStr, "="))
	if err != nil {
		return nil, err
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(eStr, "="))
	if err != nil {
		return nil, err
	}
	e := 0
	for _, b := range eBytes {
		e = e<<8 | int(b)
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: e}, nil
}

// rsaFromX5C, header.x5c[0]'daki self-signed sertifikadan public key alır (VULN-05).
func rsaFromX5C(raw interface{}) (*rsa.PublicKey, error) {
	arr, ok := raw.([]interface{})
	if !ok || len(arr) == 0 {
		return nil, ErrBadSig
	}
	certB64, _ := arr[0].(string)
	der, err := base64.StdEncoding.DecodeString(certB64)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, ErrBadSig
	}
	return pub, nil
}

// fetchRSAFromJKU, jku URL'inden JWKS indirir (VULN-06: SSRF + saldırgan anahtarı).
func fetchRSAFromJKU(url string) (*rsa.PublicKey, error) {
	resp, err := httpClient.Get(url) // BİLEREK: URL allow-list yok -> SSRF
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var jwks struct {
		Keys []map[string]interface{} `json:"keys"`
	}
	if err := json.Unmarshal(body, &jwks); err != nil || len(jwks.Keys) == 0 {
		return nil, ErrBadSig
	}
	return rsaFromJWK(jwks.Keys[0])
}

// fetchRSAFromX5U, x5u URL'inden PEM sertifika indirir (VULN-06).
func fetchRSAFromX5U(url string) (*rsa.PublicKey, error) {
	resp, err := httpClient.Get(url) // BİLEREK: URL allow-list yok -> SSRF
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	block, _ := pem.Decode(body)
	if block == nil {
		return nil, ErrBadSig
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, ErrBadSig
	}
	return pub, nil
}
