package vulnjwt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"time"
)

// IssueBaselineToken, baseline RS256 token üretir. BİLEREK zafiyetli tasarım:
//   - VULN-07: exp 7 GÜN (aşırı ömür; çalınan token uzun süre replay edilir)
//   - VULN-16: `jti` YOK (replay/revocation koruması yok)
//   - VULN-16: payload'da PII taşınır (email) — JWT imzalı ama şifreli değil
//   - VULN-10/12: `role` ve `sub` yetki/kimlik kararı için payload'dan okunur
func IssueBaselineToken(sub, email, role string) (string, error) {
	now := time.Now()
	claims := map[string]interface{}{
		"sub":   sub,
		"email": email, // VULN-16: PII token payload'ında
		"role":  role,  // VULN-10: yetki claim'i
		"aud":   "secman-api",
		"iss":   "secman-auth",
		"iat":   now.Unix(),
		"exp":   now.Add(7 * 24 * time.Hour).Unix(), // VULN-07: 7 günlük aşırı ömür
		// jti bilerek eklenmedi -> VULN-16 predictable/missing jti
	}
	header := map[string]interface{}{"alg": "RS256", "typ": "JWT", "kid": "secman-baseline-2024"}
	return signRS256(header, claims)
}

// IssueUserToken, gerçek bir kullanıcı için (DB'den gelen id/email/role/company) app
// oturum token'ı üretir. Bu, merge sonrası SecMan'in TEK auth token'ıdır: /users/login
// bunu döner ve middlewares.Authentication bunu doğrular. BİLEREK zafiyetli tasarım
// IssueBaselineToken ile aynıdır (RS256, 7g exp, jti yok, PII payload'da); ek olarak
// uygulama kimliği için `id` (UUID) ve tenant izolasyonu için `tenant_id` taşır.
//   - VULN-10: role claim'i yetki kararı için (privilege escalation)
//   - VULN-12: sub/id claim'i kimlik kararı için (subject-confusion BOLA)
//   - VULN-13: tenant_id claim'i tenant izolasyonu için (tenant BOLA)
func IssueUserToken(id, email, role, tenantID string) (string, error) {
	now := time.Now()
	claims := map[string]interface{}{
		"id":        id,    // uygulama kimliği (UUID) — forge edilince BOLA
		"sub":       email, // subject = email
		"email":     email, // VULN-16: PII token payload'ında
		"role":      role,  // VULN-10: yetki claim'i
		"tenant_id": tenantID,
		"aud":       "secman-api",
		"iss":       "secman-auth",
		"iat":       now.Unix(),
		"exp":       now.Add(7 * 24 * time.Hour).Unix(), // VULN-07: 7 günlük aşırı ömür
		// jti bilerek eklenmedi -> VULN-16 predictable/missing jti
	}
	header := map[string]interface{}{"alg": "RS256", "typ": "JWT", "kid": "secman-baseline-2024"}
	return signRS256(header, claims)
}

func signRS256(header, claims map[string]interface{}) (string, error) {
	hb, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	cb, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signingInput := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(cb)
	h := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, serverPrivateKey, crypto.SHA256, h[:])
	if err != nil {
		return "", err
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}
