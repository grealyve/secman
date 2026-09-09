package vulnjwt

// Package vulnjwt, Secman projesine BİLEREK yerleştirilmiş zafiyetli bir JWT
// doğrulama katmanıdır. Amaç: DAST tarayıcısının (worker) crAPI üzerinde İZOLE
// edemediği JWT zafiyetlerini (Algorithm Confusion, kid injection, embedded-key
// forgery, jku/x5u SSRF, alg:none, claim/temporal validation eksikliği) canlı ve
// izole test edilebilir bir hedefte üretmek.
//
// GÜVENLİK UYARISI: Bu paket kasıtlı olarak zafiyetlidir. ASLA production'da
// kullanılmamalıdır. Her zafiyet kaynak kodda `// VULN-NN` etiketiyle işaretlidir.

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"strings"
	"sync"

	"github.com/grealyve/secman/logger"
)

var (
	// serverPrivateKey: baseline RS256 token'ları imzalamak için kullanılır.
	serverPrivateKey *rsa.PrivateKey
	// serverPublicPEM: JWKS/algorithm-confusion için dışa açık PEM (PKIX) public key.
	serverPublicPEM []byte
	initOnce        sync.Once

	// WeakHMACWordlist: zayıf/tahmin edilebilir HMAC secret sözlüğü (weak-hmac vektörü).
	WeakHMACWordlist = []string{"secret", "secman", "changeme", "password", "jwt", "admin"}

	// kidKeyTable: kid -> key eşlemesini simüle eden "DB tablosu".
	kidKeyTable = map[string]string{
		"key-2024-prod": "s3rv3r-hmac-signing-key-2024",
		"key-2023-prod": "legacy-hmac-key-2023",
	}
)

// InitKeys sunucu RSA anahtar çiftini üretir. main.go'dan bir kez çağrılır.
func InitKeys() {
	initOnce.Do(func() {
		pk, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			logger.Log.Errorf("vulnjwt: RSA anahtar üretilemedi: %v", err)
			return
		}
		serverPrivateKey = pk

		pubDER, err := x509.MarshalPKIXPublicKey(&pk.PublicKey)
		if err != nil {
			logger.Log.Errorf("vulnjwt: public key marshal edilemedi: %v", err)
			return
		}
		serverPublicPEM = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
		logger.Log.Infoln("vulnjwt: zafiyetli JWT anahtarları hazırlandı (RS256 baseline).")
	})
}

// PrivateKey baseline imzalama anahtarını döner.
func PrivateKey() *rsa.PrivateKey { return serverPrivateKey }

// PublicPEM dışa açık public key PEM'ini döner (algorithm-confusion HMAC secret'i olur).
func PublicPEM() []byte { return serverPublicPEM }

// JWKS, RS256 public key'i JWK Set olarak döner (/.well-known/jwks.json).
func JWKS() map[string]interface{} {
	n := base64.RawURLEncoding.EncodeToString(serverPublicKey().N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(serverPublicKey().E)).Bytes())
	return map[string]interface{}{
		"keys": []map[string]interface{}{
			{
				"kty": "RSA",
				"use": "sig",
				"alg": "RS256",
				"kid": "secman-baseline-2024",
				"n":   n,
				"e":   e,
			},
		},
	}
}

func serverPublicKey() *rsa.PublicKey { return &serverPrivateKey.PublicKey }

// resolveKidKey, `kid` header'ından doğrulama anahtarı türetir. BİLEREK zafiyetlidir:
// path-traversal ile boş anahtar, SQL injection ile saldırgan-kontrollü anahtar,
// ve store'da bulunamayınca kid değerinin kendisini anahtar olarak döner.
func resolveKidKey(kid string) []byte {
	// VULN-04a (kid empty-key / path traversal): kid bir dosya yolu gibi çözülür.
	// `/dev/null`, `..`  gibi sentinel'ler 0-bayt (boş) anahtar döndürür — saldırgan
	// token'ı boş string ile HMAC imzalayıp geçebilir.
	if strings.Contains(kid, "..") || strings.Contains(kid, "/dev/null") || strings.HasPrefix(kid, "/") {
		logger.Log.Debugf("vulnjwt: kid path olarak çözüldü -> boş anahtar: %q", kid)
		return []byte("")
	}

	// VULN-04b (kid SQL injection): kid doğrudan SQL sorgusuna gömülür. UNION SELECT
	// ile saldırgan, döndürülecek anahtarı kendisi belirler.
	//   SELECT key FROM jwt_keys WHERE kid = '<kid>'
	if idx := strings.Index(strings.ToUpper(kid), "UNION SELECT"); idx != -1 {
		// UNION SELECT 'attacker_secret' -- şeklindeki payload'tan sabiti çıkar.
		if q := extractFirstQuoted(kid[idx:]); q != "" {
			logger.Log.Debugf("vulnjwt: kid SQLi -> saldırgan anahtarı döndü: %q", q)
			return []byte(q)
		}
	}

	// Normal yol: "DB"den anahtar getir.
	if k, ok := kidKeyTable[kid]; ok {
		return []byte(k)
	}

	// VULN-04c (kid-as-key): store'da yoksa kid'in kendisi HMAC anahtarı olur.
	logger.Log.Debugf("vulnjwt: kid store'da yok -> kid değeri anahtar olarak kullanıldı: %q", kid)
	return []byte(kid)
}

// extractFirstQuoted, bir string içindeki ilk tek-tırnaklı literali döner.
func extractFirstQuoted(s string) string {
	first := strings.Index(s, "'")
	if first == -1 {
		return ""
	}
	rest := s[first+1:]
	second := strings.Index(rest, "'")
	if second == -1 {
		return ""
	}
	return rest[:second]
}
