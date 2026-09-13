package vulnjwt

import "testing"

// IssueUserToken, gerçek kullanıcı için (id + sub/email/role/tenant) zafiyetli RS256
// baseline token üretir. Merge sonrası app auth'u bu token'a dayanır.
func TestIssueUserToken_BaselineAcceptedAndCarriesClaims(t *testing.T) {
	InitKeys()

	tok, err := IssueUserToken("7a1e5c2d-0b3f-4d6e-9a8c-1f2e3d4c5b6a", "secman-admin@lutenix.local", "admin", "aab6068a-0758-4497-9592-3c606990506e")
	if err != nil {
		t.Fatalf("IssueUserToken: %v", err)
	}

	vt, err := VerifyVulnerable(tok)
	if err != nil {
		t.Fatalf("baseline reddedildi: %v", err)
	}
	if vt.Claims["id"] != "7a1e5c2d-0b3f-4d6e-9a8c-1f2e3d4c5b6a" {
		t.Errorf("id claim eksik/yanlış: %v", vt.Claims["id"])
	}
	if vt.Claims["sub"] != "secman-admin@lutenix.local" {
		t.Errorf("sub claim yanlış: %v", vt.Claims["sub"])
	}
	if vt.Claims["role"] != "admin" {
		t.Errorf("role claim yanlış: %v", vt.Claims["role"])
	}
	if vt.Claims["tenant_id"] != "aab6068a-0758-4497-9592-3c606990506e" {
		t.Errorf("tenant_id claim yanlış: %v", vt.Claims["tenant_id"])
	}

	// Negative control: imza bozulunca reddedilmeli (endpoint imzayı gerçekten doğruluyor).
	bad := tok[:len(tok)-4] + "AAAA"
	if _, err := VerifyVulnerable(bad); err == nil {
		t.Fatalf("negative control KABUL edildi (olmamalı)")
	}
}
