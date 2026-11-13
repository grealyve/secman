package routes

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func internalRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	InternalRoutes(router)
	return router
}

func getJSON(t *testing.T, router *gin.Engine, path string) (int, map[string]any) {
	t.Helper()
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	body := map[string]any{}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("GET %s: body is not a JSON object: %v (%s)", path, err, rec.Body.String())
	}
	return rec.Code, body
}

func TestInternalDebugConfigAnswersWithoutAuth(t *testing.T) {
	code, body := getJSON(t, internalRouter(), "/api/v1/internal/debug/config")
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	for _, key := range []string{"service", "build", "environment", "features"} {
		if _, ok := body[key]; !ok {
			t.Errorf("missing %q in %v", key, body)
		}
	}
}

func TestInternalTenantFlagsEchoesTheTenant(t *testing.T) {
	code, body := getJSON(t, internalRouter(), "/api/v1/internal/tenants/acme-42/flags")
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	if body["tenant_id"] != "acme-42" {
		t.Errorf("tenant_id = %v, want acme-42", body["tenant_id"])
	}
	if _, ok := body["flags"].(map[string]any); !ok {
		t.Errorf("flags is not an object: %v", body["flags"])
	}
}

func TestInternalRoutesAreGetOnly(t *testing.T) {
	rec := httptest.NewRecorder()
	internalRouter().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/internal/debug/config", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("POST status = %d, want 404 (only GET is routed)", rec.Code)
	}
}
