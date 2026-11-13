package controller

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func healthBody(t *testing.T, target string) map[string]any {
	t.Helper()
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/health", NewSystemController().Health)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s: status = %d, want 200", target, rec.Code)
	}
	body := map[string]any{}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("GET %s: body is not a JSON object: %v", target, err)
	}
	return body
}

func TestHealthKeepsItsDocumentedShape(t *testing.T) {
	body := healthBody(t, "/health")
	if body["status"] != "ok" || body["message"] != "SecMan is running" {
		t.Errorf("unexpected health body: %v", body)
	}
	if _, ok := body["runtime"]; ok {
		t.Errorf("runtime details must not appear without verbose: %v", body)
	}
}

func TestHealthVerboseAddsRuntimeDetails(t *testing.T) {
	body := healthBody(t, "/health?verbose=true")
	runtime, ok := body["runtime"].(map[string]any)
	if !ok {
		t.Fatalf("runtime is not an object: %v", body)
	}
	for _, key := range []string{"go_version", "goroutines", "uptime_seconds"} {
		if _, ok := runtime[key]; !ok {
			t.Errorf("missing %q in runtime %v", key, runtime)
		}
	}
}

func TestHealthIgnoresVerboseFalse(t *testing.T) {
	if _, ok := healthBody(t, "/health?verbose=false")["runtime"]; ok {
		t.Errorf("verbose=false must not add runtime details")
	}
}
