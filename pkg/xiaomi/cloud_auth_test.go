package xiaomi

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFinishAuthPreservesSeededCredentials(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "cUserId", Value: "cloud-user", Path: "/"})
		http.SetCookie(w, &http.Cookie{Name: "serviceToken", Value: "service-token", Path: "/"})
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cloud := NewCloud("xiaomiio")
	cloud.userID = "123456"
	cloud.passToken = "persisted-token"
	cloud.ssecurity = []byte("secret")

	if err := cloud.finishAuth(server.URL); err != nil {
		t.Fatalf("finishAuth() error = %v", err)
	}

	userID, token := cloud.UserToken()
	if userID != "123456" || token != "persisted-token" {
		t.Fatalf("UserToken() = %q, %q", userID, token)
	}
	if !strings.Contains(cloud.cookies, "cUserId=cloud-user") ||
		!strings.Contains(cloud.cookies, "serviceToken=service-token") {
		t.Fatalf("auth cookies were not collected: %q", cloud.cookies)
	}
}

func TestFinishAuthRejectsIncompleteCredentials(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cloud := NewCloud("xiaomiio")
	err := cloud.finishAuth(server.URL)
	if err == nil || !strings.Contains(err.Error(), "incomplete login response") {
		t.Fatalf("finishAuth() error = %v", err)
	}
}

func TestLoginWithTokenRejectsEmptyCredentials(t *testing.T) {
	cloud := NewCloud("xiaomiio")
	if err := cloud.LoginWithToken("", ""); err == nil {
		t.Fatal("LoginWithToken() accepted empty credentials")
	}
}

func TestRequestMarksAuthorizationFailures(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(421)
	}))
	defer server.Close()

	cloud := NewCloud("xiaomiio")
	cloud.ssecurity = []byte("secret")
	_, err := cloud.Request(server.URL, "/test", "{}", nil)
	if !IsUnauthorized(err) {
		t.Fatalf("Request() error = %v, want ErrUnauthorized", err)
	}
	if !IsUnauthorized(fmt.Errorf("wrapped: %w", err)) {
		t.Fatal("IsUnauthorized() did not recognize a wrapped error")
	}
}
