package xiaomi

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
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
		if err := r.ParseForm(); err != nil {
			t.Errorf("ParseForm() error = %v", err)
		}
		if got := r.Form.Get("ssecurity"); got != "c2VjcmV0" {
			t.Errorf("ssecurity = %q", got)
		}
		if got := r.Header.Get("X-XIAOMI-PROTOCAL-FLAG-CLI"); got != "PROTOCAL-HTTP2" {
			t.Errorf("protocol header = %q", got)
		}
		if got := r.Header.Get("MIOT-ENCRYPT-ALGORITHM"); got != "ENCRYPT-RC4" {
			t.Errorf("encryption header = %q", got)
		}
		if got := r.Header.Get("Cookie"); !strings.Contains(got, "yetAnotherServiceToken=service-token") {
			t.Errorf("auth cookies = %q", got)
		}
		w.WriteHeader(421)
	}))
	defer server.Close()

	cloud := NewCloud("xiaomiio")
	cloud.ssecurity = []byte("secret")
	cloud.cookies = "serviceToken=service-token; yetAnotherServiceToken=service-token"
	_, err := cloud.Request(server.URL, "/test", "{}", nil)
	if !IsUnauthorized(err) {
		t.Fatalf("Request() error = %v, want ErrUnauthorized", err)
	}
	if !IsUnauthorized(fmt.Errorf("wrapped: %w", err)) {
		t.Fatal("IsUnauthorized() did not recognize a wrapped error")
	}
}

func TestFinishVerifyFollowsConfirmPhoneSkipURL(t *testing.T) {
	var skipped bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/verify":
			http.SetCookie(w, &http.Cookie{Name: "userId", Value: "verified-user", Path: "/"})
			http.SetCookie(w, &http.Cookie{Name: "passToken", Value: "verified-token", Path: "/"})
			w.Header().Set("Extension-Pragma", `{"ssecurity":"dmVyaWZ5LXNlY3JldA=="}`)
			http.Redirect(w, r, "/fe/confirm?skipUrl=%2Fdone", http.StatusFound)
		case "/fe/confirm":
			w.WriteHeader(http.StatusOK)
		case "/done":
			skipped = true
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	cloud := NewCloud("xiaomiio")
	if err := cloud.finishVerify(server.URL + "/verify"); err != nil {
		t.Fatalf("finishVerify() error = %v", err)
	}
	if !skipped {
		t.Fatal("finishVerify() did not follow the confirm-phone skip URL")
	}
	userID, token := cloud.UserToken()
	if userID != "verified-user" || token != "verified-token" {
		t.Fatalf("verification credentials were not preserved: %q, %q", userID, token)
	}
	if string(cloud.ssecurity) != "verify-secret" {
		t.Fatalf("verification ssecurity was not preserved: %q", cloud.ssecurity)
	}
}

func TestConfirmPhoneSkipURL(t *testing.T) {
	u, err := url.Parse("https://account.xiaomi.com/fe/confirm?skipUrl=%2Fpass%2FserviceLogin")
	if err != nil {
		t.Fatal(err)
	}
	if got := confirmPhoneSkipURL(u); got != "/pass/serviceLogin" {
		t.Fatalf("confirmPhoneSkipURL() = %q", got)
	}

	u.Path = "/pass/serviceLogin"
	if got := confirmPhoneSkipURL(u); got != "" {
		t.Fatalf("confirmPhoneSkipURL() accepted non-confirmation URL: %q", got)
	}
}

func TestJSONScalarString(t *testing.T) {
	for name, tc := range map[string]struct {
		raw  string
		want string
	}{
		"string": {raw: `"123456"`, want: "123456"},
		"number": {raw: "123456", want: "123456"},
		"null":   {raw: "null", want: ""},
		"object": {raw: "{}", want: ""},
	} {
		t.Run(name, func(t *testing.T) {
			if got := jsonScalarString([]byte(tc.raw)); got != tc.want {
				t.Fatalf("jsonScalarString(%s) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}
