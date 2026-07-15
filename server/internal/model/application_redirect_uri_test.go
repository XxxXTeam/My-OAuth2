package model

import "testing"

func TestApplication_ValidateRedirectURI_ExactMatch(t *testing.T) {
	app := &Application{}
	app.SetRedirectURIs([]string{"http://localhost:9000/callback"})

	if !app.ValidateRedirectURI("http://localhost:9000/callback") {
		t.Fatal("expected exact redirect_uri match")
	}
}

func TestApplication_ValidateRedirectURI_RejectsSameOriginSubpath(t *testing.T) {
	app := &Application{}
	app.SetRedirectURIs([]string{"http://localhost:9000/callback"})

	if app.ValidateRedirectURI("http://localhost:9000/sso/callback") {
		t.Fatal("expected same-origin subpath redirect_uri to be rejected")
	}
}

func TestApplication_ValidateRedirectURI_RejectsDifferentOrigin(t *testing.T) {
	app := &Application{}
	app.SetRedirectURIs([]string{"http://localhost:9000/callback"})

	if app.ValidateRedirectURI("https://evil.example/sso/callback") {
		t.Fatal("expected different-origin redirect_uri to be rejected")
	}
	if app.ValidateRedirectURI("http://localhost:9001/sso/callback") {
		t.Fatal("expected different-port redirect_uri to be rejected")
	}
}

func TestApplication_ValidateRedirectURI_RejectsUnsafeURI(t *testing.T) {
	app := &Application{}
	app.SetRedirectURIs([]string{"http://localhost:9000/callback"})

	for _, uri := range []string{
		"javascript:alert(1)",
		"data:text/html,test",
		"http://localhost:9000/../evil",
		"http://user@localhost:9000/sso/callback",
	} {
		if app.ValidateRedirectURI(uri) {
			t.Fatalf("expected unsafe redirect_uri %q to be rejected", uri)
		}
	}
}

func TestApplication_ValidatePostLogoutRedirectURI_ExactMatch(t *testing.T) {
	app := &Application{}
	app.SetPostLogoutRedirectURIs([]string{"http://localhost:9000/logout-callback"})

	if !app.ValidatePostLogoutRedirectURI("http://localhost:9000/logout-callback") {
		t.Fatal("expected exact post_logout_redirect_uri match")
	}
}

func TestApplication_ValidatePostLogoutRedirectURI_RejectsOAuthRedirectURI(t *testing.T) {
	app := &Application{}
	app.SetRedirectURIs([]string{"http://localhost:9000/callback"})
	app.SetPostLogoutRedirectURIs([]string{"http://localhost:9000/logout-callback"})

	if app.ValidatePostLogoutRedirectURI("http://localhost:9000/callback") {
		t.Fatal("expected OAuth redirect_uri to be rejected as post_logout_redirect_uri")
	}
}
