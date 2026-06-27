package oauth

import (
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

const googleUserInfoEndpoint = "https://openidconnect.googleapis.com/v1/userinfo"

// GoogleScopes are the default OpenID Connect scopes for Google sign-in.
var GoogleScopes = []string{
	"openid",
	"email",
	"profile",
}

// NewGoogleOAuthConfig builds an oauth2.Config for Google sign-in.
func NewGoogleOAuthConfig(clientID, clientSecret, redirectURL string) *oauth2.Config {
	if clientID == "" || clientSecret == "" || redirectURL == "" {
		return nil
	}
	return &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Endpoint:     google.Endpoint,
		Scopes:       GoogleScopes,
	}
}

// IsGoogleConfigured reports whether Google OAuth client settings are complete.
func IsGoogleConfigured(cfg *oauth2.Config) bool {
	return cfg != nil && cfg.ClientID != "" && cfg.ClientSecret != "" && cfg.RedirectURL != ""
}
