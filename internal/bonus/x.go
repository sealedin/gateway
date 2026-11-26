package bonus

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

const (
	// DefaultAuthorizeURL is X's sign-in page; tests point elsewhere.
	DefaultAuthorizeURL = "https://x.com/i/oauth2/authorize"
	// DefaultAPIBase is X's API; tests point elsewhere.
	DefaultAPIBase = "https://api.x.com"

	// follows.read is what connection_status needs; tweet.read rides along because X refuses users.read without it.
	scopes          = "users.read tweet.read follows.read"
	maxReplyBytes   = 64 << 10
	statusFollowing = "following"
)

// X is the client of the three X calls a claim makes. An empty ClientSecret means a public client, which names itself in the
// token request's body instead of authenticating.
type X struct {
	ClientID     string
	ClientSecret string
	AuthorizeURL string
	APIBase      string
	HTTP         *http.Client
}

// Account is the signed-in X account.
type Account struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
}

// AuthorizeLink is where the browser goes to sign in, with the PKCE challenge of verifier.
func (x *X) AuthorizeLink(redirectURI, state, verifier string) string {
	challenge := sha256.Sum256([]byte(verifier))
	query := url.Values{
		"response_type":         {"code"},
		"client_id":             {x.ClientID},
		"redirect_uri":          {redirectURI},
		"scope":                 {scopes},
		"state":                 {state},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(challenge[:])},
		"code_challenge_method": {"S256"},
	}
	return x.AuthorizeURL + "?" + query.Encode()
}

// Exchange turns the callback's code into the user's access token, which lives only for this claim.
func (x *X) Exchange(ctx context.Context, redirectURI, code, verifier string) (string, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"code_verifier": {verifier},
	}
	if x.ClientSecret == "" {
		form.Set("client_id", x.ClientID)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, x.APIBase+"/2/oauth2/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("x: token: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if x.ClientSecret != "" {
		req.SetBasicAuth(url.QueryEscape(x.ClientID), url.QueryEscape(x.ClientSecret))
	}
	var reply struct {
		AccessToken string `json:"access_token"`
	}
	if err = x.do(req, "token", &reply); err != nil {
		return "", err
	}
	if reply.AccessToken == "" {
		return "", errors.New("x: token: reply carries no access token")
	}
	return reply.AccessToken, nil
}

// Me is the account behind token.
func (x *X) Me(ctx context.Context, token string) (Account, error) {
	var reply struct {
		Data Account `json:"data"`
	}
	if err := x.get(ctx, token, "/2/users/me?user.fields=created_at", "me", &reply); err != nil {
		return Account{}, err
	}
	if reply.Data.ID == "" {
		return Account{}, errors.New("x: me: reply carries no id")
	}
	return reply.Data, nil
}

// Follows reports whether the account behind token follows username: one user object read, whatever the size of either list.
func (x *X) Follows(ctx context.Context, token, username string) (bool, error) {
	var reply struct {
		Data struct {
			ConnectionStatus []string `json:"connection_status"`
		} `json:"data"`
	}
	path := "/2/users/by/username/" + url.PathEscape(username) + "?user.fields=connection_status"
	if err := x.get(ctx, token, path, "follows", &reply); err != nil {
		return false, err
	}
	return slices.Contains(reply.Data.ConnectionStatus, statusFollowing), nil
}

func (x *X) get(ctx context.Context, token, path, name string, reply any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, x.APIBase+path, http.NoBody)
	if err != nil {
		return fmt.Errorf("x: %s: %w", name, err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	return x.do(req, name, reply)
}

// do never puts a body or a URL in an error: either can carry a code or a token.
func (x *X) do(req *http.Request, name string, reply any) error {
	resp, err := x.HTTP.Do(req)
	if err != nil {
		if urlErr, ok := errors.AsType[*url.Error](err); ok {
			err = urlErr.Err
		}
		return fmt.Errorf("x: %s: %w", name, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("x: %s: status %d", name, resp.StatusCode)
	}
	if err = json.NewDecoder(io.LimitReader(resp.Body, maxReplyBytes)).Decode(reply); err != nil {
		return fmt.Errorf("x: %s: invalid reply", name)
	}
	return nil
}
