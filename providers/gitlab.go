package providers

import (
	"fmt"
	"log"
	"net/http"
	"net/url"

	"github.com/pusher/oauth2_proxy/api"
)

// GitLabProvider represents an GitLab based Identity Provider
type GitLabProvider struct {
	*ProviderData
}

// NewGitLabProvider initiates a new GitLabProvider
func NewGitLabProvider(p *ProviderData) *GitLabProvider {
	p.ProviderName = "GitLab"
	if p.LoginURL == nil || p.LoginURL.String() == "" {
		p.LoginURL = &url.URL{
			Scheme: "https",
			Host:   "gitlab.com",
			Path:   "/oauth/authorize",
		}
	}
	if p.RedeemURL == nil || p.RedeemURL.String() == "" {
		p.RedeemURL = &url.URL{
			Scheme: "https",
			Host:   "gitlab.com",
			Path:   "/oauth/token",
		}
	}
	if p.ValidateURL == nil || p.ValidateURL.String() == "" {
		p.ValidateURL = &url.URL{
			Scheme: "https",
			Host:   "gitlab.com",
			Path:   "/api/v4/user",
		}
	}

	if p.Scope == "" {
		p.Scope = "read_user"
	}
	return &GitLabProvider{ProviderData: p}
}

func (p *GitLabProvider) SupportsPersonalAccessTokens() bool {
	return true
}

func (p *GitLabProvider) makeAccessTokenParameter(s *SessionState) (string, error) {
	if s.AccessToken != "" {
		return "access_token=" + s.AccessToken, nil
	} else if s.PersonalAccessToken != "" {
		return "private_token=" + s.PersonalAccessToken, nil
	} else {
		return "", fmt.Errorf("no access token")
	}
}

func (p *GitLabProvider) ValidateSessionState(s *SessionState) bool {
	if s.AccessToken != "" {
		return validateToken(p, s.AccessToken, nil)
	} else if s.PersonalAccessToken != "" {
		hdr := http.Header{}
		hdr.Add("Private-Token", s.PersonalAccessToken)
		return validateToken(p, s.PersonalAccessToken, hdr)
	} else {
		return false
	}
}

// GetEmailAddress returns the Account email address
func (p *GitLabProvider) GetEmailAddress(s *SessionState) (string, error) {
    accessTokenParam, err := p.makeAccessTokenParameter(s)
    if err != nil {
		log.Printf("failed building request %s", err)
		return "", err
	}

	req, err := http.NewRequest("GET",
		p.ValidateURL.String()+"?"+accessTokenParam, nil)
	if err != nil {
		log.Printf("failed building request %s", err)
		return "", err
	}
	json, err := api.Request(req)
	if err != nil {
		log.Printf("failed making request %s", err)
		return "", err
	}
	return json.Get("email").String()
}

// GetUserName returns the Account username
func (p *GitLabProvider) GetUserName(s *SessionState) (string, error) {
	accessTokenParam, err := p.makeAccessTokenParameter(s)
	if err != nil {
		log.Printf("failed building request %s", err)
		return "", err
	}

	req, err := http.NewRequest("GET",
		p.ValidateURL.String()+"?"+accessTokenParam, nil)
	if err != nil {
		log.Printf("failed building request %s", err)
		return "", err
	}
	json, err := api.Request(req)
	if err != nil {
		log.Printf("failed making request %s", err)
		return "", err
	}
	return json.Get("username").String()
}
