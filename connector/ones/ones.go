package ones

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/dexidp/dex/connector"
	"github.com/dexidp/dex/pkg/log"
	"io"
	"net"
	"net/http"
	"time"
)

type Config struct {
	BaseURL string `json:"baseURL"`
	// UsernamePrompt allows users to override the username attribute (displayed
	// in the username/password prompt). If unset, the handler will use.
	// "Username".
	UsernamePrompt string `json:"usernamePrompt"`
	// PreferredUsernameField allows users to set the field to any of the
	// following values: "id", "name" or "email".
	// If unset, the preferred_username field will remain empty.
	PreferredUsernameField string `json:"preferredUsernameField"`
	SkipTLSVerify          bool   `json:"skipTLSVerify"`
}

// Open returns a strategy for logging in through ONES
func (c *Config) Open(_ string, logger log.Logger) (connector.Connector, error) {
	if c.BaseURL == "" {
		return nil, fmt.Errorf("ones: no baseURL provided for ones connector")
	}
	return &onesConnector{Config: *c, logger: logger}, nil
}

type user struct {
	Uuid     string `json:"uuid"`
	Email    string `json:"email"`
	Name     string `json:"name"`
	Token    string `json:"token"`
	IdNumber string `json:"id_number"`
	Avatar   string `json:"avatar"`
}
type onesLoginResponse struct {
	User user
}
type onesConnector struct {
	Config
	logger log.Logger
}

func (o *onesConnector) Prompt() string {
	return o.UsernamePrompt
}
func (o *onesConnector) onesAPIClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			TLSClientConfig:       &tls.Config{InsecureSkipVerify: o.SkipTLSVerify},
		},
	}
}
func (o *onesConnector) Login(ctx context.Context, s connector.Scopes, username, password string) (identity connector.Identity, validPassword bool, err error) {
	req, err := o.onesLoginRequest(ctx, "POST", "/project/api/project/auth/login", struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}{Email: username, Password: password})
	if err != nil {
		return connector.Identity{}, false, fmt.Errorf("ones: new login api request %v", err)
	}
	response, err := o.onesAPIClient().Do(req)
	if err != nil {
		return connector.Identity{}, false, fmt.Errorf("ones: login api request error %v", err)
	}
	defer response.Body.Close()

	validateOnesResponse, err := o.validateOnesResponse(response)
	if err != nil {
		return connector.Identity{}, false, fmt.Errorf("ones: login api request error %v", err)
	}
	var loginResp onesLoginResponse

	if err := json.Unmarshal(validateOnesResponse, &loginResp); err != nil {
		return connector.Identity{}, false, fmt.Errorf("unmarshal auth pass response: %d %v %q", response.StatusCode, err, string(validateOnesResponse))
	}
	request, err := o.onesLoginRequest(ctx, "GET", "/project/api/project/users/me", nil)
	if err != nil {
		return connector.Identity{}, false, fmt.Errorf("ones: new login api request %v", err)
	}
	request.Header.Set("Ones-Auth-Token", loginResp.User.Token)
	request.Header.Set("Ones-User-Id", loginResp.User.Uuid)
	response, err = o.onesAPIClient().Do(request)
	defer response.Body.Close()
	onesUserInfoResponse, err := o.validateOnesResponse(response)
	if err != nil {
		return connector.Identity{}, false, fmt.Errorf("ones: login api request error %v", err)
	}
	var userResp user
	if err := json.Unmarshal(onesUserInfoResponse, &userResp); err != nil {
		return connector.Identity{}, false, fmt.Errorf("unmarshal get user info response: %d %v %q", response.StatusCode, err, string(validateOnesResponse))
	}
	identity = connector.Identity{
		UserID:        userResp.IdNumber,
		Username:      userResp.Name,
		Email:         userResp.Email,
		EmailVerified: true,
	}
	switch o.PreferredUsernameField {
	case "id":
		identity.PreferredUsername = userResp.IdNumber
	case "name":
		identity.PreferredUsername = userResp.Name
	case "email":
		identity.PreferredUsername = userResp.Email
	default:
		if o.PreferredUsernameField != "" {
			o.logger.Warnf("preferred_username left empty. Invalid crowd field mapped to preferred_username: %s", o.PreferredUsernameField)
		}
	}
	return identity, true, nil
}

// onesLoginRequest create a http.Request with basic auth, json payload and Accept header
func (o *onesConnector) onesLoginRequest(ctx context.Context, method string, apiURL string, jsonPayload interface{}) (*http.Request, error) {
	var body io.Reader
	if jsonPayload != nil {
		jsonData, err := json.Marshal(jsonPayload)
		if err != nil {
			return nil, fmt.Errorf("ones: marshal API json payload: %v", err)
		}
		body = bytes.NewReader(jsonData)
	}

	req, err := http.NewRequest(method, fmt.Sprintf("%s%s", o.BaseURL, apiURL), body)
	if err != nil {
		return nil, fmt.Errorf("new API req: %v", err)
	}
	req = req.WithContext(ctx)

	req.Header.Set("Accept", "application/json")
	if jsonPayload != nil {
		req.Header.Set("Content-type", "application/json")
	}
	return req, nil
}

// validateOnesResponse validates unique not JSON responses from API
func (o *onesConnector) validateOnesResponse(resp *http.Response) ([]byte, error) {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("ones: read user body: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		o.logger.Debugf("ones response validation failed: %s", string(body))
		return nil, fmt.Errorf("认证失败！ 请检查用户名密码！")
	}

	return body, nil
}
