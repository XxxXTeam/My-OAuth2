package oauth2

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

/* DeviceAuthResponse 设备授权响应结构 (RFC 8628) */
type DeviceAuthResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete,omitempty"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

/* DeviceFlowError Device Flow 专用错误类型 */
type DeviceFlowError struct {
	Code        string
	Description string
}

func (e *DeviceFlowError) Error() string {
	return fmt.Sprintf("device flow: %s - %s", e.Code, e.Description)
}

/* IsAuthorizationPending 用户尚未授权 */
func (e *DeviceFlowError) IsAuthorizationPending() bool {
	return e.Code == "authorization_pending"
}

/* IsSlowDown 轮询过于频繁 */
func (e *DeviceFlowError) IsSlowDown() bool {
	return e.Code == "slow_down"
}

/* IsAccessDenied 用户拒绝授权 */
func (e *DeviceFlowError) IsAccessDenied() bool {
	return e.Code == "access_denied"
}

/* IsExpired 设备码已过期 */
func (e *DeviceFlowError) IsExpired() bool {
	return e.Code == "expired_token"
}

// DeviceAuthorization initiates the device authorization flow (RFC 8628)
// Returns device code info that should be displayed to the user
func (c *Client) DeviceAuthorization(ctx context.Context, scope string) (*DeviceAuthResponse, error) {
	c.logger.Debug("Starting device authorization flow")

	// Build request
	data := url.Values{}
	data.Set("client_id", c.config.ClientID)
	if scope != "" {
		data.Set("scope", scope)
	}

	// Get device authorization endpoint
	deviceURL := c.GetAPIBaseURL() + "/oauth/device/code"

	httpReq, err := http.NewRequestWithContext(ctx, "POST", deviceURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("oauth2: failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("oauth2: request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("oauth2: failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var errResp struct {
			Error       string `json:"error"`
			Description string `json:"error_description"`
		}
		if json.Unmarshal(body, &errResp) == nil && errResp.Error != "" {
			return nil, &DeviceFlowError{Code: errResp.Error, Description: errResp.Description}
		}
		return nil, fmt.Errorf("oauth2: device authorization failed with status %d", resp.StatusCode)
	}

	var result DeviceAuthResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("oauth2: failed to parse response: %w", err)
	}

	c.logger.Info("Device authorization initiated",
		"user_code", result.UserCode,
		"verification_uri", result.VerificationURI)

	return &result, nil
}

// PollDeviceToken polls for the token after user authorization
// This should be called repeatedly until success, access_denied, or expired_token
func (c *Client) PollDeviceToken(ctx context.Context, deviceCode string, interval int) (*Token, error) {
	c.logger.Debug("Polling for device token")

	data := url.Values{}
	data.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
	data.Set("device_code", deviceCode)
	data.Set("client_id", c.config.ClientID)

	httpReq, err := http.NewRequestWithContext(ctx, "POST", c.config.TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("oauth2: failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("oauth2: request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("oauth2: failed to read response: %w", err)
	}

	// Check for errors
	if resp.StatusCode != http.StatusOK {
		var errResp struct {
			Error       string `json:"error"`
			Description string `json:"error_description"`
		}
		if json.Unmarshal(body, &errResp) == nil && errResp.Error != "" {
			return nil, &DeviceFlowError{Code: errResp.Error, Description: errResp.Description}
		}
		return nil, fmt.Errorf("oauth2: token request failed with status %d", resp.StatusCode)
	}

	// Parse token response
	token, err := parseTokenResponse(body)
	if err != nil {
		return nil, err
	}

	// Store token
	if err := c.tokenStore.SetToken(token); err != nil {
		c.logger.Warn("Failed to store token", "error", err)
	}

	c.logger.Info("Device flow completed successfully")
	return token, nil
}

// DeviceFlow performs the complete device authorization flow
// It displays instructions to the user and polls for authorization
func (c *Client) DeviceFlow(ctx context.Context, scope string) (*Token, error) {
	// Step 1: Get device code
	deviceAuth, err := c.DeviceAuthorization(ctx, scope)
	if err != nil {
		return nil, err
	}

	// Display instructions to user
	fmt.Println("\n=== Device Authorization ===")
	fmt.Printf("Please visit: %s\n", deviceAuth.VerificationURI)
	fmt.Printf("And enter code: %s\n", deviceAuth.UserCode)
	if deviceAuth.VerificationURIComplete != "" {
		fmt.Printf("\nOr visit: %s\n", deviceAuth.VerificationURIComplete)
	}
	fmt.Println("\nWaiting for authorization...")

	// Step 2: Poll for token
	interval := deviceAuth.Interval
	if interval < 1 {
		interval = 5
	}

	deadline := time.Now().Add(time.Duration(deviceAuth.ExpiresIn) * time.Second)

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Duration(interval) * time.Second):
			if time.Now().After(deadline) {
				return nil, &DeviceFlowError{Code: "expired_token", Description: "Device code has expired"}
			}

			token, err := c.PollDeviceToken(ctx, deviceAuth.DeviceCode, interval)
			if err != nil {
				if dfe, ok := err.(*DeviceFlowError); ok {
					switch {
					case dfe.IsAuthorizationPending():
						// Continue polling
						continue
					case dfe.IsSlowDown():
						// Increase interval
						interval += 5
						continue
					case dfe.IsAccessDenied():
						return nil, err
					case dfe.IsExpired():
						return nil, err
					}
				}
				return nil, err
			}

			return token, nil
		}
	}
}

// DeviceFlowWithCallback performs device flow with a callback for status updates
type DeviceFlowCallback func(status string, data interface{})

func (c *Client) DeviceFlowWithCallback(ctx context.Context, scope string, callback DeviceFlowCallback) (*Token, error) {
	// Step 1: Get device code
	deviceAuth, err := c.DeviceAuthorization(ctx, scope)
	if err != nil {
		return nil, err
	}

	// Notify callback with device code info
	if callback != nil {
		callback("device_code", deviceAuth)
	}

	// Step 2: Poll for token
	interval := deviceAuth.Interval
	if interval < 1 {
		interval = 5
	}

	deadline := time.Now().Add(time.Duration(deviceAuth.ExpiresIn) * time.Second)

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Duration(interval) * time.Second):
			if time.Now().After(deadline) {
				if callback != nil {
					callback("expired", nil)
				}
				return nil, &DeviceFlowError{Code: "expired_token", Description: "Device code has expired"}
			}

			if callback != nil {
				callback("polling", nil)
			}

			token, err := c.PollDeviceToken(ctx, deviceAuth.DeviceCode, interval)
			if err != nil {
				if dfe, ok := err.(*DeviceFlowError); ok {
					switch {
					case dfe.IsAuthorizationPending():
						if callback != nil {
							callback("pending", nil)
						}
						continue
					case dfe.IsSlowDown():
						interval += 5
						if callback != nil {
							callback("slow_down", interval)
						}
						continue
					case dfe.IsAccessDenied():
						if callback != nil {
							callback("denied", nil)
						}
						return nil, err
					case dfe.IsExpired():
						if callback != nil {
							callback("expired", nil)
						}
						return nil, err
					}
				}
				return nil, err
			}

			if callback != nil {
				callback("authorized", token)
			}
			return token, nil
		}
	}
}
