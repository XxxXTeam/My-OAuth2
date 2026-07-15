package handler

import (
	"server/internal/model"
	"time"
)

/*
 * AppResponse OAuth2/OIDC 客户端元数据 API 响应（对齐 RFC 7591 常用字段子集）
 */
type AppResponse struct {
	ID                      string   `json:"id"`
	ClientID                string   `json:"client_id"`
	ClientSecret            string   `json:"client_secret,omitempty"`
	Name                    string   `json:"name"`
	Description             string   `json:"description"`
	RedirectURIs            []string `json:"redirect_uris"`
	PostLogoutRedirectURIs  []string `json:"post_logout_redirect_uris"`
	Scopes                  []string `json:"scopes"`
	AllowedScopes           []string `json:"allowed_scopes"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypesSupported  []string `json:"response_types_supported"`
	AppType                 string   `json:"app_type"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	IssuedTokenTypes        []string `json:"issued_token_types"`
	CreatedAt               string   `json:"created_at"`
	UpdatedAt               string   `json:"updated_at,omitempty"`
}

/* toAppResponse 将应用实体转为完整客户端元数据响应 */
func toAppResponse(app *model.Application, clientSecret string) AppResponse {
	if app.AppType == "" {
		app.AppType = model.AppTypeConfidential
	}
	if app.TokenEndpointAuthMethod == "" {
		app.TokenEndpointAuthMethod = model.AuthMethodClientSecretBasic
	}
	resp := AppResponse{
		ID:                      app.ID.String(),
		ClientID:                app.ClientID,
		Name:                    app.Name,
		Description:             app.Description,
		RedirectURIs:            app.GetRedirectURIs(),
		PostLogoutRedirectURIs:  app.GetPostLogoutRedirectURIs(),
		Scopes:                  app.GetOIDCScopes(),
		AllowedScopes:           app.GetAllowedScopes(),
		GrantTypes:              app.GetGrantTypes(),
		ResponseTypesSupported:  app.GetResponseTypesSupported(),
		AppType:                 string(app.AppType),
		TokenEndpointAuthMethod: string(app.TokenEndpointAuthMethod),
		IssuedTokenTypes:        app.GetIssuedTokenTypes(),
		CreatedAt:               app.CreatedAt.Format(time.RFC3339),
		UpdatedAt:               app.UpdatedAt.Format(time.RFC3339),
	}
	if clientSecret != "" {
		resp.ClientSecret = clientSecret
	}
	return resp
}
