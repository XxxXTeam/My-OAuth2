package service

import (
	"bytes"
	"compress/flate"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/crewjam/saml"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"server/internal/model"
	"server/internal/repository"
	"server/pkg/jwt"
)

const (
	SAMLIdPCertificateConfigKey = "saml_idp_certificate_pem"
	SAMLIdPPrivateKeyConfigKey  = "saml_idp_private_key_pem"
)

var ErrSAMLIdPConfigInvalid = errors.New("saml idp config invalid")

type SAMLIdPService struct {
	spRepo         *repository.SAMLIdPServiceProviderRepository
	configRepo     *repository.ConfigRepository
	userRepo       *repository.UserRepository
	oauthRepo      *repository.OAuthRepository
	jwtManager     *jwt.Manager
	tokenBlacklist *jwt.Blacklist
	baseURL        string
	frontendURL    string
}

type SAMLIdPConfigInput struct {
	EntityID          string
	ACSURL            string
	SLOURL            string
	CertificatePEM    string
	NameIDFormat      string
	AttributeMappings map[string]string
	Enabled           bool
}

type SAMLIdPCertificatePair struct {
	CertificatePEM string
	PrivateKeyPEM  string
}

type SAMLIdPSessionProvider struct {
	service *SAMLIdPService
}

type SAMLIdPServiceProviderProvider struct {
	service *SAMLIdPService
}

func NewSAMLIdPService(
	spRepo *repository.SAMLIdPServiceProviderRepository,
	configRepo *repository.ConfigRepository,
	userRepo *repository.UserRepository,
	oauthRepo *repository.OAuthRepository,
	jwtManager *jwt.Manager,
	tokenBlacklist *jwt.Blacklist,
	baseURL string,
	frontendURL string,
) *SAMLIdPService {
	return &SAMLIdPService{
		spRepo:         spRepo,
		configRepo:     configRepo,
		userRepo:       userRepo,
		oauthRepo:      oauthRepo,
		jwtManager:     jwtManager,
		tokenBlacklist: tokenBlacklist,
		baseURL:        strings.TrimRight(baseURL, "/"),
		frontendURL:    strings.TrimRight(frontendURL, "/"),
	}
}

func (s *SAMLIdPService) MetadataURL() string {
	return s.baseURL + "/saml/idp/metadata"
}

func (s *SAMLIdPService) SSOURL() string {
	return s.baseURL + "/saml/idp/sso"
}

/** SLOURL 返回 SAML IdP 单点登出 URL */
func (s *SAMLIdPService) SLOURL() string {
	return s.baseURL + "/saml/idp/slo"
}

func (s *SAMLIdPService) ServiceProviderProvider() *SAMLIdPServiceProviderProvider {
	return &SAMLIdPServiceProviderProvider{service: s}
}

func (s *SAMLIdPService) SessionProvider() *SAMLIdPSessionProvider {
	return &SAMLIdPSessionProvider{service: s}
}

func (s *SAMLIdPService) UpsertServiceProvider(appID uuid.UUID, input SAMLIdPConfigInput) (*model.SAMLIdPServiceProvider, error) {
	if strings.TrimSpace(input.EntityID) == "" || strings.TrimSpace(input.ACSURL) == "" {
		return nil, ErrSAMLIdPConfigInvalid
	}
	if _, err := url.ParseRequestURI(input.EntityID); err != nil {
		return nil, ErrSAMLIdPConfigInvalid
	}
	if parsed, err := url.ParseRequestURI(input.ACSURL); err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return nil, ErrSAMLIdPConfigInvalid
	}
	nameIDFormat := input.NameIDFormat
	if nameIDFormat == "" {
		nameIDFormat = model.SAMLNameIDFormatPersistent
	}
	if !model.IsSupportedSAMLNameIDFormat(nameIDFormat) {
		return nil, ErrSAMLIdPConfigInvalid
	}
	if strings.TrimSpace(input.CertificatePEM) != "" {
		if _, err := parseSAMLIdPCertificatePEM(input.CertificatePEM); err != nil {
			return nil, ErrSAMLIdPConfigInvalid
		}
	}

	sp, err := s.spRepo.FindByAppID(appID)
	if err != nil && !errors.Is(err, repository.ErrSAMLIdPServiceProviderNotFound) {
		return nil, err
	}
	if sp == nil {
		sp = &model.SAMLIdPServiceProvider{AppID: appID}
	}
	sp.EntityID = strings.TrimSpace(input.EntityID)
	sp.ACSURL = strings.TrimSpace(input.ACSURL)
	sp.SLOURL = strings.TrimSpace(input.SLOURL)
	if strings.TrimSpace(input.CertificatePEM) != "" {
		sp.CertificatePEM = strings.TrimSpace(input.CertificatePEM)
	}
	sp.NameIDFormat = nameIDFormat
	sp.Enabled = input.Enabled
	sp.SetAttributeMappings(input.AttributeMappings)

	if sp.ID == uuid.Nil {
		return sp, s.spRepo.Create(sp)
	}
	return sp, s.spRepo.Update(sp)
}

func (s *SAMLIdPService) GetServiceProviderByAppID(appID uuid.UUID) (*model.SAMLIdPServiceProvider, error) {
	return s.spRepo.FindByAppID(appID)
}

func (s *SAMLIdPService) DeleteServiceProviderByAppID(appID uuid.UUID) error {
	return s.spRepo.DeleteByAppID(appID)
}

func (s *SAMLIdPService) EnsureCertificatePair() (*SAMLIdPCertificatePair, error) {
	certPEM, certErr := s.configRepo.Get(SAMLIdPCertificateConfigKey)
	keyPEM, keyErr := s.configRepo.Get(SAMLIdPPrivateKeyConfigKey)
	if certErr == nil && keyErr == nil && certPEM != "" && keyPEM != "" {
		return &SAMLIdPCertificatePair{CertificatePEM: certPEM, PrivateKeyPEM: keyPEM}, nil
	}

	certPEM, keyPEM, err := generateSAMLIdPKeyPair(s.MetadataURL())
	if err != nil {
		return nil, err
	}
	if err := s.configRepo.Set(SAMLIdPCertificateConfigKey, certPEM); err != nil {
		return nil, err
	}
	if err := s.configRepo.Set(SAMLIdPPrivateKeyConfigKey, keyPEM); err != nil {
		return nil, err
	}
	return &SAMLIdPCertificatePair{CertificatePEM: certPEM, PrivateKeyPEM: keyPEM}, nil
}

func (s *SAMLIdPService) ServiceProviderMetadata(sp *model.SAMLIdPServiceProvider) (*saml.EntityDescriptor, error) {
	if sp == nil || !sp.Enabled || sp.EntityID == "" || sp.ACSURL == "" {
		return nil, repository.ErrSAMLIdPServiceProviderNotFound
	}
	isDefault := true
	wantAssertionsSigned := true
	descriptor := saml.SPSSODescriptor{
		SSODescriptor: saml.SSODescriptor{
			RoleDescriptor: saml.RoleDescriptor{
				ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol",
			},
			NameIDFormats: []saml.NameIDFormat{saml.NameIDFormat(sp.NameIDFormat)},
		},
		WantAssertionsSigned: &wantAssertionsSigned,
		AssertionConsumerServices: []saml.IndexedEndpoint{
			{
				Binding:   saml.HTTPPostBinding,
				Location:  sp.ACSURL,
				Index:     0,
				IsDefault: &isDefault,
			},
		},
	}
	if strings.TrimSpace(sp.CertificatePEM) != "" {
		cert, err := parseSAMLIdPCertificatePEM(sp.CertificatePEM)
		if err != nil {
			return nil, err
		}
		descriptor.KeyDescriptors = []saml.KeyDescriptor{
			{
				Use:     "encryption",
				KeyInfo: saml.KeyInfo{X509Data: saml.X509Data{X509Certificates: []saml.X509Certificate{{Data: base64.StdEncoding.EncodeToString(cert.Raw)}}}},
			},
		}
	}
	return &saml.EntityDescriptor{
		EntityID:         sp.EntityID,
		SPSSODescriptors: []saml.SPSSODescriptor{descriptor},
	}, nil
}

func (p *SAMLIdPServiceProviderProvider) GetServiceProvider(_ *http.Request, serviceProviderID string) (*saml.EntityDescriptor, error) {
	sp, err := p.service.spRepo.FindEnabledByEntityID(serviceProviderID)
	if errors.Is(err, repository.ErrSAMLIdPServiceProviderNotFound) || errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, os.ErrNotExist
	}
	if err != nil {
		return nil, err
	}
	return p.service.ServiceProviderMetadata(sp)
}

func (p *SAMLIdPSessionProvider) GetSession(w http.ResponseWriter, r *http.Request, req *saml.IdpAuthnRequest) *saml.Session {
	user, claims, ok := p.service.userFromRequest(r)
	if !ok {
		loginURL := p.service.frontendURL + "/login?return_to=" + url.QueryEscape(r.URL.RequestURI())
		http.Redirect(w, r, loginURL, http.StatusFound)
		return nil
	}

	nameIDFormat := model.SAMLNameIDFormatPersistent
	customAttributes := userSAMLAttributes(user, nil)
	if req != nil && req.ServiceProviderMetadata != nil {
		if sp, err := p.service.spRepo.FindEnabledByEntityID(req.ServiceProviderMetadata.EntityID); err == nil {
			nameIDFormat = sp.NameIDFormat
			customAttributes = userSAMLAttributes(user, sp.GetAttributeMappings())
		}
	}
	nameID := samlNameIDValue(user, nameIDFormat)
	return &saml.Session{
		ID:               claims.ID,
		CreateTime:       time.Unix(claims.AuthTime, 0),
		ExpireTime:       claims.ExpiresAt.Time,
		Index:            claims.ID,
		NameID:           nameID,
		NameIDFormat:     nameIDFormat,
		SubjectID:        nameID,
		UserName:         user.Username,
		UserEmail:        user.Email,
		UserCommonName:   displayName(user),
		UserSurname:      user.FamilyName,
		UserGivenName:    user.GivenName,
		CustomAttributes: customAttributes,
	}
}

func (s *SAMLIdPService) userFromRequest(r *http.Request) (*model.User, *jwt.Claims, bool) {
	cookie, err := r.Cookie("access_token")
	if err != nil || cookie.Value == "" {
		return nil, nil, false
	}
	claims, err := s.jwtManager.ValidateAccessToken(cookie.Value)
	if err != nil {
		return nil, nil, false
	}
	if s.tokenBlacklist != nil {
		if s.tokenBlacklist.IsRevoked(claims.ID) {
			return nil, nil, false
		}
		if claims.IssuedAt != nil && s.tokenBlacklist.IsUserTokenRevoked(claims.UserID.String(), claims.IssuedAt.Time) {
			return nil, nil, false
		}
	}
	if s.oauthRepo != nil {
		accessToken, err := s.oauthRepo.FindAccessToken(cookie.Value)
		if err != nil || !accessToken.IsValid() || accessToken.ClientID != claims.ClientID || !accessToken.HasEndUser() || accessToken.UserID == nil || *accessToken.UserID != claims.UserID {
			return nil, nil, false
		}
	}
	user, err := s.userRepo.FindByID(claims.UserID)
	if err != nil || user == nil || (user.Status != "" && user.Status != "active") {
		return nil, nil, false
	}
	return user, claims, true
}

func parseSAMLIdPCertificatePEM(raw string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(raw))
	if block == nil {
		return nil, fmt.Errorf("invalid certificate PEM")
	}
	return x509.ParseCertificate(block.Bytes)
}

func parseSAMLIdPPrivateKeyPEM(raw string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(raw))
	if block == nil {
		return nil, fmt.Errorf("invalid private key PEM")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not RSA")
	}
	return key, nil
}

func generateSAMLIdPKeyPair(commonName string) (string, string, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate private key: %w", err)
	}
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", "", fmt.Errorf("failed to generate serial number: %w", err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to create certificate: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	return string(certPEM), string(keyPEM), nil
}

func displayName(user *model.User) string {
	name := strings.TrimSpace(strings.TrimSpace(user.GivenName + " " + user.FamilyName))
	if name != "" {
		return name
	}
	if user.Nickname != "" {
		return user.Nickname
	}
	return user.Username
}

func samlNameIDValue(user *model.User, format string) string {
	switch format {
	case model.SAMLNameIDFormatEmailAddress:
		return user.Email
	case model.SAMLNameIDFormatUnspecified:
		return user.Username
	default:
		return user.ID.String()
	}
}

func userSAMLAttributes(user *model.User, mappings map[string]string) []saml.Attribute {
	values := map[string]string{
		"email":       user.Email,
		"username":    user.Username,
		"displayName": displayName(user),
		"givenName":   user.GivenName,
		"familyName":  user.FamilyName,
		"employeeId":  user.EmployeeID,
		"department":  user.Department,
		"jobTitle":    user.JobTitle,
	}
	attributeNames := map[string]string{
		"email":       "email",
		"username":    "username",
		"displayName": "displayName",
	}
	for key, attrName := range mappings {
		if _, ok := values[key]; ok && strings.TrimSpace(attrName) != "" {
			attributeNames[key] = strings.TrimSpace(attrName)
		}
	}
	attributes := []saml.Attribute{}
	for key, attrName := range attributeNames {
		if value := values[key]; value != "" {
			attributes = append(attributes, basicSAMLAttribute(attrName, value))
		}
	}
	return attributes
}

func basicSAMLAttribute(name string, value string) saml.Attribute {
	return saml.Attribute{
		Name:       name,
		NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
		Values: []saml.AttributeValue{{
			Type:  "xs:string",
			Value: value,
		}},
	}
}

func (s *SAMLIdPService) MarshalMetadata(metadata *saml.EntityDescriptor) ([]byte, error) {
	return xml.MarshalIndent(metadata, "", "  ")
}

func ParseSAMLIdPCertificatePair(pair *SAMLIdPCertificatePair) (*x509.Certificate, *rsa.PrivateKey, error) {
	cert, err := parseSAMLIdPCertificatePEM(pair.CertificatePEM)
	if err != nil {
		return nil, nil, err
	}
	key, err := parseSAMLIdPPrivateKeyPEM(pair.PrivateKeyPEM)
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}

/**
 * ProcessSLORequest 处理 SP 发来的 SAML LogoutRequest
 *
 * @description
 *   解析 LogoutRequest，验证 Issuer 对应已注册 SP，
 *   根据 NameID 查找用户并吊销该用户所有 token，返回 LogoutResponse XML 和 SP 的 SLO 响应地址。
 *
 * @param samlRequest - Base64+Deflate 编码的 LogoutRequest
 * @param relayState  - SAML RelayState 透传参数
 * @returns responseXML, destination, relayState, error
 */
func (s *SAMLIdPService) ProcessSLORequest(samlRequest string, relayState string) ([]byte, string, string, error) {
	rawXML, err := decodeSAMLRedirectRequest(samlRequest)
	if err != nil {
		return nil, "", "", fmt.Errorf("decode SAMLRequest: %w", err)
	}

	var logoutReq saml.LogoutRequest
	if err := xml.Unmarshal(rawXML, &logoutReq); err != nil {
		return nil, "", "", fmt.Errorf("unmarshal LogoutRequest: %w", err)
	}

	if logoutReq.Issuer == nil || logoutReq.Issuer.Value == "" {
		return nil, "", "", errors.New("LogoutRequest missing Issuer")
	}

	sp, err := s.spRepo.FindEnabledByEntityID(logoutReq.Issuer.Value)
	if err != nil {
		return nil, "", "", fmt.Errorf("unknown SP: %s", logoutReq.Issuer.Value)
	}

	// 确定用户并吊销 token
	if logoutReq.NameID != nil && logoutReq.NameID.Value != "" {
		s.revokeUserByNameID(logoutReq.NameID.Value, sp.NameIDFormat)
	}

	// 构建 LogoutResponse
	destination := s.spSLOResponseURL(sp)
	resp := s.buildLogoutResponse(logoutReq.ID, destination)

	respXML, err := xml.Marshal(resp)
	if err != nil {
		return nil, "", "", fmt.Errorf("marshal LogoutResponse: %w", err)
	}

	return respXML, destination, relayState, nil
}

/** revokeUserByNameID 根据 NameID 值和格式查找用户并吊销所有 token */
func (s *SAMLIdPService) revokeUserByNameID(nameIDValue, nameIDFormat string) {
	var user *model.User
	var err error

	switch nameIDFormat {
	case model.SAMLNameIDFormatEmailAddress:
		user, err = s.userRepo.FindByEmail(nameIDValue)
	case model.SAMLNameIDFormatUnspecified:
		user, err = s.userRepo.FindByUsername(nameIDValue)
	default:
		uid, parseErr := uuid.Parse(nameIDValue)
		if parseErr != nil {
			return
		}
		user, err = s.userRepo.FindByID(uid)
	}
	if err != nil || user == nil {
		return
	}
	if s.oauthRepo != nil {
		s.oauthRepo.RevokeTokensByUserID(user.ID)
	}
	if s.tokenBlacklist != nil {
		s.tokenBlacklist.RevokeAllForUser(user.ID.String(), 24*time.Hour)
	}
}

/** spSLOResponseURL 获取 SP 的 SLO 响应地址（默认使用 ACS URL 同域的 /slo） */
func (s *SAMLIdPService) spSLOResponseURL(sp *model.SAMLIdPServiceProvider) string {
	if sp.SLOURL != "" {
		return sp.SLOURL
	}
	// 回退到 ACS URL（大部分 SP 的 SLO Response 接收地址与 ACS 同域）
	return sp.ACSURL
}

/** buildLogoutResponse 构造 SAML LogoutResponse */
func (s *SAMLIdPService) buildLogoutResponse(inResponseTo, destination string) *saml.LogoutResponse {
	now := time.Now().UTC()
	return &saml.LogoutResponse{
		ID:           fmt.Sprintf("_response_%s", uuid.New().String()),
		InResponseTo: inResponseTo,
		Version:      "2.0",
		IssueInstant: now,
		Destination:  destination,
		Issuer: &saml.Issuer{
			Value: s.MetadataURL(),
		},
		Status: saml.Status{
			StatusCode: saml.StatusCode{
				Value: saml.StatusSuccess,
			},
		},
	}
}

/** decodeSAMLRedirectRequest 解码 HTTP-Redirect 绑定的 SAMLRequest (Base64 + Deflate) */
func decodeSAMLRedirectRequest(encoded string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		raw, err = base64.RawURLEncoding.DecodeString(encoded)
		if err != nil {
			return nil, err
		}
	}
	// HTTP-Redirect 使用 DEFLATE 压缩
	return inflateBytes(raw)
}

/** inflateBytes 解压 DEFLATE 数据 */
func inflateBytes(data []byte) ([]byte, error) {
	reader := flate.NewReader(bytes.NewReader(data))
	defer reader.Close()
	return io.ReadAll(reader)
}
