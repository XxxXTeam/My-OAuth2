/*
 * Package email 邮件服务包
 * 功能：提供 SMTP 邮件发送、模板管理、连接测试等功能
 */
package email

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"html/template"
	"net/smtp"
	"strings"
	"sync"
)

/* Config SMTP 邮件服务配置 */
type Config struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
	FromName string
	UseTLS   bool
}

/* TemplateData 邮件模板数据（主题 + 正文） */
type TemplateData struct {
	Subject string
	Body    string
}

/*
 * Service 邮件服务
 * 功能：管理 SMTP 连接、邮件模板（默认+自定义）、邮件发送，支持热更新配置
 */
type Service struct {
	mu              sync.RWMutex
	config          *Config
	defaultSubjects map[string]string
	defaultBodies   map[string]string
	customTemplates map[string]*TemplateData // 从 DB 加载的自定义模板
	siteName        string
	frontendURL     string
}

/*
 * NewService 创建邮件服务实例
 * @param cfg - SMTP 配置
 */
func NewService(cfg *Config) *Service {
	s := &Service{
		config:          cfg,
		defaultSubjects: make(map[string]string),
		defaultBodies:   make(map[string]string),
		customTemplates: make(map[string]*TemplateData),
	}
	s.initDefaults()
	return s
}

/* UpdateConfig 热更新 SMTP 配置（线程安全） */
func (s *Service) UpdateConfig(cfg *Config) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.config = cfg
}

/* GetConfig 获取当前 SMTP 配置（只读副本） */
func (s *Service) GetConfig() Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return *s.config
}

// ========== 模板管理 ==========

// SetCustomTemplate 设置自定义模板（覆盖默认值）
func (s *Service) SetCustomTemplate(name string, subject, body string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.customTemplates[name] = &TemplateData{Subject: subject, Body: body}
}

// RemoveCustomTemplate 删除自定义模板（回退到默认值）
func (s *Service) RemoveCustomTemplate(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.customTemplates, name)
}

// GetTemplate 获取模板（优先自定义，回退默认）
func (s *Service) GetTemplate(name string) *TemplateData {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if custom, ok := s.customTemplates[name]; ok {
		return custom
	}
	return &TemplateData{
		Subject: s.defaultSubjects[name],
		Body:    s.defaultBodies[name],
	}
}

// GetDefaultTemplate 获取默认模板
func (s *Service) GetDefaultTemplate(name string) *TemplateData {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return &TemplateData{
		Subject: s.defaultSubjects[name],
		Body:    s.defaultBodies[name],
	}
}

// HasCustomTemplate 检查是否有自定义模板
func (s *Service) HasCustomTemplate(name string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.customTemplates[name]
	return ok
}

// ListTemplateNames 返回所有已知模板名称
func (s *Service) ListTemplateNames() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	names := make([]string, 0, len(s.defaultSubjects))
	for name := range s.defaultSubjects {
		names = append(names, name)
	}
	return names
}

// ========== 发送邮件方法 ==========

// SendPasswordReset 发送密码重置邮件
func (s *Service) SendPasswordReset(to, username, resetLink string) error {
	data := map[string]string{
		"Username":  username,
		"ResetLink": resetLink,
	}
	return s.sendWithTemplate("password_reset", to, data)
}

// SendPasswordResetSuccess 发送密码重置成功通知
func (s *Service) SendPasswordResetSuccess(to, username string) error {
	data := map[string]string{
		"Username": username,
	}
	return s.sendWithTemplate("password_reset_success", to, data)
}

// SendWelcome 发送欢迎邮件
func (s *Service) SendWelcome(to, username string) error {
	data := map[string]string{
		"Username": username,
	}
	return s.sendWithTemplate("welcome", to, data)
}

// SendLoginAlert 发送异常登录警告
func (s *Service) SendLoginAlert(to, username, ipAddress, device, location string) error {
	data := map[string]string{
		"Username":  username,
		"IPAddress": ipAddress,
		"Device":    device,
		"Location":  location,
	}
	return s.sendWithTemplate("login_alert", to, data)
}

// SendEmailVerification 发送邮箱验证邮件
func (s *Service) SendEmailVerification(to, username, verifyLink string) error {
	data := map[string]string{
		"Username":   username,
		"VerifyLink": verifyLink,
	}
	return s.sendWithTemplate("email_verification", to, data)
}

// SetCommonData 设置模板公共变量
func (s *Service) SetCommonData(siteName, frontendURL string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.siteName = siteName
	s.frontendURL = frontendURL
}

// TestConnection 测试 SMTP 连接
func (s *Service) TestConnection() error {
	s.mu.RLock()
	cfg := s.config
	s.mu.RUnlock()

	if cfg.Host == "" {
		return fmt.Errorf("SMTP host not configured")
	}

	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)

	if cfg.UseTLS {
		conn, err := tls.Dial("tcp", addr, &tls.Config{ServerName: cfg.Host})
		if err != nil {
			return fmt.Errorf("TLS connection failed: %w", err)
		}
		client, err := smtp.NewClient(conn, cfg.Host)
		if err != nil {
			conn.Close()
			return fmt.Errorf("SMTP client creation failed: %w", err)
		}
		if cfg.Username != "" {
			auth := smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Host)
			if err := client.Auth(auth); err != nil {
				client.Close()
				return fmt.Errorf("SMTP authentication failed: %w", err)
			}
		}
		client.Quit()
		return nil
	}

	client, err := smtp.Dial(addr)
	if err != nil {
		return fmt.Errorf("SMTP connection failed: %w", err)
	}
	defer client.Close()

	if cfg.Username != "" {
		auth := smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Host)
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("SMTP authentication failed: %w", err)
		}
	}

	client.Quit()
	return nil
}

// SendTestEmail 发送测试邮件
func (s *Service) SendTestEmail(to string) error {
	subject := "OAuth2 Email Service Test"
	body := `<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
    <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
        <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; border-radius: 8px 8px 0 0;">
            <h1>✅ Email Configuration Test</h1>
        </div>
        <div style="background: #f9fafb; padding: 30px; border-radius: 0 0 8px 8px;">
            <p>This is a test email to verify your SMTP configuration is working correctly.</p>
            <p>If you received this email, your email service is properly configured.</p>
        </div>
    </div>
</body>
</html>`
	return s.Send(to, subject, body)
}

// ========== 内部方法 ==========

// sendWithTemplate 使用模板发送邮件
func (s *Service) sendWithTemplate(templateName, to string, data interface{}) error {
	tplData := s.GetTemplate(templateName)
	if tplData == nil || tplData.Body == "" {
		return fmt.Errorf("template %s not found", templateName)
	}

	// 注入公共变量
	enrichedData := s.enrichTemplateData(data)

	// 解析并执行 body 模板
	bodyTmpl, err := template.New(templateName).Parse(tplData.Body)
	if err != nil {
		return fmt.Errorf("failed to parse template %s: %w", templateName, err)
	}
	var body bytes.Buffer
	if err := bodyTmpl.Execute(&body, enrichedData); err != nil {
		return fmt.Errorf("failed to execute template %s: %w", templateName, err)
	}

	// 解析并执行 subject 模板
	subjectTmpl, err := template.New(templateName + "_subject").Parse(tplData.Subject)
	if err != nil {
		return fmt.Errorf("failed to parse subject template: %w", err)
	}
	var subject bytes.Buffer
	if err := subjectTmpl.Execute(&subject, enrichedData); err != nil {
		return fmt.Errorf("failed to execute subject template: %w", err)
	}

	return s.Send(to, subject.String(), body.String())
}

// enrichTemplateData 注入公共模板变量（SiteName, FrontendURL）
func (s *Service) enrichTemplateData(data interface{}) map[string]string {
	s.mu.RLock()
	siteName := s.siteName
	frontendURL := s.frontendURL
	s.mu.RUnlock()

	if siteName == "" {
		siteName = "OAuth2"
	}

	// 将原始 data 合并到新 map
	result := map[string]string{
		"SiteName":    siteName,
		"FrontendURL": frontendURL,
	}

	switch d := data.(type) {
	case map[string]string:
		for k, v := range d {
			result[k] = v
		}
	}

	return result
}

// Send 发送邮件
func (s *Service) Send(to, subject, body string) error {
	s.mu.RLock()
	cfg := s.config
	s.mu.RUnlock()

	if cfg.Host == "" {
		return fmt.Errorf("email service not configured")
	}

	from := cfg.From
	if cfg.FromName != "" {
		from = fmt.Sprintf("%s <%s>", cfg.FromName, cfg.From)
	}

	msg := buildMessage(from, to, subject, body)
	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)

	var auth smtp.Auth
	if cfg.Username != "" {
		auth = smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Host)
	}

	if cfg.UseTLS {
		return sendWithTLS(addr, auth, cfg.Host, cfg.From, to, msg)
	}

	return smtp.SendMail(addr, auth, cfg.From, []string{to}, msg)
}

// buildMessage 构建邮件消息
func buildMessage(from, to, subject, body string) []byte {
	headers := make(map[string]string)
	headers["From"] = from
	headers["To"] = to
	headers["Subject"] = subject
	headers["MIME-Version"] = "1.0"
	headers["Content-Type"] = "text/html; charset=UTF-8"

	var msg strings.Builder
	for k, v := range headers {
		msg.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
	}
	msg.WriteString("\r\n")
	msg.WriteString(body)

	return []byte(msg.String())
}

// sendWithTLS 使用TLS发送邮件
func sendWithTLS(addr string, auth smtp.Auth, host, fromAddr, to string, msg []byte) error {
	tlsConfig := &tls.Config{
		ServerName: host,
	}

	conn, err := tls.Dial("tcp", addr, tlsConfig)
	if err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, host)
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}
	defer client.Close()

	if auth != nil {
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("failed to authenticate: %w", err)
		}
	}

	if err := client.Mail(fromAddr); err != nil {
		return fmt.Errorf("failed to set sender: %w", err)
	}

	if err := client.Rcpt(to); err != nil {
		return fmt.Errorf("failed to set recipient: %w", err)
	}

	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("failed to get writer: %w", err)
	}

	if _, err := w.Write(msg); err != nil {
		return fmt.Errorf("failed to write message: %w", err)
	}

	if err := w.Close(); err != nil {
		return fmt.Errorf("failed to close writer: %w", err)
	}

	return client.Quit()
}

// ========== 默认模板 ==========

func (s *Service) initDefaults() {
	s.defaultSubjects["password_reset"] = "Password Reset Request"
	s.defaultBodies["password_reset"] = passwordResetTemplate

	s.defaultSubjects["password_reset_success"] = "Your Password Has Been Reset"
	s.defaultBodies["password_reset_success"] = passwordResetSuccessTemplate

	s.defaultSubjects["welcome"] = "Welcome to {{.SiteName}}"
	s.defaultBodies["welcome"] = welcomeTemplate

	s.defaultSubjects["login_alert"] = "Security Alert: New Login Detected"
	s.defaultBodies["login_alert"] = loginAlertTemplate

	s.defaultSubjects["email_verification"] = "Verify Your Email Address"
	s.defaultBodies["email_verification"] = emailVerificationTemplate
}

const passwordResetTemplate = `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; border-radius: 8px 8px 0 0; }
        .content { background: #f9fafb; padding: 30px; border-radius: 0 0 8px 8px; }
        .button { display: inline-block; background: #667eea; color: white; padding: 12px 30px; text-decoration: none; border-radius: 6px; margin: 20px 0; }
        .footer { text-align: center; margin-top: 20px; color: #6b7280; font-size: 12px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Password Reset</h1>
        </div>
        <div class="content">
            <p>Hello {{.Username}},</p>
            <p>We received a request to reset your password. Click the button below to create a new password:</p>
            <p style="text-align: center;">
                <a href="{{.ResetLink}}" class="button">Reset Password</a>
            </p>
            <p>This link will expire in 1 hour.</p>
            <p>If you didn't request this, you can safely ignore this email.</p>
        </div>
        <div class="footer">
            <p>This is an automated message. Please do not reply.</p>
        </div>
    </div>
</body>
</html>`

const passwordResetSuccessTemplate = `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: linear-gradient(135deg, #10b981 0%, #059669 100%); color: white; padding: 30px; text-align: center; border-radius: 8px 8px 0 0; }
        .content { background: #f9fafb; padding: 30px; border-radius: 0 0 8px 8px; }
        .footer { text-align: center; margin-top: 20px; color: #6b7280; font-size: 12px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Password Changed</h1>
        </div>
        <div class="content">
            <p>Hello {{.Username}},</p>
            <p>Your password has been successfully reset.</p>
            <p>If you did not make this change, please contact support immediately and secure your account.</p>
        </div>
        <div class="footer">
            <p>This is an automated message. Please do not reply.</p>
        </div>
    </div>
</body>
</html>`

const welcomeTemplate = `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; border-radius: 8px 8px 0 0; }
        .content { background: #f9fafb; padding: 30px; border-radius: 0 0 8px 8px; }
        .footer { text-align: center; margin-top: 20px; color: #6b7280; font-size: 12px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Welcome!</h1>
        </div>
        <div class="content">
            <p>Hello {{.Username}},</p>
            <p>Welcome to our OAuth2 service! Your account has been created successfully.</p>
            <p>You can now use your account to:</p>
            <ul>
                <li>Create and manage OAuth2 applications</li>
                <li>Authorize third-party applications</li>
                <li>Manage your security settings</li>
            </ul>
            <p>Thank you for joining us!</p>
        </div>
        <div class="footer">
            <p>This is an automated message. Please do not reply.</p>
        </div>
    </div>
</body>
</html>`

const loginAlertTemplate = `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: #ef4444; color: white; padding: 30px; text-align: center; border-radius: 8px 8px 0 0; }
        .content { background: #f9fafb; padding: 30px; border-radius: 0 0 8px 8px; }
        .info-box { background: white; border: 1px solid #e5e7eb; border-radius: 6px; padding: 15px; margin: 15px 0; }
        .footer { text-align: center; margin-top: 20px; color: #6b7280; font-size: 12px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Security Alert</h1>
        </div>
        <div class="content">
            <p>Hello {{.Username}},</p>
            <p>We detected a new login to your account from an unrecognized device or location:</p>
            <div class="info-box">
                <p><strong>IP Address:</strong> {{.IPAddress}}</p>
                <p><strong>Device:</strong> {{.Device}}</p>
                <p><strong>Location:</strong> {{.Location}}</p>
            </div>
            <p>If this was you, you can ignore this email.</p>
            <p>If you don't recognize this activity, please change your password immediately and review your account security settings.</p>
        </div>
        <div class="footer">
            <p>This is an automated message. Please do not reply.</p>
        </div>
    </div>
</body>
</html>`

const emailVerificationTemplate = `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: linear-gradient(135deg, #3b82f6 0%, #1d4ed8 100%); color: white; padding: 30px; text-align: center; border-radius: 8px 8px 0 0; }
        .content { background: #f9fafb; padding: 30px; border-radius: 0 0 8px 8px; }
        .button { display: inline-block; background: #3b82f6; color: white; padding: 12px 30px; text-decoration: none; border-radius: 6px; margin: 20px 0; }
        .footer { text-align: center; margin-top: 20px; color: #6b7280; font-size: 12px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Email Verification</h1>
        </div>
        <div class="content">
            <p>Hello {{.Username}},</p>
            <p>Please verify your email address by clicking the button below:</p>
            <p style="text-align: center;">
                <a href="{{.VerifyLink}}" class="button">Verify Email</a>
            </p>
            <p>This link will expire in 24 hours.</p>
            <p>If you didn't request this, you can safely ignore this email.</p>
        </div>
        <div class="footer">
            <p>{{.SiteName}} - This is an automated message. Please do not reply.</p>
        </div>
    </div>
</body>
</html>`
