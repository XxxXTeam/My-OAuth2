/*
 * Package logger 统一日志系统
 * 功能：基于 slog 的结构化日志，支持彩色终端输出、JSON 格式、TraceID 关联、
 *       敏感信息脱敏、文件轮转、GORM 集成、HTTP 请求日志
 *
 * 日志格式（text 模式）：
 *   15:04:05 ● INFO  [module/file.go:42] 消息内容 key=value
 *   时间(灰)  等级(彩)  源(青)         消息(白粗)  属性(青=白)
 *
 * 等级图标：
 *   ○ DEBUG (灰)  ● INFO (绿)  ▲ WARN (黄)  ✖ ERROR (红)
 */
package logger

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

/* Level 日志级别类型别名 */
type Level = slog.Level

const (
	LevelDebug = slog.LevelDebug
	LevelInfo  = slog.LevelInfo
	LevelWarn  = slog.LevelWarn
	LevelError = slog.LevelError
)

/* ANSI 终端颜色码 */
const (
	colorReset   = "\033[0m"
	colorRed     = "\033[31m"
	colorGreen   = "\033[32m"
	colorYellow  = "\033[33m"
	colorBlue    = "\033[34m"
	colorMagenta = "\033[35m"
	colorCyan    = "\033[36m"
	colorWhite   = "\033[37m"
	colorGray    = "\033[90m"
	colorBold    = "\033[1m"
)

/*
 * PrettyHandler 彩色日志处理器
 * 功能：实现 slog.Handler 接口，输出彩色格式化日志
 *       支持时间、等级图标、源文件、属性的彩色输出
 */
type PrettyHandler struct {
	opts   *slog.HandlerOptions
	output io.Writer
	attrs  []slog.Attr
	group  string
	mu     sync.Mutex
}

/*
 * NewPrettyHandler 创建彩色日志处理器
 * @param output - 输出目标
 * @param opts   - slog 处理器选项
 */
func NewPrettyHandler(output io.Writer, opts *slog.HandlerOptions) *PrettyHandler {
	return &PrettyHandler{
		opts:   opts,
		output: output,
	}
}

func (h *PrettyHandler) Enabled(_ context.Context, level slog.Level) bool {
	minLevel := slog.LevelInfo
	if h.opts != nil && h.opts.Level != nil {
		minLevel = h.opts.Level.Level()
	}
	return level >= minLevel
}

func (h *PrettyHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	/* 时间（灰色） */
	timeStr := colorGray + r.Time.Format("15:04:05") + colorReset

	/* 等级（带颜色） */
	levelStr := h.formatLevel(r.Level)

	/* 调用源 [模块/文件:行号]（青色+括号），PC==0 时显示 [HTTP] 标签 */
	sourceStr := ""
	if h.opts != nil && h.opts.AddSource {
		if r.PC != 0 {
			fs := runtime.CallersFrames([]uintptr{r.PC})
			f, _ := fs.Next()
			if f.File != "" {
				dir := filepath.Base(filepath.Dir(f.File))
				file := filepath.Base(f.File)
				sourceStr = colorCyan + "[" + dir + "/" + file + ":" + strconv.Itoa(f.Line) + "]" + colorReset + " "
			}
		} else {
			sourceStr = colorCyan + "[HTTP]" + colorReset + " "
		}
	}

	/* 消息（白色加粗） */
	msg := colorBold + colorWhite + r.Message + colorReset

	/* 收集属性， key=青色 value=默认 */
	var parts []string
	r.Attrs(func(a slog.Attr) bool {
		if a.Key != "" && a.Key != "trace_id" {
			parts = append(parts, fmt.Sprintf("%s%s%s=%v", colorCyan, a.Key, colorReset, a.Value.Any()))
		}
		return true
	})
	for _, a := range h.attrs {
		if a.Key != "" && a.Key != "trace_id" {
			parts = append(parts, fmt.Sprintf("%s%s%s=%v", colorCyan, a.Key, colorReset, a.Value.Any()))
		}
	}

	attrStr := ""
	if len(parts) > 0 {
		attrStr = " " + strings.Join(parts, " ")
	}

	/* 输出格式: 时间 [等级] [模块/文件:行号] 消息 属性 */
	fmt.Fprintf(h.output, "%s %s %s%s%s\n", timeStr, levelStr, sourceStr, msg, attrStr)
	return nil
}

func (h *PrettyHandler) formatLevel(level slog.Level) string {
	switch {
	case level < slog.LevelInfo:
		return fmt.Sprintf("%s%s○ DEBUG%s", colorBold, colorGray, colorReset)
	case level < slog.LevelWarn:
		return fmt.Sprintf("%s%s● INFO %s", colorBold, colorGreen, colorReset)
	case level < slog.LevelError:
		return fmt.Sprintf("%s%s▲ WARN %s", colorBold, colorYellow, colorReset)
	default:
		return fmt.Sprintf("%s%s✖ ERROR%s", colorBold, colorRed, colorReset)
	}
}

func (h *PrettyHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &PrettyHandler{
		opts:   h.opts,
		output: h.output,
		attrs:  append(h.attrs, attrs...),
		group:  h.group,
	}
}

func (h *PrettyHandler) WithGroup(name string) slog.Handler {
	return &PrettyHandler{
		opts:   h.opts,
		output: h.output,
		attrs:  h.attrs,
		group:  name,
	}
}

/* contextKey 上下文键类型（用于 TraceID） */
type contextKey string

const TraceIDKey contextKey = "trace_id"

/*
 * Config 日志配置
 * 功能：配置日志级别、格式、输出目标、文件轮转等
 */
type Config struct {
	Level      Level  // Log level
	Format     string // "json" or "text"
	Output     string // "stdout", "stderr", or file path
	AddSource  bool   // Add source file info
	TimeFormat string // Time format

	// File rotation settings
	FileOutput  string // File path for file logging (optional, in addition to Output)
	MaxSizeMB   int    // Max size in MB per log file before rotation (default: 100)
	MaxBackups  int    // Max number of old log files to keep (default: 5)
	MaxAgeDays  int    // Max age in days for old log files (default: 30)
	CompressOld bool   // Whether to compress old log files
}

/* DefaultConfig 返回默认日志配置（Info级别、text格式、stdout输出） */
func DefaultConfig() *Config {
	return &Config{
		Level:      LevelInfo,
		Format:     "text",
		Output:     "stdout",
		AddSource:  true,
		TimeFormat: "2006-01-02 15:04:05",
		MaxSizeMB:  100,
		MaxBackups: 5,
		MaxAgeDays: 30,
	}
}

/*
 * Logger 增强型日志器
 * 功能：包装 slog.Logger，增加 TraceID、字段注入、HTTP 请求日志、文件管理等
 */
type Logger struct {
	*slog.Logger
	config       *Config
	file         *os.File
	rotateWriter *RotateWriter
}

var (
	defaultLogger *Logger
	once          sync.Once
)

/*
 * Init 初始化全局日志器（仅执行一次）
 * @param cfg - 日志配置
 */
func Init(cfg *Config) error {
	var err error
	once.Do(func() {
		defaultLogger, err = New(cfg)
	})
	return err
}

/*
 * ReInit 重新初始化全局日志器（关闭旧实例）
 * @param cfg - 新日志配置
 */
func ReInit(cfg *Config) error {
	newLogger, err := New(cfg)
	if err != nil {
		return err
	}
	if defaultLogger != nil {
		defaultLogger.Close()
	}
	defaultLogger = newLogger
	return nil
}

/*
 * New 创建新的 Logger 实例
 * 功能：根据配置创建输出目标（stdout/stderr/文件），支持多路输出和文件轮转
 *       text 格式使用 PrettyHandler（彩色），json 格式使用 slog.JSONHandler
 *       自动脱敏：password/client_secret/token/access_token/refresh_token/api_secret
 * @param cfg - 日志配置
 */
func New(cfg *Config) (*Logger, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	var output io.Writer
	var file *os.File
	var rw *RotateWriter

	switch cfg.Output {
	case "stdout", "":
		output = os.Stdout
	case "stderr":
		output = os.Stderr
	default:
		// File output
		dir := filepath.Dir(cfg.Output)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, err
		}
		var err error
		file, err = os.OpenFile(cfg.Output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return nil, err
		}
		output = file
	}

	// 如果配置了文件日志输出（带轮转），创建多路输出
	if cfg.FileOutput != "" {
		var err error
		rw, err = NewRotateWriter(cfg.FileOutput, cfg.MaxSizeMB, cfg.MaxBackups, cfg.MaxAgeDays, cfg.CompressOld)
		if err != nil {
			return nil, fmt.Errorf("failed to create rotate writer: %w", err)
		}
		// 同时输出到控制台和文件
		output = io.MultiWriter(output, rw)
	}

	opts := &slog.HandlerOptions{
		Level:     cfg.Level,
		AddSource: cfg.AddSource,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			// Custom time format
			if a.Key == slog.TimeKey {
				if t, ok := a.Value.Any().(time.Time); ok {
					a.Value = slog.StringValue(t.Format(cfg.TimeFormat))
				}
			}
			// Mask sensitive fields
			if a.Key == "password" || a.Key == "client_secret" || a.Key == "token" ||
				a.Key == "access_token" || a.Key == "refresh_token" || a.Key == "api_secret" {
				a.Value = slog.StringValue("***REDACTED***")
			}
			return a
		},
	}

	var handler slog.Handler
	if cfg.Format == "text" {
		handler = NewPrettyHandler(output, opts)
	} else {
		handler = slog.NewJSONHandler(output, opts)
	}

	return &Logger{
		Logger:       slog.New(handler),
		config:       cfg,
		file:         file,
		rotateWriter: rw,
	}, nil
}

/* Default 获取全局默认日志器 */
func Default() *Logger {
	if defaultLogger == nil {
		defaultLogger, _ = New(DefaultConfig())
	}
	return defaultLogger
}

/* Close 关闭日志文件和轮转写入器 */
func (l *Logger) Close() error {
	if l.rotateWriter != nil {
		l.rotateWriter.Close()
	}
	if l.file != nil {
		return l.file.Close()
	}
	return nil
}

/* WithTraceID 返回携带 TraceID 的日志器 */
func (l *Logger) WithTraceID(traceID string) *Logger {
	return &Logger{
		Logger: l.Logger.With(slog.String("trace_id", traceID)),
		config: l.config,
		file:   l.file,
	}
}

/* WithContext 从上下文提取 TraceID 并返回携带 TraceID 的日志器 */
func (l *Logger) WithContext(ctx context.Context) *Logger {
	if traceID, ok := ctx.Value(TraceIDKey).(string); ok {
		return l.WithTraceID(traceID)
	}
	return l
}

/* WithFields 返回携带额外字段的日志器 */
func (l *Logger) WithFields(fields map[string]any) *Logger {
	attrs := make([]any, 0, len(fields)*2)
	for k, v := range fields {
		attrs = append(attrs, k, v)
	}
	return &Logger{
		Logger: l.Logger.With(attrs...),
		config: l.config,
		file:   l.file,
	}
}

/* Request HTTP 请求日志快捷方法 */
func (l *Logger) Request(method, path string, statusCode int, latency time.Duration, clientIP string) {
	l.Info("HTTP Request",
		slog.String("method", method),
		slog.String("path", path),
		slog.Int("status", statusCode),
		slog.Duration("latency", latency),
		slog.String("client_ip", clientIP),
	)
}

/* ========== 认证日志快捷方法 ========== */

/* AuthLogin 登录事件日志 */
func (l *Logger) AuthLogin(userID, email, clientIP string, success bool, reason string) {
	l.Info("Auth Login",
		slog.String("event", "login"),
		slog.String("user_id", userID),
		slog.String("email", email),
		slog.String("client_ip", clientIP),
		slog.Bool("success", success),
		slog.String("reason", reason),
	)
}

func (l *Logger) AuthRegister(userID, email, username string) {
	l.Info("Auth Register",
		slog.String("event", "register"),
		slog.String("user_id", userID),
		slog.String("email", email),
		slog.String("username", username),
	)
}

func (l *Logger) AuthLogout(userID string) {
	l.Info("Auth Logout",
		slog.String("event", "logout"),
		slog.String("user_id", userID),
	)
}

/* ========== OAuth2 日志快捷方法 ========== */

/* OAuthAuthorize OAuth 授权事件日志 */
func (l *Logger) OAuthAuthorize(userID, appID, appName, scope string) {
	l.Info("OAuth Authorize",
		slog.String("event", "oauth_authorize"),
		slog.String("user_id", userID),
		slog.String("app_id", appID),
		slog.String("app_name", appName),
		slog.String("scope", scope),
	)
}

func (l *Logger) OAuthToken(clientID, grantType string, success bool) {
	l.Info("OAuth Token",
		slog.String("event", "oauth_token"),
		slog.String("client_id", clientID),
		slog.String("grant_type", grantType),
		slog.Bool("success", success),
	)
}

func (l *Logger) OAuthRevoke(userID, clientID string) {
	l.Info("OAuth Revoke",
		slog.String("event", "oauth_revoke"),
		slog.String("user_id", userID),
		slog.String("client_id", clientID),
	)
}

/* ========== SDK 日志快捷方法 ========== */

/* SDKRegister SDK 注册事件日志 */
func (l *Logger) SDKRegister(appID, userID, email string) {
	l.Info("SDK Register",
		slog.String("event", "sdk_register"),
		slog.String("app_id", appID),
		slog.String("user_id", userID),
		slog.String("email", email),
	)
}

func (l *Logger) SDKLogin(appID, userID, email string) {
	l.Info("SDK Login",
		slog.String("event", "sdk_login"),
		slog.String("app_id", appID),
		slog.String("user_id", userID),
		slog.String("email", email),
	)
}

/* ========== 管理员日志快捷方法 ========== */

/* AdminAction 管理员操作日志 */
func (l *Logger) AdminAction(adminID, action, targetType, targetID string) {
	l.Info("Admin Action",
		slog.String("event", "admin_action"),
		slog.String("admin_id", adminID),
		slog.String("action", action),
		slog.String("target_type", targetType),
		slog.String("target_id", targetID),
	)
}

/* ErrorWithStack 输出错误日志并附带源文件和行号 */
func (l *Logger) ErrorWithStack(msg string, err error) {
	_, file, line, _ := runtime.Caller(1)
	l.Error(msg,
		slog.String("error", err.Error()),
		slog.String("file", file),
		slog.Int("line", line),
	)
}

/*
 * LogHTTP 写入 HTTP 请求日志（source 标记为 [HTTP]）
 * 功能：用于请求日志中间件，caller 指向中间件本身而非实际处理模块时，
 *       使用此方法输出 [HTTP] 标签替代误导性的 [middleware/xxx.go:行号]
 */
func (l *Logger) LogHTTP(level Level, msg string, args ...any) {
	if !l.Logger.Enabled(context.Background(), level) {
		return
	}
	r := slog.NewRecord(time.Now(), level, msg, 0) /* PC=0 → 不输出 source */
	for i := 0; i+1 < len(args); i += 2 {
		if key, ok := args[i].(string); ok {
			r.AddAttrs(slog.Any(key, args[i+1]))
		}
	}
	_ = l.Logger.Handler().Handle(context.Background(), r)
}

/* ========== 包级别全局快捷函数 ========== */
func Debug(msg string, args ...any)                          { Default().Debug(msg, args...) }
func Info(msg string, args ...any)                           { Default().Info(msg, args...) }
func Warn(msg string, args ...any)                           { Default().Warn(msg, args...) }
func Error(msg string, args ...any)                          { Default().Error(msg, args...) }
func WithTraceID(traceID string) *Logger                     { return Default().WithTraceID(traceID) }
func WithContext(ctx context.Context) *Logger                { return Default().WithContext(ctx) }
func WithFields(fields map[string]any) *Logger               { return Default().WithFields(fields) }
func Request(m, p string, s int, l time.Duration, ip string) { Default().Request(m, p, s, l, ip) }
