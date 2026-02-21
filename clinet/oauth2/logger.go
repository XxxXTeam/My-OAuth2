package oauth2

import (
	"fmt"
	"io"
	"log"
	"os"
	"time"
)

/*
 * LogLevel 日志级别枚举
 * @value LogLevelDebug - 调试
 * @value LogLevelInfo  - 信息
 * @value LogLevelWarn  - 警告
 * @value LogLevelError - 错误
 * @value LogLevelNone  - 禁用日志
 */
type LogLevel int

const (
	LogLevelDebug LogLevel = iota
	LogLevelInfo
	LogLevelWarn
	LogLevelError
	LogLevelNone // Disable logging
)

/* String 返回日志级别的字符串表示 */
func (l LogLevel) String() string {
	switch l {
	case LogLevelDebug:
		return "DEBUG"
	case LogLevelInfo:
		return "INFO"
	case LogLevelWarn:
		return "WARN"
	case LogLevelError:
		return "ERROR"
	default:
		return "UNKNOWN"
	}
}

/*
 * Logger SDK 日志接口
 * 功能：所有日志实现必须实现此接口，支持 Debug/Info/Warn/Error 四个级别
 */
type Logger interface {
	Debug(msg string, args ...interface{})
	Info(msg string, args ...interface{})
	Warn(msg string, args ...interface{})
	Error(msg string, args ...interface{})
	SetLevel(level LogLevel)
	GetLevel() LogLevel
}

/* DefaultLogger 默认日志实现（输出到 stdout） */
type DefaultLogger struct {
	level  LogLevel
	logger *log.Logger
}

/* NewDefaultLogger 创建默认日志器实例 */
func NewDefaultLogger() *DefaultLogger {
	return &DefaultLogger{
		level:  LogLevelInfo,
		logger: log.New(os.Stdout, "[OAuth2-SDK] ", log.LstdFlags),
	}
}

/*
 * NewDefaultLoggerWithOutput 创建自定义输出目标的日志器
 * @param output - 日志输出目标
 */
func NewDefaultLoggerWithOutput(output io.Writer) *DefaultLogger {
	return &DefaultLogger{
		level:  LogLevelInfo,
		logger: log.New(output, "[OAuth2-SDK] ", log.LstdFlags),
	}
}

/* SetLevel 设置日志级别 */
func (l *DefaultLogger) SetLevel(level LogLevel) {
	l.level = level
}

/* GetLevel 获取当前日志级别 */
func (l *DefaultLogger) GetLevel() LogLevel {
	return l.level
}

/* Debug 输出调试级别日志 */
func (l *DefaultLogger) Debug(msg string, args ...interface{}) {
	if l.level <= LogLevelDebug {
		l.log(LogLevelDebug, msg, args...)
	}
}

/* Info 输出信息级别日志 */
func (l *DefaultLogger) Info(msg string, args ...interface{}) {
	if l.level <= LogLevelInfo {
		l.log(LogLevelInfo, msg, args...)
	}
}

/* Warn 输出警告级别日志 */
func (l *DefaultLogger) Warn(msg string, args ...interface{}) {
	if l.level <= LogLevelWarn {
		l.log(LogLevelWarn, msg, args...)
	}
}

/* Error 输出错误级别日志 */
func (l *DefaultLogger) Error(msg string, args ...interface{}) {
	if l.level <= LogLevelError {
		l.log(LogLevelError, msg, args...)
	}
}

func (l *DefaultLogger) log(level LogLevel, msg string, args ...interface{}) {
	if len(args) > 0 {
		l.logger.Printf("[%s] %s %v", level.String(), msg, args)
	} else {
		l.logger.Printf("[%s] %s", level.String(), msg)
	}
}

/* NopLogger 空日志器（不输出任何内容） */
type NopLogger struct{}

func (l *NopLogger) Debug(msg string, args ...interface{}) {}
func (l *NopLogger) Info(msg string, args ...interface{})  {}
func (l *NopLogger) Warn(msg string, args ...interface{})  {}
func (l *NopLogger) Error(msg string, args ...interface{}) {}
func (l *NopLogger) SetLevel(level LogLevel)               {}
func (l *NopLogger) GetLevel() LogLevel                    { return LogLevelNone }

/* HTTPLogger HTTP 请求/响应日志器 */
type HTTPLogger struct {
	logger Logger
}

/* NewHTTPLogger 创建 HTTP 日志器实例 */
func NewHTTPLogger(logger Logger) *HTTPLogger {
	return &HTTPLogger{logger: logger}
}

/* LogRequest 记录 HTTP 请求日志 */
func (l *HTTPLogger) LogRequest(method, url string, body []byte) {
	if l.logger.GetLevel() <= LogLevelDebug {
		l.logger.Debug(fmt.Sprintf("HTTP Request: %s %s", method, url))
		if len(body) > 0 {
			// Truncate body for logging
			bodyStr := string(body)
			if len(bodyStr) > 500 {
				bodyStr = bodyStr[:500] + "..."
			}
			l.logger.Debug(fmt.Sprintf("Request Body: %s", bodyStr))
		}
	}
}

/* LogResponse 记录 HTTP 响应日志 */
func (l *HTTPLogger) LogResponse(method, url string, statusCode int, duration time.Duration, body []byte) {
	if l.logger.GetLevel() <= LogLevelDebug {
		l.logger.Debug(fmt.Sprintf("HTTP Response: %s %s -> %d (%s)", method, url, statusCode, duration))
		if len(body) > 0 {
			bodyStr := string(body)
			if len(bodyStr) > 500 {
				bodyStr = bodyStr[:500] + "..."
			}
			l.logger.Debug(fmt.Sprintf("Response Body: %s", bodyStr))
		}
	}
}

/* LogError 记录 HTTP 错误日志 */
func (l *HTTPLogger) LogError(method, url string, err error) {
	l.logger.Error(fmt.Sprintf("HTTP Error: %s %s -> %v", method, url, err))
}

/* globalLogger 全局日志实例 */
var globalLogger Logger = NewDefaultLogger()

/* SetGlobalLogger 设置全局日志实例 */
func SetGlobalLogger(logger Logger) {
	globalLogger = logger
}

/* GetGlobalLogger 获取全局日志实例 */
func GetGlobalLogger() Logger {
	return globalLogger
}

/* ========== 包级别日志快捷函数 ========== */
func logDebug(msg string, args ...interface{}) {
	if globalLogger != nil {
		globalLogger.Debug(msg, args...)
	}
}

func logInfo(msg string, args ...interface{}) {
	if globalLogger != nil {
		globalLogger.Info(msg, args...)
	}
}

func logWarn(msg string, args ...interface{}) {
	if globalLogger != nil {
		globalLogger.Warn(msg, args...)
	}
}

func logError(msg string, args ...interface{}) {
	if globalLogger != nil {
		globalLogger.Error(msg, args...)
	}
}
