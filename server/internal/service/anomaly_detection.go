package service

import (
	"net"
	"strings"
	"time"

	"server/internal/model"
	"server/internal/repository"

	"github.com/google/uuid"
)

/*
 * AnomalyDetectionService 异常登录检测服务
 * 功能：基于登录历史分析用户登录行为，检测新设备、新位置、异常时间、
 *       连续失败、快速IP变化等异常情况，计算风险分数并决定是否拦截或要求 MFA
 */
type AnomalyDetectionService struct {
	loginLogRepo *repository.LoginLogRepository
	userRepo     *repository.UserRepository
}

/*
 * NewAnomalyDetectionService 创建异常检测服务实例
 * @param loginLogRepo - 登录日志仓储
 * @param userRepo     - 用户仓储
 */
func NewAnomalyDetectionService(
	loginLogRepo *repository.LoginLogRepository,
	userRepo *repository.UserRepository,
) *AnomalyDetectionService {
	return &AnomalyDetectionService{
		loginLogRepo: loginLogRepo,
		userRepo:     userRepo,
	}
}

/*
 * AnomalyType 异常类型枚举
 * @value AnomalyNewDevice         - 新设备登录
 * @value AnomalyNewLocation       - 新位置/IP段登录
 * @value AnomalyUnusualTime       - 异常时间登录（凌晨 0-5 点）
 * @value AnomalyMultipleFailures  - 近 1h 内多次登录失败
 * @value AnomalyRapidIPChange     - 短时间内 IP 段变化
 * @value AnomalySuspiciousPattern - 可疑行为模式
 */
type AnomalyType string

const (
	AnomalyNone              AnomalyType = "none"
	AnomalyNewDevice         AnomalyType = "new_device"
	AnomalyNewLocation       AnomalyType = "new_location"
	AnomalyUnusualTime       AnomalyType = "unusual_time"
	AnomalyMultipleFailures  AnomalyType = "multiple_failures"
	AnomalyRapidIPChange     AnomalyType = "rapid_ip_change"
	AnomalySuspiciousPattern AnomalyType = "suspicious_pattern"
)

/*
 * AnomalyResult 异常检测结果
 * 功能：包含异常列表、风险分数 (0-100)、是否应拦截或要求 MFA
 */
type AnomalyResult struct {
	IsAnomalous bool          `json:"is_anomalous"`
	Anomalies   []AnomalyType `json:"anomalies"`
	RiskScore   int           `json:"risk_score"` // 0-100
	Message     string        `json:"message,omitempty"`
	ShouldBlock bool          `json:"should_block"`
	RequireMFA  bool          `json:"require_mfa"`
}

/*
 * CheckLoginAnomaly 检查登录是否存在异常
 * 功能：分析用户最近 30 条登录记录，检测新设备/新位置/异常时间/多次失败/快速IP变化
 *       风险分数 >= 80 拦截登录，>= 50 要求 MFA
 * @param userID    - 用户 UUID
 * @param ipAddress - 当前登录 IP
 * @param userAgent - 当前登录 User-Agent
 * @return *AnomalyResult - 异常检测结果
 */
func (s *AnomalyDetectionService) CheckLoginAnomaly(
	userID uuid.UUID,
	ipAddress string,
	userAgent string,
) (*AnomalyResult, error) {
	result := &AnomalyResult{
		Anomalies: make([]AnomalyType, 0),
	}

	// 获取用户最近的登录历史
	recentLogs, err := s.loginLogRepo.FindRecentByUserID(userID, 30) // 最近30条
	if err != nil {
		return result, err
	}
	if len(recentLogs) == 0 {
		return result, nil
	}
	s.checkNewDevice(result, recentLogs, userAgent)
	s.checkNewLocation(result, recentLogs, ipAddress)
	s.checkUnusualTime(result, recentLogs)
	s.checkMultipleFailures(result, recentLogs)
	s.checkRapidIPChange(result, recentLogs, ipAddress)

	// 计算总风险分数
	s.calculateRiskScore(result)

	// 根据风险分数决定行动
	if result.RiskScore >= 80 {
		result.ShouldBlock = true
		result.Message = "Login blocked due to suspicious activity"
	} else if result.RiskScore >= 50 {
		result.RequireMFA = true
		result.Message = "Additional verification required"
	}

	result.IsAnomalous = len(result.Anomalies) > 0

	return result, nil
}

/* checkNewDevice 检查是否是新设备（基于 UA 指纹比对历史成功登录） */
func (s *AnomalyDetectionService) checkNewDevice(result *AnomalyResult, logs []model.LoginLog, currentUA string) {
	currentDevice := extractDeviceFingerprint(currentUA)

	for _, log := range logs {
		if log.Success {
			historicalDevice := extractDeviceFingerprint(log.UserAgent)
			if historicalDevice == currentDevice {
				return
			}
		}
	}
	result.Anomalies = append(result.Anomalies, AnomalyNewDevice)
}

/* checkNewLocation 检查是否是新位置（基于 IP 段比对历史成功登录） */
func (s *AnomalyDetectionService) checkNewLocation(result *AnomalyResult, logs []model.LoginLog, currentIP string) {
	currentPrefix := getIPPrefix(currentIP)

	for _, log := range logs {
		if log.Success {
			historicalPrefix := getIPPrefix(log.IPAddress)
			if historicalPrefix == currentPrefix {
				return
			}
		}
	}

	result.Anomalies = append(result.Anomalies, AnomalyNewLocation)
}

/* checkUnusualTime 检查是否在异常时间登录（凌晨 0-5 点且历史无此时段记录） */
func (s *AnomalyDetectionService) checkUnusualTime(result *AnomalyResult, logs []model.LoginLog) {
	currentHour := time.Now().Hour()
	hourCount := make(map[int]int)
	totalSuccess := 0
	for _, log := range logs {
		if log.Success {
			hourCount[log.CreatedAt.Hour()]++
			totalSuccess++
		}
	}

	if totalSuccess < 5 {
		return
	}
	if hourCount[currentHour] == 0 && (currentHour >= 0 && currentHour <= 5) {
		result.Anomalies = append(result.Anomalies, AnomalyUnusualTime)
	}
}

/* checkMultipleFailures 检查近 1h 内是否有 3 次以上失败尝试 */
func (s *AnomalyDetectionService) checkMultipleFailures(result *AnomalyResult, logs []model.LoginLog) {
	recentFailures := 0
	cutoff := time.Now().Add(-1 * time.Hour) // 过去1小时

	for _, log := range logs {
		if !log.Success && log.CreatedAt.After(cutoff) {
			recentFailures++
		}
	}

	if recentFailures >= 3 {
		result.Anomalies = append(result.Anomalies, AnomalyMultipleFailures)
	}
}

/* checkRapidIPChange 检查是否在 1h 内从不同 IP 段登录 */
func (s *AnomalyDetectionService) checkRapidIPChange(result *AnomalyResult, logs []model.LoginLog, currentIP string) {
	if len(logs) < 2 {
		return
	}

	// 检查最近的成功登录
	var lastSuccessLog *model.LoginLog
	for i := range logs {
		if logs[i].Success {
			lastSuccessLog = &logs[i]
			break
		}
	}

	if lastSuccessLog == nil {
		return
	}

	// 如果在短时间内（1小时）从不同IP登录
	if time.Since(lastSuccessLog.CreatedAt) < time.Hour {
		if lastSuccessLog.IPAddress != currentIP {
			// 检查是否是完全不同的IP段
			if getIPPrefix(lastSuccessLog.IPAddress) != getIPPrefix(currentIP) {
				result.Anomalies = append(result.Anomalies, AnomalyRapidIPChange)
			}
		}
	}
}

/*
 * calculateRiskScore 计算综合风险分数 (0-100)
 * 评分规则：新设备+20、新位置+25、异常时间+15、多次失败+30、快速IP变化+35、可疑模式+40
 */
func (s *AnomalyDetectionService) calculateRiskScore(result *AnomalyResult) {
	score := 0

	for _, anomaly := range result.Anomalies {
		switch anomaly {
		case AnomalyNewDevice:
			score += 20
		case AnomalyNewLocation:
			score += 25
		case AnomalyUnusualTime:
			score += 15
		case AnomalyMultipleFailures:
			score += 30
		case AnomalyRapidIPChange:
			score += 35
		case AnomalySuspiciousPattern:
			score += 40
		}
	}

	if score > 100 {
		score = 100
	}

	result.RiskScore = score
}

/* DeviceInfo 设备信息结构（从 User-Agent 解析） */
type DeviceInfo struct {
	Browser        string
	BrowserVersion string
	OS             string
	OSVersion      string
	DeviceType     string // desktop, mobile, tablet, bot
	IsMobile       bool
}

/* extractDeviceFingerprint 从 UA 提取设备指纹（浏览器_操作系统_设备类型） */
func extractDeviceFingerprint(userAgent string) string {
	info := parseUserAgent(userAgent)
	return info.Browser + "_" + info.OS + "_" + info.DeviceType
}

/*
 * parseUserAgent 解析 User-Agent 获取详细设备信息
 * 功能：识别浏览器、操作系统、设备类型（桌面/移动/平板/机器人）
 * @param userAgent - User-Agent 字符串
 * @return *DeviceInfo - 设备信息
 */
func parseUserAgent(userAgent string) *DeviceInfo {
	ua := strings.ToLower(userAgent)
	info := &DeviceInfo{
		Browser:    "unknown",
		OS:         "unknown",
		DeviceType: "desktop",
	}

	// 检测是否是机器人
	if strings.Contains(ua, "bot") || strings.Contains(ua, "crawler") ||
		strings.Contains(ua, "spider") || strings.Contains(ua, "curl") ||
		strings.Contains(ua, "wget") {
		info.DeviceType = "bot"
		info.Browser = "bot"
		return info
	}

	// 检测移动设备
	if strings.Contains(ua, "mobile") || strings.Contains(ua, "android") ||
		strings.Contains(ua, "iphone") || strings.Contains(ua, "ipad") ||
		strings.Contains(ua, "ipod") {
		info.IsMobile = true
		if strings.Contains(ua, "tablet") || strings.Contains(ua, "ipad") {
			info.DeviceType = "tablet"
		} else {
			info.DeviceType = "mobile"
		}
	}

	// 检测浏览器及版本
	switch {
	case strings.Contains(ua, "edg/"):
		info.Browser = "edge"
		info.BrowserVersion = extractVersion(ua, "edg/")
	case strings.Contains(ua, "opr/") || strings.Contains(ua, "opera"):
		info.Browser = "opera"
		info.BrowserVersion = extractVersion(ua, "opr/")
	case strings.Contains(ua, "chrome/") && !strings.Contains(ua, "chromium"):
		info.Browser = "chrome"
		info.BrowserVersion = extractVersion(ua, "chrome/")
	case strings.Contains(ua, "firefox/"):
		info.Browser = "firefox"
		info.BrowserVersion = extractVersion(ua, "firefox/")
	case strings.Contains(ua, "safari/") && !strings.Contains(ua, "chrome"):
		info.Browser = "safari"
		info.BrowserVersion = extractVersion(ua, "version/")
	case strings.Contains(ua, "msie") || strings.Contains(ua, "trident"):
		info.Browser = "ie"
	}

	// 检测操作系统及版本
	switch {
	case strings.Contains(ua, "windows nt 10"):
		info.OS = "windows"
		info.OSVersion = "10"
	case strings.Contains(ua, "windows nt 6.3"):
		info.OS = "windows"
		info.OSVersion = "8.1"
	case strings.Contains(ua, "windows nt 6.2"):
		info.OS = "windows"
		info.OSVersion = "8"
	case strings.Contains(ua, "windows nt 6.1"):
		info.OS = "windows"
		info.OSVersion = "7"
	case strings.Contains(ua, "windows"):
		info.OS = "windows"
	case strings.Contains(ua, "mac os x"):
		info.OS = "macos"
		info.OSVersion = extractMacVersion(ua)
	case strings.Contains(ua, "iphone os") || strings.Contains(ua, "cpu os"):
		info.OS = "ios"
		info.OSVersion = extractIOSVersion(ua)
	case strings.Contains(ua, "android"):
		info.OS = "android"
		info.OSVersion = extractVersion(ua, "android ")
	case strings.Contains(ua, "linux"):
		info.OS = "linux"
	case strings.Contains(ua, "cros"):
		info.OS = "chromeos"
	}

	return info
}

/* extractVersion 从 UA 中提取指定前缀后的版本号 */
func extractVersion(ua, prefix string) string {
	idx := strings.Index(ua, prefix)
	if idx == -1 {
		return ""
	}
	start := idx + len(prefix)
	end := start
	for end < len(ua) && (ua[end] >= '0' && ua[end] <= '9' || ua[end] == '.') {
		end++
	}
	if end > start {
		return ua[start:end]
	}
	return ""
}

/* extractMacVersion 从 UA 中提取 macOS 版本号 */
func extractMacVersion(ua string) string {
	idx := strings.Index(ua, "mac os x ")
	if idx == -1 {
		return ""
	}
	start := idx + 9
	end := start
	for end < len(ua) && (ua[end] >= '0' && ua[end] <= '9' || ua[end] == '_' || ua[end] == '.') {
		end++
	}
	if end > start {
		return strings.ReplaceAll(ua[start:end], "_", ".")
	}
	return ""
}

/* extractIOSVersion 从 UA 中提取 iOS 版本号 */
func extractIOSVersion(ua string) string {
	for _, prefix := range []string{"iphone os ", "cpu os "} {
		idx := strings.Index(ua, prefix)
		if idx != -1 {
			start := idx + len(prefix)
			end := start
			for end < len(ua) && (ua[end] >= '0' && ua[end] <= '9' || ua[end] == '_') {
				end++
			}
			if end > start {
				return strings.ReplaceAll(ua[start:end], "_", ".")
			}
		}
	}
	return ""
}

/*
 * GetDeviceInfo 获取设备信息（公开接口）
 * @param userAgent - User-Agent 字符串
 * @return *DeviceInfo - 解析后的设备信息
 */
func GetDeviceInfo(userAgent string) *DeviceInfo {
	return parseUserAgent(userAgent)
}

/*
 * getIPPrefix 获取 IP 前缀（用于判断是否同一网段）
 * IPv4 取前 3 段，IPv6 取前 64 位
 */
func getIPPrefix(ipStr string) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ipStr
	}

	// IPv4: 取前3段
	if ip4 := ip.To4(); ip4 != nil {
		return ip4[0:3].String()
	}

	// IPv6: 取前64位
	return ip[0:8].String()
}

/*
 * RecordLoginAttempt 记录登录尝试并检测异常
 * 功能：先写入登录日志，然后对成功登录进行异常检测
 * @param userID        - 用户 UUID（可为 nil）
 * @param appID         - 应用 UUID（可为 nil）
 * @param loginType     - 登录类型
 * @param ipAddress     - 客户端 IP
 * @param userAgent     - User-Agent
 * @param email         - 尝试登录的邮箱
 * @param success       - 是否成功
 * @param failureReason - 失败原因
 * @return *AnomalyResult - 异常检测结果
 */
func (s *AnomalyDetectionService) RecordLoginAttempt(
	userID *uuid.UUID,
	appID *uuid.UUID,
	loginType model.LoginType,
	ipAddress string,
	userAgent string,
	email string,
	success bool,
	failureReason string,
) (*AnomalyResult, error) {
	// 记录登录日志
	s.loginLogRepo.CreateLoginLog(userID, appID, loginType, ipAddress, userAgent, email, success, failureReason)

	// 如果用户ID存在且登录成功，检测异常
	if userID != nil && success {
		return s.CheckLoginAnomaly(*userID, ipAddress, userAgent)
	}

	return &AnomalyResult{}, nil
}
