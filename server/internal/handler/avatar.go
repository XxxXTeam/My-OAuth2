package handler

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"server/internal/context"
	"server/internal/repository"

	"github.com/gin-gonic/gin"
)

/*
 * AvatarHandler 头像上传处理器
 * 功能：处理用户头像的上传和删除，支持 JPEG/PNG/GIF/WebP 格式，最大 5MB
 */
type AvatarHandler struct {
	userRepo  *repository.UserRepository
	uploadDir string
	maxSize   int64 // 最大文件大小（字节）
	baseURL   string
}

/*
 * NewAvatarHandler 创建头像处理器实例
 * @param userRepo  - 用户仓储
 * @param uploadDir - 上传目录路径
 * @param baseURL   - 头像访问 URL 前缀
 */
func NewAvatarHandler(userRepo *repository.UserRepository, uploadDir, baseURL string) *AvatarHandler {
	// 确保上传目录存在
	os.MkdirAll(uploadDir, 0755)
	return &AvatarHandler{
		userRepo:  userRepo,
		uploadDir: uploadDir,
		maxSize:   5 * 1024 * 1024, // 5MB
		baseURL:   baseURL,
	}
}

/* allowedImageTypes 允许上传的图片 MIME 类型及对应扩展名 */
var allowedImageTypes = map[string]string{
	"image/jpeg": ".jpg",
	"image/png":  ".png",
	"image/gif":  ".gif",
	"image/webp": ".webp",
}

/*
 * Upload 上传用户头像
 * @route POST /api/user/avatar
 * 功能：接收 multipart 文件，校验类型和大小，生成 MD5 文件名存储
 */
func (h *AvatarHandler) Upload(c *gin.Context) {
	userID, ok := context.GetUserID(c)
	if !ok {
		Unauthorized(c, "Not authenticated")
		return
	}

	// 获取上传的文件
	file, header, err := c.Request.FormFile("avatar")
	if err != nil {
		BadRequest(c, "No file uploaded")
		return
	}
	defer file.Close()

	// 检查文件大小
	if header.Size > h.maxSize {
		BadRequest(c, fmt.Sprintf("File too large. Maximum size is %d MB", h.maxSize/(1024*1024)))
		return
	}

	// 检查文件类型
	contentType := header.Header.Get("Content-Type")
	ext, ok := allowedImageTypes[contentType]
	if !ok {
		BadRequest(c, "Invalid file type. Allowed types: JPEG, PNG, GIF, WebP")
		return
	}

	// 读取文件内容
	content, err := io.ReadAll(file)
	if err != nil {
		InternalError(c, "Failed to read file")
		return
	}

	// 生成文件名（使用用户ID和内容哈希）
	hash := md5.Sum(content)
	hashStr := hex.EncodeToString(hash[:])
	filename := fmt.Sprintf("%s_%s%s", userID.String(), hashStr[:8], ext)
	filePath := filepath.Join(h.uploadDir, filename)

	// 保存文件
	if err := os.WriteFile(filePath, content, 0644); err != nil {
		InternalError(c, "Failed to save file")
		return
	}

	// 更新用户头像URL
	user, err := h.userRepo.FindByID(userID)
	if err != nil {
		InternalError(c, "Failed to find user")
		return
	}

	// 删除旧头像文件（如果存在且是本地上传的）
	if user.Avatar != "" && strings.HasPrefix(user.Avatar, h.baseURL) {
		oldFilename := filepath.Base(user.Avatar)
		oldPath := filepath.Join(h.uploadDir, oldFilename)
		os.Remove(oldPath) // 忽略错误
	}

	// 更新头像URL
	avatarURL := h.baseURL + "/" + filename
	user.Avatar = avatarURL
	if err := h.userRepo.Update(user); err != nil {
		InternalError(c, "Failed to update avatar")
		return
	}

	Success(c, gin.H{
		"avatar":  avatarURL,
		"message": "Avatar uploaded successfully",
	})
}

// Delete 删除头像
// DELETE /api/user/avatar
func (h *AvatarHandler) Delete(c *gin.Context) {
	userID, ok := context.GetUserID(c)
	if !ok {
		Unauthorized(c, "Not authenticated")
		return
	}

	user, err := h.userRepo.FindByID(userID)
	if err != nil {
		InternalError(c, "Failed to find user")
		return
	}

	// 删除旧头像文件（如果存在且是本地上传的）
	if user.Avatar != "" && strings.HasPrefix(user.Avatar, h.baseURL) {
		oldFilename := filepath.Base(user.Avatar)
		oldPath := filepath.Join(h.uploadDir, oldFilename)
		os.Remove(oldPath) // 忽略错误
	}

	// 清空头像URL
	user.Avatar = ""
	if err := h.userRepo.Update(user); err != nil {
		InternalError(c, "Failed to update avatar")
		return
	}

	Success(c, gin.H{
		"message": "Avatar deleted successfully",
	})
}

// ServeAvatar 提供头像文件服务
// GET /avatars/:filename
func (h *AvatarHandler) ServeAvatar(c *gin.Context) {
	filename := c.Param("filename")

	// 安全检查：防止目录遍历
	if strings.Contains(filename, "..") || strings.Contains(filename, "/") {
		NotFound(c, "Avatar not found")
		return
	}

	filePath := filepath.Join(h.uploadDir, filename)

	// 检查文件是否存在
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		NotFound(c, "Avatar not found")
		return
	}

	c.File(filePath)
}
