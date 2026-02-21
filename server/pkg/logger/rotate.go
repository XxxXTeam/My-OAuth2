package logger

import (
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

/*
 * RotateWriter 日志文件轮转写入器
 * 功能：实现 io.Writer 接口，当文件超过指定大小时自动轮转
 *       支持最大备份数、过期清理和 gzip 压缩
 */
type RotateWriter struct {
	mu         sync.Mutex
	filePath   string
	maxSizeMB  int
	maxBackups int
	maxAgeDays int
	compress   bool
	file       *os.File
	size       int64
}

/*
 * NewRotateWriter 创建日志轮转写入器
 * @param filePath   - 日志文件路径
 * @param maxSizeMB  - 单文件最大 MB（默认 100）
 * @param maxBackups - 保留历史文件数（默认 5）
 * @param maxAgeDays - 历史文件最大保留天数（默认 30）
 * @param compress   - 是否压缩历史文件
 */
func NewRotateWriter(filePath string, maxSizeMB, maxBackups, maxAgeDays int, compress bool) (*RotateWriter, error) {
	if maxSizeMB <= 0 {
		maxSizeMB = 100
	}
	if maxBackups <= 0 {
		maxBackups = 5
	}
	if maxAgeDays <= 0 {
		maxAgeDays = 30
	}

	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create log directory: %w", err)
	}

	rw := &RotateWriter{
		filePath:   filePath,
		maxSizeMB:  maxSizeMB,
		maxBackups: maxBackups,
		maxAgeDays: maxAgeDays,
		compress:   compress,
	}

	if err := rw.openFile(); err != nil {
		return nil, err
	}

	return rw, nil
}

func (rw *RotateWriter) openFile() error {
	f, err := os.OpenFile(rw.filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("failed to open log file: %w", err)
	}

	info, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}

	rw.file = f
	rw.size = info.Size()
	return nil
}

/* Write 实现 io.Writer，超过大小限制时自动触发轮转 */
func (rw *RotateWriter) Write(p []byte) (n int, err error) {
	rw.mu.Lock()
	defer rw.mu.Unlock()

	if rw.file == nil {
		if err := rw.openFile(); err != nil {
			return 0, err
		}
	}

	// Check if rotation is needed
	maxBytes := int64(rw.maxSizeMB) * 1024 * 1024
	if rw.size+int64(len(p)) > maxBytes {
		if err := rw.rotate(); err != nil {
			// If rotation fails, try to write anyway
			_ = err
		}
	}

	n, err = rw.file.Write(p)
	rw.size += int64(n)
	return n, err
}

func (rw *RotateWriter) rotate() error {
	// Close current file
	if rw.file != nil {
		rw.file.Close()
		rw.file = nil
	}

	// Generate rotation filename with timestamp
	timestamp := time.Now().Format("20060102-150405")
	ext := filepath.Ext(rw.filePath)
	base := strings.TrimSuffix(rw.filePath, ext)
	rotatedPath := fmt.Sprintf("%s-%s%s", base, timestamp, ext)

	// Rename current file
	if err := os.Rename(rw.filePath, rotatedPath); err != nil {
		// If rename fails, just open a new file
		return rw.openFile()
	}

	// Compress old file in background if enabled
	if rw.compress {
		go rw.compressFile(rotatedPath)
	}

	// Cleanup old files
	go rw.cleanup()

	// Open new file
	return rw.openFile()
}

func (rw *RotateWriter) compressFile(filePath string) {
	src, err := os.Open(filePath)
	if err != nil {
		return
	}
	defer src.Close()

	dst, err := os.Create(filePath + ".gz")
	if err != nil {
		return
	}

	gz := gzip.NewWriter(dst)
	if _, err := io.Copy(gz, src); err != nil {
		gz.Close()
		dst.Close()
		os.Remove(filePath + ".gz")
		return
	}
	gz.Close()
	dst.Close()
	src.Close()
	os.Remove(filePath)
}

func (rw *RotateWriter) cleanup() {
	dir := filepath.Dir(rw.filePath)
	base := filepath.Base(rw.filePath)
	ext := filepath.Ext(base)
	prefix := strings.TrimSuffix(base, ext)

	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}

	type logFile struct {
		path    string
		modTime time.Time
	}

	var oldFiles []logFile
	cutoff := time.Now().AddDate(0, 0, -rw.maxAgeDays)

	for _, entry := range entries {
		name := entry.Name()
		if name == base {
			continue // Skip current log file
		}
		if !strings.HasPrefix(name, prefix+"-") {
			continue
		}
		if !strings.Contains(name, ext) {
			continue
		}

		fullPath := filepath.Join(dir, name)
		info, err := entry.Info()
		if err != nil {
			continue
		}

		// Delete files older than maxAgeDays
		if info.ModTime().Before(cutoff) {
			os.Remove(fullPath)
			continue
		}

		oldFiles = append(oldFiles, logFile{path: fullPath, modTime: info.ModTime()})
	}

	// Sort by modification time (newest first)
	sort.Slice(oldFiles, func(i, j int) bool {
		return oldFiles[i].modTime.After(oldFiles[j].modTime)
	})

	// Delete excess backups
	if len(oldFiles) > rw.maxBackups {
		for _, f := range oldFiles[rw.maxBackups:] {
			os.Remove(f.path)
		}
	}
}

/* Close 关闭轮转写入器和当前日志文件 */
func (rw *RotateWriter) Close() error {
	rw.mu.Lock()
	defer rw.mu.Unlock()
	if rw.file != nil {
		err := rw.file.Close()
		rw.file = nil
		return err
	}
	return nil
}
