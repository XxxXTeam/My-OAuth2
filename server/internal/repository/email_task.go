package repository

import (
	"server/internal/model"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

/*
 * EmailTaskRepository 邮件任务仓储
 * 功能：管理邮件任务队列的 CRUD 操作，供后台 worker 消费
 */
type EmailTaskRepository struct {
	db *gorm.DB
}

func NewEmailTaskRepository(db *gorm.DB) *EmailTaskRepository {
	return &EmailTaskRepository{db: db}
}

/* Enqueue 将邮件任务入队 */
func (r *EmailTaskRepository) Enqueue(task *model.EmailTask) error {
	return r.db.Create(task).Error
}

/* FetchPending 获取待处理的任务（pending 且到达重试时间的） */
func (r *EmailTaskRepository) FetchPending(limit int) ([]model.EmailTask, error) {
	var tasks []model.EmailTask
	now := time.Now()
	err := r.db.Where(
		"(status = ? OR (status = ? AND attempts < max_attempts AND (next_retry_at IS NULL OR next_retry_at <= ?)))",
		model.EmailTaskPending, model.EmailTaskFailed, now,
	).Order("created_at ASC").Limit(limit).Find(&tasks).Error
	return tasks, err
}

/* MarkProcessing 标记任务为处理中 */
func (r *EmailTaskRepository) MarkProcessing(id uuid.UUID) error {
	return r.db.Model(&model.EmailTask{}).Where("id = ?", id).
		Updates(map[string]interface{}{
			"status":  model.EmailTaskProcessing,
			"attempts": gorm.Expr("attempts + 1"),
		}).Error
}

/* MarkSent 标记任务为已发送 */
func (r *EmailTaskRepository) MarkSent(id uuid.UUID) error {
	now := time.Now()
	return r.db.Model(&model.EmailTask{}).Where("id = ?", id).
		Updates(map[string]interface{}{
			"status":       model.EmailTaskSent,
			"processed_at": &now,
		}).Error
}

/* MarkFailed 标记任务为失败，设置下次重试时间 */
func (r *EmailTaskRepository) MarkFailed(id uuid.UUID, errMsg string, attempts int) error {
	nextRetry := time.Now().Add(time.Duration(attempts*attempts) * time.Minute)
	return r.db.Model(&model.EmailTask{}).Where("id = ?", id).
		Updates(map[string]interface{}{
			"status":        model.EmailTaskFailed,
			"error":         errMsg,
			"next_retry_at": &nextRetry,
		}).Error
}

/* CleanupOld 清理已完成的旧任务 */
func (r *EmailTaskRepository) CleanupOld(olderThan time.Duration) error {
	cutoff := time.Now().Add(-olderThan)
	return r.db.Where("status = ? AND processed_at < ?", model.EmailTaskSent, cutoff).
		Delete(&model.EmailTask{}).Error
}
