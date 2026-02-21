package service

import (
	"encoding/json"
	"fmt"
	"server/internal/model"
	"server/internal/repository"
	"server/pkg/email"
	"server/pkg/logger"
	"sync"
	"time"
)

/*
 * EmailQueueService 邮件队列服务
 * 功能：接收邮件任务入队请求，后台 worker 异步处理发送
 *       支持失败重试、状态跟踪，解耦请求处理与邮件发送
 */
type EmailQueueService struct {
	taskRepo     *repository.EmailTaskRepository
	emailSvc     *email.Service
	log          *logger.Logger
	stopCh       chan struct{}
	wg           sync.WaitGroup
	pollInterval time.Duration
}

func NewEmailQueueService(
	taskRepo *repository.EmailTaskRepository,
	emailSvc *email.Service,
	log *logger.Logger,
) *EmailQueueService {
	return &EmailQueueService{
		taskRepo:     taskRepo,
		emailSvc:     emailSvc,
		log:          log,
		stopCh:       make(chan struct{}),
		pollInterval: 5 * time.Second,
	}
}

/* SetEmailService 热更新邮件服务实例（管理员配置 SMTP 后生效） */
func (s *EmailQueueService) SetEmailService(svc *email.Service) {
	s.emailSvc = svc
}

/*
 * EnqueueVerification 入队邮箱验证邮件
 * 功能：将验证邮件任务写入数据库队列，立即返回
 */
func (s *EmailQueueService) EnqueueVerification(recipient, username, verifyLink string) error {
	data, _ := json.Marshal(map[string]string{
		"username":    username,
		"verify_link": verifyLink,
	})
	task := &model.EmailTask{
		Type:         model.EmailTaskVerification,
		Recipient:    recipient,
		TemplateData: string(data),
		Status:       model.EmailTaskPending,
	}
	return s.taskRepo.Enqueue(task)
}

/*
 * EnqueueEmailChange 入队邮箱更换验证邮件
 * 功能：将更换邮箱验证邮件任务写入数据库队列
 */
func (s *EmailQueueService) EnqueueEmailChange(recipient, username, verifyLink string) error {
	data, _ := json.Marshal(map[string]string{
		"username":    username,
		"verify_link": verifyLink,
	})
	task := &model.EmailTask{
		Type:         model.EmailTaskEmailChange,
		Recipient:    recipient,
		TemplateData: string(data),
		Status:       model.EmailTaskPending,
	}
	return s.taskRepo.Enqueue(task)
}

/*
 * EnqueuePasswordReset 入队密码重置邮件
 * 功能：将密码重置链接邮件任务写入数据库队列
 */
func (s *EmailQueueService) EnqueuePasswordReset(recipient, username, resetLink string) error {
	data, _ := json.Marshal(map[string]string{
		"username":   username,
		"reset_link": resetLink,
	})
	task := &model.EmailTask{
		Type:         model.EmailTaskPasswordReset,
		Recipient:    recipient,
		TemplateData: string(data),
		Status:       model.EmailTaskPending,
	}
	return s.taskRepo.Enqueue(task)
}

/*
 * EnqueueResetSuccess 入队密码重置成功通知邮件
 * 功能：将密码重置成功通知邮件任务写入数据库队列
 */
func (s *EmailQueueService) EnqueueResetSuccess(recipient, username string) error {
	data, _ := json.Marshal(map[string]string{
		"username": username,
	})
	task := &model.EmailTask{
		Type:         model.EmailTaskResetSuccess,
		Recipient:    recipient,
		TemplateData: string(data),
		Status:       model.EmailTaskPending,
	}
	return s.taskRepo.Enqueue(task)
}

/* Start 启动后台邮件处理 worker */
func (s *EmailQueueService) Start() {
	s.wg.Add(1)
	go s.worker()
}

/* Stop 停止后台 worker */
func (s *EmailQueueService) Stop() {
	close(s.stopCh)
	s.wg.Wait()
}

/* worker 后台轮询处理邮件任务 */
func (s *EmailQueueService) worker() {
	defer s.wg.Done()
	ticker := time.NewTicker(s.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.processBatch()
		}
	}
}

/* processBatch 批量处理待发送的邮件任务 */
func (s *EmailQueueService) processBatch() {
	if s.emailSvc == nil {
		return
	}

	tasks, err := s.taskRepo.FetchPending(10)
	if err != nil {
		s.log.Error("Failed to fetch pending email tasks", "error", err)
		return
	}

	for _, task := range tasks {
		if err := s.taskRepo.MarkProcessing(task.ID); err != nil {
			continue
		}
		if err := s.processTask(task); err != nil {
			/* 区分日志级别：SMTP 未配置用 Debug（避免刷屏），真正失败用 Warn */
			if err.Error() == "email service not configured" {
				s.log.Debug("Email task deferred (SMTP not configured)",
					"task_id", task.ID,
					"type", task.Type,
					"recipient", task.Recipient,
				)
			} else {
				s.log.Warn("Email task failed",
					"task_id", task.ID,
					"type", task.Type,
					"recipient", task.Recipient,
					"attempt", task.Attempts+1,
					"error", err,
				)
			}
			_ = s.taskRepo.MarkFailed(task.ID, err.Error(), task.Attempts+1)
		} else {
			s.log.Info("Email sent successfully",
				"task_id", task.ID,
				"type", task.Type,
				"recipient", task.Recipient,
			)
			_ = s.taskRepo.MarkSent(task.ID)
		}
	}
}

/* processTask 根据任务类型调用对应的邮件发送方法 */
func (s *EmailQueueService) processTask(task model.EmailTask) error {
	var data map[string]string
	if err := json.Unmarshal([]byte(task.TemplateData), &data); err != nil {
		return fmt.Errorf("invalid template data: %w", err)
	}

	switch task.Type {
	case model.EmailTaskVerification, model.EmailTaskEmailChange:
		return s.emailSvc.SendEmailVerification(task.Recipient, data["username"], data["verify_link"])
	case model.EmailTaskPasswordReset:
		return s.emailSvc.SendPasswordReset(task.Recipient, data["username"], data["reset_link"])
	case model.EmailTaskResetSuccess:
		return s.emailSvc.SendPasswordResetSuccess(task.Recipient, data["username"])
	default:
		return fmt.Errorf("unknown email task type: %s", task.Type)
	}
}
