package audit

import (
	"testing"
)

/* ========== Action/Result 常量验证 ========== */

func TestAction_Constants_NotEmpty(t *testing.T) {
	actions := []Action{
		ActionPasswordChange, ActionPasswordReset, ActionSecretReset,
		ActionRoleChange, ActionAccountLock, ActionAccountUnlock,
		ActionAccountDelete, ActionAccountCreate, ActionStatusChange,
		ActionTokenIssue, ActionTokenRevoke, ActionAppCreate, ActionAppDelete,
		ActionConfigChange, ActionEmailChange, ActionMFAEnable, ActionMFADisable,
		ActionProviderCreate, ActionProviderDelete, ActionJWTSecretRotate,
	}
	for _, a := range actions {
		if string(a) == "" {
			t.Error("Action constant should not be empty")
		}
	}
}

func TestResult_Constants_NotEmpty(t *testing.T) {
	results := []Result{ResultSuccess, ResultFailure, ResultDenied}
	for _, r := range results {
		if string(r) == "" {
			t.Error("Result constant should not be empty")
		}
	}
}

/* ========== Log 调用不 panic ========== */

func TestLog_Success_NoPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Log(success) panicked: %v", r)
		}
	}()
	Log(ActionPasswordChange, ResultSuccess, "actor-1", "target-1", "127.0.0.1")
}

func TestLog_Failure_NoPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Log(failure) panicked: %v", r)
		}
	}()
	Log(ActionAccountDelete, ResultFailure, "actor-2", "target-2", "192.168.1.1")
}

func TestLog_Denied_NoPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Log(denied) panicked: %v", r)
		}
	}()
	Log(ActionRoleChange, ResultDenied, "actor-3", "target-3", "10.0.0.1")
}

func TestLog_WithExtra_NoPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Log(extra) panicked: %v", r)
		}
	}()
	Log(ActionTokenIssue, ResultSuccess, "client-id", "user-id", "1.2.3.4",
		"grant_type", "authorization_code", "scope", "openid profile")
}

func TestLog_EmptyFields_NoPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Log(empty) panicked: %v", r)
		}
	}()
	Log(ActionPasswordReset, ResultSuccess, "", "", "")
}

/* ========== Action 唯一性 ========== */

func TestAction_Constants_Unique(t *testing.T) {
	actions := []Action{
		ActionPasswordChange, ActionPasswordReset, ActionSecretReset,
		ActionRoleChange, ActionAccountLock, ActionAccountUnlock,
		ActionAccountDelete, ActionAccountCreate, ActionStatusChange,
		ActionTokenIssue, ActionTokenRevoke, ActionAppCreate, ActionAppDelete,
		ActionConfigChange, ActionEmailChange, ActionMFAEnable, ActionMFADisable,
		ActionProviderCreate, ActionProviderDelete, ActionJWTSecretRotate,
	}
	seen := make(map[Action]bool)
	for _, a := range actions {
		if seen[a] {
			t.Errorf("duplicate Action constant: %q", a)
		}
		seen[a] = true
	}
}
