'use client';

import { createContext, useContext, useEffect, useState, useCallback, useRef, ReactNode } from 'react';
import { api } from './api';
import type { User } from './types';

/* 默认提前刷新时间：过期前 2 分钟 */
const REFRESH_BEFORE_EXPIRY_MS = 2 * 60 * 1000;

interface AuthContextType {
  user: User | null;
  isLoading: boolean;
  isAuthenticated: boolean;
  login: (email: string, password: string) => Promise<{ success: boolean; error?: string }>;
  register: (email: string, username: string, password: string) => Promise<{ success: boolean; error?: string }>;
  logout: () => Promise<void>;
  refreshUser: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

/**
 * 从 JWT payload 中解析过期时间（秒级时间戳）
 * 不依赖外部库，仅读取 exp 字段用于定时刷新
 */
function getTokenExpiry(token: string | null): number | null {
  if (!token) return null;
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));
    return typeof payload.exp === 'number' ? payload.exp : null;
  } catch {
    return null;
  }
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const refreshTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const scheduleRefreshRef = useRef<() => void>(() => {});

  /** 清理定时刷新 */
  const clearRefreshTimer = useCallback(() => {
    if (refreshTimerRef.current) {
      clearTimeout(refreshTimerRef.current);
      refreshTimerRef.current = null;
    }
  }, []);

  /**
   * refresh 失败后的二次确认：
   * 可能是另一条路径已经刷新成功，当前 token 实际有效。
   * 先尝试 getProfile，仍然失败才真正清除登录状态。
   */
  const handleRefreshFailure = useCallback(async () => {
    const currentToken = api.getAccessToken();
    if (currentToken) {
      const profileRes = await api.getProfile();
      if (profileRes.success && profileRes.data) {
        setUser(profileRes.data);
        scheduleRefreshRef.current();
        return;
      }
    }
    setUser(null);
    api.setAccessToken(null);
    if (typeof window !== 'undefined') {
      localStorage.removeItem('refresh_token');
    }
  }, []);

  /** 设置定时刷新：在 access token 过期前自动刷新 */
  const scheduleRefresh = useCallback(() => {
    clearRefreshTimer();
    const token = api.getAccessToken();
    const exp = getTokenExpiry(token);
    if (!exp) return;

    const now = Date.now();
    const expiresAt = exp * 1000;
    const delay = expiresAt - now - REFRESH_BEFORE_EXPIRY_MS;

    if (delay <= 0) {
      /* token 已过期或即将过期，立即刷新 */
      api.refreshToken().then((res) => {
        if (res.success) {
          scheduleRefreshRef.current();
        } else {
          handleRefreshFailure();
        }
      });
      return;
    }

    refreshTimerRef.current = setTimeout(async () => {
      const res = await api.refreshToken();
      if (res.success) {
        scheduleRefreshRef.current();
      } else {
        await handleRefreshFailure();
      }
    }, delay);
  }, [clearRefreshTimer, handleRefreshFailure]);

  /* 保持 ref 与最新 scheduleRefresh 同步 */
  useEffect(() => {
    scheduleRefreshRef.current = scheduleRefresh;
  }, [scheduleRefresh]);

  /**
   * 页面可见性变化监听：
   * 用户切标签页/锁屏/休眠回来后，定时器可能已不准确，
   * 主动检查 token 状态并重新调度刷新。
   */
  useEffect(() => {
    const handleVisibilityChange = () => {
      if (document.visibilityState === 'visible' && user) {
        const token = api.getAccessToken();
        const exp = getTokenExpiry(token);
        if (!exp) return;

        const now = Date.now();
        const expiresAt = exp * 1000;
        const remaining = expiresAt - now;

        if (remaining <= 0) {
          /* token 已过期，立即刷新 */
          api.refreshToken().then((res) => {
            if (res.success) {
              scheduleRefreshRef.current();
            } else {
              handleRefreshFailure();
            }
          });
        } else if (remaining <= REFRESH_BEFORE_EXPIRY_MS) {
          /* 即将过期，立即刷新 */
          api.refreshToken().then((res) => {
            if (res.success) {
              scheduleRefreshRef.current();
            }
          });
        } else {
          /* token 仍然有效，重新调度 */
          scheduleRefreshRef.current();
        }
      }
    };

    document.addEventListener('visibilitychange', handleVisibilityChange);
    return () => document.removeEventListener('visibilitychange', handleVisibilityChange);
  }, [user, handleRefreshFailure]);

  const checkAuth = useCallback(async () => {
    const token = api.getAccessToken();
    const refreshToken = typeof window !== 'undefined' ? localStorage.getItem('refresh_token') : null;

    if (!token && !refreshToken) {
      setIsLoading(false);
      return;
    }

    /* 尝试用当前 token 获取用户信息（api client 内置自动刷新重试） */
    const response = await api.getProfile();
    if (response.success && response.data) {
      setUser(response.data);
      scheduleRefresh();
    } else if (refreshToken) {
      /* 显式尝试 refresh（处理 access_token 已丢失但 refresh_token 仍有效的情况） */
      const refreshResponse = await api.refreshToken();
      if (refreshResponse.success) {
        const profileResponse = await api.getProfile();
        if (profileResponse.success && profileResponse.data) {
          setUser(profileResponse.data);
          scheduleRefresh();
        }
      } else {
        api.setAccessToken(null);
        if (typeof window !== 'undefined') {
          localStorage.removeItem('refresh_token');
        }
      }
    }
    setIsLoading(false);
  }, [scheduleRefresh]);

  useEffect(() => {
    checkAuth();
    return () => clearRefreshTimer();
  }, [checkAuth, clearRefreshTimer]);

  const login = async (email: string, password: string) => {
    const response = await api.login({ email, password });
    if (response.success && response.data) {
      setUser(response.data.user);
      scheduleRefresh();
      return { success: true };
    }
    return { success: false, error: response.error?.message || 'Login failed' };
  };

  const register = async (email: string, username: string, password: string) => {
    const response = await api.register({ email, username, password });
    if (response.success) {
      // Auto login after registration
      return login(email, password);
    }
    return { success: false, error: response.error?.message || 'Registration failed' };
  };

  const logout = async () => {
    clearRefreshTimer();
    await api.logout();
    setUser(null);
  };

  const refreshUser = async () => {
    const response = await api.getProfile();
    if (response.success && response.data) {
      setUser(response.data);
    }
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        isLoading,
        isAuthenticated: !!user,
        login,
        register,
        logout,
        refreshUser,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
