import type {
  ApiResponse,
  User,
  UserRole,
  LoginRequest,
  RegisterRequest,
  LoginResponse,
  Application,
  CreateAppRequest,
  UpdateAppRequest,
  UpdateProfileRequest,
  AdminCreateUserRequest,
  AdminUpdateUserRequest,
  AdminStats,
  LoginTrend,
  LoginLog,
  AppStats,
  UserAuthorization,
  Webhook,
  WebhookDelivery,
  CreateWebhookRequest,
  UpdateWebhookRequest,
  SystemConfig,
  SystemConfigUpdate,
  FederationProvider,
  CreateFederationProviderRequest,
  SocialProvider,
} from './types';

// In production (embedded in server), use same origin; in dev, use configured URL
const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || (typeof window !== 'undefined' ? window.location.origin : 'http://localhost:8080');

/* 从 document.cookie 中读取指定名称的 cookie 值 */
function getCookie(name: string): string | null {
  if (typeof document === 'undefined') return null;
  const match = document.cookie.match(new RegExp('(?:^|; )' + name.replace(/([.$?*|{}()\[\]\\/+^])/g, '\\$1') + '=([^;]*)'));
  return match ? decodeURIComponent(match[1]) : null;
}

class ApiClient {
  private accessToken: string | null = null;
  private isRefreshing = false;
  private refreshPromise: Promise<boolean> | null = null;

  /*
   * 请求去重：防止同一 mutation 请求在上一次未完成时重复发送
   * key = method + endpoint，value = 进行中的 Promise
   * 仅对 POST/PUT/DELETE 等写操作生效，GET 请求不去重
   */
  private inflightMutations = new Map<string, Promise<ApiResponse<unknown>>>();

  constructor() {
    if (typeof window !== 'undefined') {
      this.accessToken = localStorage.getItem('access_token');
    }
  }

  setAccessToken(token: string | null) {
    this.accessToken = token;
    if (typeof window !== 'undefined') {
      if (token) {
        localStorage.setItem('access_token', token);
      } else {
        localStorage.removeItem('access_token');
      }
    }
  }

  getAccessToken(): string | null {
    return this.accessToken;
  }

  /**
   * 尝试刷新 token（防止并发多次刷新）
   * 返回 true 表示刷新成功，false 表示失败
   */
  private async tryRefresh(): Promise<boolean> {
    if (this.isRefreshing && this.refreshPromise) {
      return this.refreshPromise;
    }

    this.isRefreshing = true;
    this.refreshPromise = (async () => {
      try {
        const refreshToken = typeof window !== 'undefined' ? localStorage.getItem('refresh_token') : null;
        if (!refreshToken) return false;

        const url = `${API_BASE_URL}/api/auth/refresh`;
        const headers: Record<string, string> = { 'Content-Type': 'application/json' };
        const csrfToken = getCookie('csrf_token');
        if (csrfToken) headers['X-CSRF-Token'] = csrfToken;

        const response = await fetch(url, {
          method: 'POST',
          headers,
          body: JSON.stringify({ refresh_token: refreshToken }),
          credentials: 'include',
        });

        if (!response.ok) return false;

        const data = await response.json();
        const tokenData = data.data || data;

        if (tokenData.access_token) {
          this.setAccessToken(tokenData.access_token);
          if (tokenData.refresh_token && typeof window !== 'undefined') {
            localStorage.setItem('refresh_token', tokenData.refresh_token);
          }
          return true;
        }
        return false;
      } catch {
        return false;
      } finally {
        this.isRefreshing = false;
        this.refreshPromise = null;
      }
    })();

    return this.refreshPromise;
  }

  private async request<T>(
    endpoint: string,
    options: RequestInit = {},
    _isRetry = false
  ): Promise<ApiResponse<T>> {
    /* 请求去重：mutation 请求（POST/PUT/DELETE）如果已有同 endpoint 的请求在飞行中，直接复用 */
    const method = (options.method || 'GET').toUpperCase();
    if (method !== 'GET' && method !== 'HEAD' && !_isRetry) {
      const dedupeKey = `${method}:${endpoint}`;
      const inflight = this.inflightMutations.get(dedupeKey);
      if (inflight) {
        return inflight as Promise<ApiResponse<T>>;
      }
      const promise = this._doRequest<T>(endpoint, options, _isRetry);
      this.inflightMutations.set(dedupeKey, promise as Promise<ApiResponse<unknown>>);
      promise.finally(() => this.inflightMutations.delete(dedupeKey));
      return promise;
    }
    return this._doRequest<T>(endpoint, options, _isRetry);
  }

  private async _doRequest<T>(
    endpoint: string,
    options: RequestInit = {},
    _isRetry = false
  ): Promise<ApiResponse<T>> {
    const url = `${API_BASE_URL}${endpoint}`;
    const headers: HeadersInit = {
      'Content-Type': 'application/json',
      ...options.headers,
    };

    if (this.accessToken) {
      (headers as Record<string, string>)['Authorization'] = `Bearer ${this.accessToken}`;
    }

    /* 对状态变更请求自动附加 CSRF Token（从 cookie 读取） */
    const method = (options.method || 'GET').toUpperCase();
    if (method !== 'GET' && method !== 'HEAD') {
      const csrfToken = getCookie('csrf_token');
      if (csrfToken) {
        (headers as Record<string, string>)['X-CSRF-Token'] = csrfToken;
      }
    }

    /* 请求超时控制：默认 30 秒，防止请求永远挂起 */
    const timeoutMs = 30000;
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

    try {
      const response = await fetch(url, {
        ...options,
        headers,
        credentials: 'include', /* 携带 Cookie（httpOnly access_token + csrf_token） */
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      const data = await response.json();

      if (!response.ok) {
        const error = data.error || { code: 'UNKNOWN', message: 'An error occurred' };

        /* 自动刷新：当 access token 过期时，尝试用 refresh token 换取新 token 并重试 */
        if (
          !_isRetry &&
          response.status === 401 &&
          (error.code === 'TOKEN_EXPIRED' || error.code === 'UNAUTHORIZED') &&
          !endpoint.includes('/api/auth/refresh') &&
          !endpoint.includes('/api/auth/login')
        ) {
          const refreshed = await this.tryRefresh();
          if (refreshed) {
            return this.request<T>(endpoint, options, true);
          }
        }

        /* 限流错误：读取 Retry-After 头，附带剩余等待秒数 */
        if (response.status === 429) {
          const retryAfter = response.headers.get('Retry-After');
          const retrySeconds = retryAfter ? parseInt(retryAfter, 10) : 0;
          const msg = retrySeconds > 0
            ? `${error.message || 'Too many requests'} (${retrySeconds}s)`
            : (error.message || 'Too many requests, please try again later');
          return {
            success: false,
            error: { code: 'TOO_MANY_REQUESTS', message: msg, retryAfter: retrySeconds || undefined },
          };
        }

        return { success: false, error };
      }

      // Handle responses that already have success/data structure
      if ('success' in data) {
        return data;
      }

      // Wrap raw data in standard response format
      return {
        success: true,
        data: data as T,
      };
    } catch (error) {
      clearTimeout(timeoutId);
      /* 区分超时和网络错误 */
      if (error instanceof DOMException && error.name === 'AbortError') {
        return {
          success: false,
          error: {
            code: 'REQUEST_TIMEOUT',
            message: 'Request timed out, please try again',
          },
        };
      }
      return {
        success: false,
        error: {
          code: 'NETWORK_ERROR',
          message: error instanceof Error ? error.message : 'Network error',
        },
      };
    }
  }

  // Auth endpoints
  async register(data: RegisterRequest): Promise<ApiResponse<User>> {
    return this.request<User>('/api/auth/register', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  async login(data: LoginRequest): Promise<ApiResponse<LoginResponse>> {
    const response = await this.request<LoginResponse>('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify(data),
    });

    if (response.success && response.data) {
      this.setAccessToken(response.data.tokens.access_token);
      if (typeof window !== 'undefined') {
        localStorage.setItem('refresh_token', response.data.tokens.refresh_token);
      }
    }

    return response;
  }

  async logout(): Promise<void> {
    await this.request('/api/auth/logout', { method: 'POST' });
    this.setAccessToken(null);
    if (typeof window !== 'undefined') {
      localStorage.removeItem('refresh_token');
    }
  }

  // Password reset endpoints
  async forgotPassword(email: string): Promise<ApiResponse<{ message: string; token?: string }>> {
    return this.request<{ message: string; token?: string }>('/api/auth/forgot-password', {
      method: 'POST',
      body: JSON.stringify({ email }),
    });
  }

  async validateResetToken(token: string): Promise<ApiResponse<{ valid: boolean; email: string }>> {
    return this.request<{ valid: boolean; email: string }>('/api/auth/validate-reset-token', {
      method: 'POST',
      body: JSON.stringify({ token }),
    });
  }

  async resetPassword(token: string, newPassword: string): Promise<ApiResponse<{ message: string }>> {
    return this.request<{ message: string }>('/api/auth/reset-password', {
      method: 'POST',
      body: JSON.stringify({ token, new_password: newPassword }),
    });
  }

  async refreshToken(): Promise<ApiResponse<{ access_token: string; refresh_token: string }>> {
    /* 统一走 tryRefresh() 去重锁，避免与 401 自动重试产生竞态 */
    const success = await this.tryRefresh();
    if (success) {
      return {
        success: true,
        data: {
          access_token: this.accessToken || '',
          refresh_token: (typeof window !== 'undefined' ? localStorage.getItem('refresh_token') : null) || '',
        },
      };
    }
    return { success: false, error: { code: 'REFRESH_FAILED', message: 'Failed to refresh token' } };
  }

  // User endpoints
  async getProfile(): Promise<ApiResponse<User>> {
    return this.request<User>('/api/user/profile');
  }

  async updateProfile(data: UpdateProfileRequest): Promise<ApiResponse<User>> {
    return this.request<User>('/api/user/profile', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  /* 修改密码 */
  async changePassword(oldPassword: string, newPassword: string): Promise<ApiResponse<{ message: string }>> {
    return this.request<{ message: string }>('/api/user/password', {
      method: 'POST',
      body: JSON.stringify({ old_password: oldPassword, new_password: newPassword }),
    });
  }

  /* 删除账号 (GDPR 合规) */
  async deleteAccount(password: string): Promise<ApiResponse<{ message: string }>> {
    return this.request<{ message: string }>('/api/user/delete-account', {
      method: 'POST',
      body: JSON.stringify({ password }),
    });
  }

  /* 密码强度实时校验 */
  async checkPasswordStrength(password: string): Promise<ApiResponse<{
    score: number; level: string; has_upper: boolean; has_lower: boolean;
    has_digit: boolean; has_special: boolean; length_valid: boolean; valid: boolean; error?: string;
  }>> {
    return this.request('/api/auth/check-password', {
      method: 'POST',
      body: JSON.stringify({ password }),
    });
  }

  /* 上传头像 */
  async uploadAvatar(file: File): Promise<ApiResponse<{ avatar: string; message: string }>> {
    const url = `${API_BASE_URL}/api/user/avatar`;
    const formData = new FormData();
    formData.append('avatar', file);

    const headers: Record<string, string> = {};
    if (this.accessToken) {
      headers['Authorization'] = `Bearer ${this.accessToken}`;
    }
    const csrfToken = getCookie('csrf_token');
    if (csrfToken) {
      headers['X-CSRF-Token'] = csrfToken;
    }

    try {
      const response = await fetch(url, {
        method: 'POST',
        headers,
        body: formData,
        credentials: 'include',
      });
      const data = await response.json();
      if (!response.ok) {
        return { success: false, error: data.error || { code: 'UNKNOWN', message: 'Upload failed' } };
      }
      return { success: true, data };
    } catch (error) {
      return { success: false, error: { code: 'NETWORK_ERROR', message: error instanceof Error ? error.message : 'Network error' } };
    }
  }

  /* 删除头像 */
  async deleteAvatar(): Promise<ApiResponse<{ message: string }>> {
    return this.request<{ message: string }>('/api/user/avatar/delete', {
      method: 'POST',
    });
  }

  /* 发送邮箱验证邮件 */
  async sendEmailVerification(): Promise<ApiResponse<{ message: string }>> {
    return this.request<{ message: string }>('/api/user/email/send-verify', {
      method: 'POST',
    });
  }

  /* 验证邮箱令牌 */
  async verifyEmail(token: string): Promise<ApiResponse<{ message: string }>> {
    return this.request<{ message: string }>('/api/user/email/verify', {
      method: 'POST',
      body: JSON.stringify({ token }),
    });
  }

  /* 请求更换邮箱 */
  async requestEmailChange(newEmail: string): Promise<ApiResponse<{ message: string }>> {
    return this.request<{ message: string }>('/api/user/email/change', {
      method: 'POST',
      body: JSON.stringify({ new_email: newEmail }),
    });
  }

  async getUserAuthorizations(): Promise<ApiResponse<{ authorizations: UserAuthorization[] }>> {
    return this.request<{ authorizations: UserAuthorization[] }>('/api/user/authorizations');
  }

  async revokeAuthorization(id: string): Promise<ApiResponse<void>> {
    return this.request<void>(`/api/user/authorizations/${id}/revoke`, {
      method: 'POST',
    });
  }

  // Application endpoints
  async getApps(): Promise<ApiResponse<Application[]>> {
    return this.request<Application[]>('/api/apps');
  }

  async createApp(data: CreateAppRequest): Promise<ApiResponse<Application>> {
    return this.request<Application>('/api/apps', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  async getApp(id: string): Promise<ApiResponse<Application>> {
    return this.request<Application>(`/api/apps/${id}`);
  }

  async updateApp(id: string, data: UpdateAppRequest): Promise<ApiResponse<Application>> {
    return this.request<Application>(`/api/apps/${id}`, {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  async deleteApp(id: string): Promise<ApiResponse<void>> {
    return this.request<void>(`/api/apps/${id}/delete`, {
      method: 'POST',
    });
  }

  async resetAppSecret(id: string): Promise<ApiResponse<Application>> {
    return this.request<Application>(`/api/apps/${id}/reset-secret`, {
      method: 'POST',
    });
  }

  async getAppStats(id: string): Promise<ApiResponse<{
    total_authorizations: number;
    active_tokens: number;
    total_users: number;
    last_24h_tokens: number;
  }>> {
    return this.request(`/api/apps/${id}/stats`);
  }

  // OAuth endpoints
  async getOAuthAppInfo(clientId: string, redirectUri?: string): Promise<ApiResponse<{ app: { id: string; name: string; description: string } }>> {
    const params = new URLSearchParams({ client_id: clientId });
    if (redirectUri) params.set('redirect_uri', redirectUri);
    return this.request<{ app: { id: string; name: string; description: string } }>(`/api/oauth/app-info?${params.toString()}`);
  }

  async submitOAuthAuthorize(data: {
    client_id: string;
    redirect_uri: string;
    response_type: string;
    scope?: string;
    state?: string;
    code_challenge?: string;
    code_challenge_method?: string;
    consent: 'allow' | 'deny';
  }): Promise<ApiResponse<{ redirect_url: string; code?: string; state?: string }>> {
    return this.request<{ redirect_url: string; code?: string; state?: string }>('/api/oauth/authorize', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  // Admin endpoints
  async getAdminStats(): Promise<ApiResponse<AdminStats>> {
    return this.request<AdminStats>('/api/admin/stats');
  }

  async getAdminUsers(page = 1, limit = 20): Promise<ApiResponse<{ users: User[]; total: number; page: number; limit: number }>> {
    return this.request<{ users: User[]; total: number; page: number; limit: number }>(
      `/api/admin/users?page=${page}&limit=${limit}`
    );
  }

  async getAdminUser(id: string): Promise<ApiResponse<User>> {
    return this.request<User>(`/api/admin/users/${id}`);
  }

  async updateUserRole(id: string, role: UserRole): Promise<ApiResponse<void>> {
    return this.request<void>(`/api/admin/users/${id}/role`, {
      method: 'POST',
      body: JSON.stringify({ role }),
    });
  }

  async deleteUser(id: string): Promise<ApiResponse<void>> {
    return this.request<void>(`/api/admin/users/${id}/delete`, {
      method: 'POST',
    });
  }

  /* 管理员：搜索用户 */
  async searchUsers(query: string, filters: { role?: string; status?: string; email_verified?: string } = {}, page = 1, limit = 20): Promise<ApiResponse<{ users: User[]; total: number; page: number; limit: number }>> {
    const params = new URLSearchParams({ page: String(page), limit: String(limit) });
    if (query) params.set('q', query);
    if (filters.role) params.set('role', filters.role);
    if (filters.status) params.set('status', filters.status);
    if (filters.email_verified) params.set('email_verified', filters.email_verified);
    return this.request<{ users: User[]; total: number; page: number; limit: number }>(
      `/api/admin/users/search?${params.toString()}`
    );
  }

  /* 管理员：重置用户密码 */
  async resetUserPassword(id: string, newPassword: string): Promise<ApiResponse<{ message: string }>> {
    return this.request<{ message: string }>(`/api/admin/users/${id}/reset-password`, {
      method: 'POST',
      body: JSON.stringify({ new_password: newPassword }),
    });
  }

  /* 管理员：更新用户状态（停用/启用） */
  async updateUserStatus(id: string, status: 'active' | 'suspended' | 'pending'): Promise<ApiResponse<{ message: string }>> {
    return this.request<{ message: string }>(`/api/admin/users/${id}/status`, {
      method: 'POST',
      body: JSON.stringify({ status }),
    });
  }

  /* 管理员：批量更新用户状态 */
  async batchUpdateUserStatus(userIds: string[], status: string): Promise<ApiResponse<{ message: string; updated: number }>> {
    return this.request<{ message: string; updated: number }>('/api/admin/users/batch/status', {
      method: 'POST',
      body: JSON.stringify({ user_ids: userIds, status }),
    });
  }

  /* 管理员：批量删除用户 */
  async batchDeleteUsers(userIds: string[]): Promise<ApiResponse<{ message: string; deleted: number }>> {
    return this.request<{ message: string; deleted: number }>('/api/admin/users/batch/delete', {
      method: 'POST',
      body: JSON.stringify({ user_ids: userIds }),
    });
  }

  /* 管理员：创建用户 */
  async createUser(data: AdminCreateUserRequest): Promise<ApiResponse<{ message: string; user: User; generated_password?: string }>> {
    return this.request<{ message: string; user: User; generated_password?: string }>('/api/admin/users', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  /* 管理员：编辑用户 */
  async updateUser(id: string, data: AdminUpdateUserRequest): Promise<ApiResponse<{ message: string; user: User }>> {
    return this.request<{ message: string; user: User }>(`/api/admin/users/${id}/update`, {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  /* 管理员：发送密码重置邮件 */
  async sendResetEmail(id: string): Promise<ApiResponse<{ message: string; token?: string }>> {
    return this.request<{ message: string; token?: string }>(`/api/admin/users/${id}/send-reset-email`, {
      method: 'POST',
    });
  }

  /* 管理员：解锁用户账户（重置登录失败计数和锁定状态） */
  async unlockUser(id: string): Promise<ApiResponse<{ message: string }>> {
    return this.request<{ message: string }>(`/api/admin/users/${id}/unlock`, {
      method: 'POST',
    });
  }

  /* 管理员：获取用户授权列表 */
  async getAdminUserAuthorizations(id: string): Promise<ApiResponse<{ authorizations: UserAuthorization[] }>> {
    return this.request<{ authorizations: UserAuthorization[] }>(`/api/admin/users/${id}/authorizations`);
  }

  /* 管理员：导出用户 */
  getExportUsersUrl(format: 'json' | 'csv' = 'json'): string {
    return `${API_BASE_URL}/api/admin/users/export?format=${format}`;
  }

  /* 管理员：撤销应用所有授权 */
  async revokeAppAuthorizations(appId: string): Promise<ApiResponse<{ message: string; revoked: number }>> {
    return this.request<{ message: string; revoked: number }>(`/api/admin/apps/${appId}/authorizations/revoke`, {
      method: 'POST',
    });
  }

  async getAdminApps(page = 1, limit = 20): Promise<ApiResponse<{ apps: Application[]; total: number; page: number; limit: number }>> {
    return this.request<{ apps: Application[]; total: number; page: number; limit: number }>(
      `/api/admin/apps?page=${page}&limit=${limit}`
    );
  }

  // Config endpoints
  async getPublicConfig(): Promise<ApiResponse<Record<string, string>>> {
    return this.request<Record<string, string>>('/api/config');
  }

  async getAdminConfig(): Promise<ApiResponse<Record<string, string>>> {
    return this.request<Record<string, string>>('/api/admin/config');
  }

  async setAdminConfig(configs: Record<string, string>): Promise<ApiResponse<Record<string, string>>> {
    return this.request<Record<string, string>>('/api/admin/config', {
      method: 'POST',
      body: JSON.stringify(configs),
    });
  }

  // Login trend endpoint
  async getLoginTrend(days = 7): Promise<ApiResponse<{ trend: LoginTrend[] }>> {
    return this.request<{ trend: LoginTrend[] }>(`/api/admin/stats/login-trend?days=${days}`);
  }

  // Login logs endpoint
  async getLoginLogs(page = 1, limit = 20): Promise<ApiResponse<{ logs: LoginLog[]; total: number; page: number; limit: number }>> {
    return this.request<{ logs: LoginLog[]; total: number; page: number; limit: number }>(
      `/api/admin/login-logs?page=${page}&limit=${limit}`
    );
  }

  // Admin app stats endpoint
  async getAdminAppStats(id: string): Promise<ApiResponse<AppStats>> {
    return this.request<AppStats>(`/api/admin/apps/${id}/stats`);
  }

  // Admin app authorized users endpoint
  async getAdminAppUsers(id: string, page = 1, limit = 20): Promise<ApiResponse<{ authorizations: UserAuthorization[]; total: number; page: number; limit: number }>> {
    return this.request<{ authorizations: UserAuthorization[]; total: number; page: number; limit: number }>(
      `/api/admin/apps/${id}/users?page=${page}&limit=${limit}`
    );
  }

  // Get user's dashboard stats (aggregated from all apps)
  async getDashboardStats(): Promise<ApiResponse<{
    total_apps: number;
    total_authorizations: number;
    active_tokens: number;
    unique_users: number;
  }>> {
    // Get all user apps and aggregate their stats
    const appsResponse = await this.getApps();
    if (!appsResponse.success || !appsResponse.data) {
      return { success: false, error: { code: 'FETCH_ERROR', message: 'Failed to fetch apps' } };
    }

    let totalAuthorizations = 0;
    let activeTokens = 0;
    let uniqueUsers = 0;

    for (const app of appsResponse.data) {
      const statsResponse = await this.getAppStats(app.id);
      if (statsResponse.success && statsResponse.data) {
        totalAuthorizations += statsResponse.data.total_authorizations || 0;
        activeTokens += statsResponse.data.active_tokens || 0;
        uniqueUsers += statsResponse.data.total_users || 0;
      }
    }

    return {
      success: true,
      data: {
        total_apps: appsResponse.data.length,
        total_authorizations: totalAuthorizations,
        active_tokens: activeTokens,
        unique_users: uniqueUsers,
      },
    };
  }

  // Webhook endpoints
  async getWebhooks(appId: string): Promise<ApiResponse<Webhook[]>> {
    return this.request<Webhook[]>(`/api/apps/${appId}/webhooks`);
  }

  async createWebhook(appId: string, data: CreateWebhookRequest): Promise<ApiResponse<Webhook>> {
    return this.request<Webhook>(`/api/apps/${appId}/webhooks`, {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  async updateWebhook(appId: string, webhookId: string, data: UpdateWebhookRequest): Promise<ApiResponse<void>> {
    return this.request<void>(`/api/apps/${appId}/webhooks/${webhookId}`, {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  async deleteWebhook(appId: string, webhookId: string): Promise<ApiResponse<void>> {
    return this.request<void>(`/api/apps/${appId}/webhooks/${webhookId}/delete`, {
      method: 'POST',
    });
  }

  async getWebhookDeliveries(appId: string, webhookId: string, page = 1, limit = 20): Promise<ApiResponse<{ deliveries: WebhookDelivery[]; total: number }>> {
    return this.request<{ deliveries: WebhookDelivery[]; total: number }>(
      `/api/apps/${appId}/webhooks/${webhookId}/deliveries?page=${page}&limit=${limit}`
    );
  }

  async testWebhook(appId: string, webhookId: string): Promise<ApiResponse<void>> {
    return this.request<void>(`/api/apps/${appId}/webhooks/${webhookId}/test`, {
      method: 'POST',
    });
  }

  // System config management
  async getSystemConfig(): Promise<ApiResponse<SystemConfig>> {
    return this.request<SystemConfig>('/api/admin/system/config');
  }

  async updateSystemConfig(config: SystemConfigUpdate): Promise<ApiResponse<{ message: string }>> {
    return this.request<{ message: string }>('/api/admin/system/config', {
      method: 'POST',
      body: JSON.stringify(config),
    });
  }

  async regenerateJWTSecret(): Promise<ApiResponse<{ message: string }>> {
    return this.request<{ message: string }>('/api/admin/system/regenerate-jwt-secret', {
      method: 'POST',
    });
  }

  // Device Flow endpoints
  async getDeviceInfo(userCode: string): Promise<{ user_code: string; scope: string; app: { id: string; name: string; description: string }; expires_in: number }> {
    const response = await this.request<{ user_code: string; scope: string; app: { id: string; name: string; description: string }; expires_in: number }>(
      `/api/oauth/device/info?user_code=${encodeURIComponent(userCode)}`
    );
    if (!response.success || !response.data) {
      throw new Error(response.error?.message || 'Failed to get device info');
    }
    return response.data;
  }

  async authorizeDevice(userCode: string, consent: 'allow' | 'deny'): Promise<void> {
    const response = await this.request<{ message: string }>('/api/oauth/device/authorize', {
      method: 'POST',
      body: JSON.stringify({ user_code: userCode, consent }),
    });
    if (!response.success) {
      throw new Error(response.error?.message || 'Failed to authorize device');
    }
  }

  /* 联邦登录提供商 API */
  async getFederationProviders(): Promise<ApiResponse<{ providers: FederationProvider[] }>> {
    return this.request<{ providers: FederationProvider[] }>('/api/federation/providers');
  }

  /* 管理员：获取所有联邦提供商（含禁用的） */
  async getAdminFederationProviders(): Promise<ApiResponse<{ providers: FederationProvider[] }>> {
    return this.request<{ providers: FederationProvider[] }>('/api/admin/federation/providers');
  }

  /* 管理员：创建联邦提供商 */
  async createFederationProvider(data: CreateFederationProviderRequest): Promise<ApiResponse<FederationProvider>> {
    return this.request<FederationProvider>('/api/admin/federation/providers', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  /* 管理员：更新联邦提供商 */
  async updateFederationProvider(id: string, data: Partial<CreateFederationProviderRequest>): Promise<ApiResponse<FederationProvider>> {
    return this.request<FederationProvider>(`/api/admin/federation/providers/${id}`, {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  /* 管理员：删除联邦提供商 */
  async deleteFederationProvider(id: string): Promise<ApiResponse<void>> {
    return this.request<void>(`/api/admin/federation/providers/${id}/delete`, {
      method: 'POST',
    });
  }

  /* 获取联邦登录URL */
  getFederationLoginUrl(slug: string, returnTo?: string): string {
    const params = new URLSearchParams();
    if (returnTo) params.set('return_to', returnTo);
    return `${API_BASE_URL}/api/federation/login/${slug}?${params.toString()}`;
  }

  /* 获取社交登录提供商（/api/auth/social/providers） */
  async getSocialProviders(): Promise<ApiResponse<{ providers: SocialProvider[] }>> {
    return this.request<{ providers: SocialProvider[] }>('/api/auth/social/providers');
  }

  /* 获取社交登录URL */
  getSocialLoginUrl(provider: string, returnTo?: string): string {
    const params = new URLSearchParams();
    if (returnTo) params.set('return_to', returnTo);
    return `${API_BASE_URL}/api/auth/social/${provider}?${params.toString()}`;
  }

  /* 获取已关联的社交账号 */
  async getLinkedSocialAccounts(): Promise<ApiResponse<{ accounts: Array<{ provider: string; external_id: string; external_email: string; linked_at: string }> }>> {
    return this.request<{ accounts: Array<{ provider: string; external_id: string; external_email: string; linked_at: string }> }>('/api/user/social/linked');
  }

  /* 关联社交账号 */
  async linkSocialAccount(provider: string, data: { code: string; redirect_uri: string }): Promise<ApiResponse<{ message: string }>> {
    return this.request<{ message: string }>(`/api/user/social/${provider}/link`, {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  /* 解除社交账号关联 */
  async unlinkSocialAccount(provider: string): Promise<ApiResponse<{ message: string }>> {
    return this.request<{ message: string }>(`/api/user/social/${provider}/unlink`, {
      method: 'POST',
    });
  }

  /* SSE 事件流 URL（使用 Cookie 鉴权，不再通过查询字符串传递 token） */
  getEventStreamUrl(appId?: string): string {
    if (appId) {
      return `${API_BASE_URL}/api/events/app?app_id=${encodeURIComponent(appId)}`;
    }
    return `${API_BASE_URL}/api/events/stream`;
  }

  /* 创建 SSE 连接（withCredentials 确保携带 Cookie） */
  createEventSource(appId?: string): EventSource | null {
    if (typeof window === 'undefined') return null;
    const url = this.getEventStreamUrl(appId);
    const eventSource = new EventSource(url, { withCredentials: true });
    return eventSource;
  }
}

export const api = new ApiClient();

// Auth event type
export interface AuthEvent {
  type: 'user_registered' | 'user_login' | 'oauth_authorized' | 'oauth_revoked';
  app_id: string;
  app_name: string;
  user_id: string;
  username: string;
  email?: string;
  scope?: string;
  timestamp: string;
}
