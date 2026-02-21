// User types
export type UserRole = 'admin' | 'user';

export interface AddressInfo {
  formatted?: string;
  street_address?: string;
  locality?: string;
  region?: string;
  postal_code?: string;
  country?: string;
}

export type UserStatus = 'active' | 'suspended' | 'pending';

export interface User {
  id: string;
  email: string;
  username: string;
  role: UserRole;
  status?: UserStatus;
  avatar?: string;
  email_verified: boolean;
  profile_completed?: boolean;
  created_at: string;
  updated_at?: string;
  // OIDC Standard Claims
  given_name?: string;
  family_name?: string;
  nickname?: string;
  gender?: string;
  birthdate?: string;
  phone_number?: string;
  phone_number_verified?: boolean;
  address?: AddressInfo;
  locale?: string;
  zoneinfo?: string;
  website?: string;
  bio?: string;
  social_accounts?: Record<string, string>;
  // Extended Fields
  company?: string;
  department?: string;
  job_title?: string;
  employee_id?: string;
  external_id?: string;
  external_source?: string;
  last_login_at?: string;
}

export interface UpdateProfileRequest {
  username?: string;
  avatar?: string;
  given_name?: string;
  family_name?: string;
  nickname?: string;
  gender?: string;
  birthdate?: string;
  phone_number?: string;
  address?: AddressInfo;
  locale?: string;
  zoneinfo?: string;
  website?: string;
  bio?: string;
  social_accounts?: Record<string, string>;
  company?: string;
  department?: string;
  job_title?: string;
}

export interface AdminCreateUserRequest {
  email: string;
  username: string;
  password?: string;
  role?: string;
  status?: string;
  send_welcome?: boolean;
}

export interface AdminUpdateUserRequest {
  email?: string;
  username?: string;
  role?: string;
  status?: string;
  nickname?: string;
  given_name?: string;
  family_name?: string;
  phone_number?: string;
  gender?: string;
  company?: string;
  department?: string;
  job_title?: string;
  email_verified?: boolean;
}

// Auth types
export interface AuthTokens {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
}

export interface LoginRequest {
  email: string;
  password: string;
}

export interface RegisterRequest {
  email: string;
  username: string;
  password: string;
}

export interface LoginResponse {
  user: User;
  tokens: AuthTokens;
}

// Application types
export interface Application {
  id: string;
  client_id: string;
  client_secret?: string;
  name: string;
  description: string;
  redirect_uris: string[];
  scopes: string[];
  grant_types: string[];
  created_at: string;
}

export interface CreateAppRequest {
  name: string;
  description?: string;
  redirect_uris: string[];
  scopes?: string[];
  grant_types?: string[];
}

export interface UpdateAppRequest {
  name?: string;
  description?: string;
  redirect_uris?: string[];
  scopes?: string[];
  grant_types?: string[];
}

// OAuth types
export interface AuthorizeRequest {
  response_type: string;
  client_id: string;
  redirect_uri: string;
  scope?: string;
  state?: string;
  code_challenge?: string;
  code_challenge_method?: string;
}

export interface AuthorizeResponse {
  app: {
    name: string;
    description: string;
  };
  scope: string;
  redirect_uri: string;
  state: string;
}

// API Response types
export interface ApiResponse<T> {
  success: boolean;
  data?: T;
  error?: {
    code: string;
    message: string;
  };
}

// Admin types
export interface LoginStats {
  total_logins: number;
  successful_logins: number;
  failed_logins: number;
  unique_users: number;
  last_24h_logins: number;
  last_7d_logins: number;
  direct_logins: number;
  oauth_logins: number;
  sdk_logins: number;
}

export interface AdminStats {
  users: number;
  applications: number;
  active_users: number;
  today_logins: number;
  login_stats?: LoginStats;
}

export interface LoginTrend {
  date: string;
  total_count: number;
  success: number;
  failed: number;
}

export interface LoginLog {
  id: string;
  user_id?: string;
  app_id?: string;
  login_type: 'direct' | 'oauth' | 'sdk';
  ip_address: string;
  user_agent: string;
  success: boolean;
  failure_reason?: string;
  email?: string;
  created_at: string;
  user?: User;
  app?: Application;
}

export interface AppStats {
  total_authorizations: number;
  unique_users: number;
  active_authorizations: number;
  revoked_authorizations: number;
  last_24h_authorizations: number;
  last_7d_authorizations: number;
}

export interface UserAuthorization {
  id: string;
  user_id: string;
  app_id: string;
  scope: string;
  grant_type?: string;
  authorized_at: string;
  expires_at?: string;
  revoked: boolean;
  revoked_at?: string;
  created_at: string;
  user?: User;
  app?: Application;
}

export interface DashboardStats {
  total_apps: number;
  active_tokens: number;
  authorized_users: number;
  api_calls_24h: number;
}

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  limit: number;
}

// Webhook types
export interface Webhook {
  id: string;
  app_id: string;
  url: string;
  events: string;
  active: boolean;
  created_at: string;
  updated_at: string;
}

export interface WebhookDelivery {
  id: string;
  webhook_id: string;
  event: string;
  status_code: number;
  delivered: boolean;
  error?: string;
  created_at: string;
}

export interface CreateWebhookRequest {
  url: string;
  secret?: string;
  events: string;
}

export interface UpdateWebhookRequest {
  url: string;
  secret?: string;
  events: string;
  active: boolean;
}

// Federation Provider types
export interface FederationProvider {
  id: string;
  name: string;
  slug: string;
  description?: string;
  auth_url: string;
  token_url: string;
  userinfo_url: string;
  client_id: string;
  scopes?: string;
  enabled: boolean;
  auto_create_user: boolean;
  trust_email_verified: boolean;
  sync_profile: boolean;
  icon_url?: string;
  button_text?: string;
  created_at: string;
  updated_at: string;
}

export interface CreateFederationProviderRequest {
  name: string;
  slug: string;
  description?: string;
  auth_url: string;
  token_url: string;
  userinfo_url: string;
  client_id: string;
  client_secret: string;
  scopes?: string;
  enabled?: boolean;
  auto_create_user?: boolean;
  trust_email_verified?: boolean;
  sync_profile?: boolean;
  icon_url?: string;
  button_text?: string;
}

export interface SocialProvider {
  slug: string;
  name: string;
  description?: string;
  icon_url?: string;
  button_text?: string;
}

// System Config types
export interface SystemConfig {
  server: {
    host: string;
    port: number;
    mode: string;
    allow_registration: boolean;
  };
  database: {
    driver: string;
    dsn: string;
    max_open_conns: number;
    max_idle_conns: number;
    conn_max_lifetime_min: number;
    conn_max_idle_time_min: number;
  };
  jwt: {
    secret_configured: boolean;
    access_token_ttl_minutes: number;
    refresh_token_ttl_days: number;
    issuer: string;
  };
  oauth: {
    auth_code_ttl_minutes: number;
    access_token_ttl_hours: number;
    refresh_token_ttl_days: number;
    frontend_url: string;
  };
  email: {
    host: string;
    port: number;
    username: string;
    password_set: boolean;
    from: string;
    from_name: string;
    use_tls: boolean;
  };
  social: {
    enabled: boolean;
    github: {
      enabled: boolean;
      client_id: string;
      client_secret: string;
    };
    google: {
      enabled: boolean;
      client_id: string;
      client_secret: string;
    };
  };
}

export interface SystemConfigUpdate {
  server?: {
    host?: string;
    port?: number;
    mode?: string;
    allow_registration?: boolean;
  };
  jwt?: {
    secret?: string;
    access_token_ttl_minutes?: number;
    refresh_token_ttl_days?: number;
    issuer?: string;
  };
  oauth?: {
    auth_code_ttl_minutes?: number;
    access_token_ttl_hours?: number;
    refresh_token_ttl_days?: number;
    frontend_url?: string;
  };
  email?: {
    host?: string;
    port?: number;
    username?: string;
    password?: string;
    from?: string;
    from_name?: string;
    use_tls?: boolean;
  };
  social?: {
    enabled?: boolean;
    github?: {
      enabled?: boolean;
      client_id?: string;
      client_secret?: string;
    };
    google?: {
      enabled?: boolean;
      client_id?: string;
      client_secret?: string;
    };
  };
}
