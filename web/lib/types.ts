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

export type UserStatus = 'active' | 'disabled' | 'suspended' | 'pending';

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
  failed_logins?: number;
  locked_until?: string;
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
  id_token?: string;
  token_type: string;
  expires_in: number;
}

export interface LoginRequest {
  email: string;
  password: string;
}

export interface LDAPLoginRequest {
  provider_slug: string;
  identifier: string;
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
  access_token: string;
  refresh_token: string;
  id_token?: string;
  token_type: string;
  expires_in: number;
}

// Application types
export interface Application {
  id: string;
  client_id: string;
  client_secret?: string;
  name: string;
  description: string;
  redirect_uris: string[];
  post_logout_redirect_uris?: string[];
  scopes: string[];
  allowed_scopes?: string[];
  grant_types: string[];
  issued_token_types?: string[];
  response_types_supported?: string[];
  app_type?: string;
  token_endpoint_auth_method?: string;
  created_at: string;
  updated_at?: string;
}

export interface CreateAppRequest {
  name: string;
  description?: string;
  redirect_uris: string[];
  post_logout_redirect_uris?: string[];
  scopes?: string[];
  allowed_scopes?: string[];
  grant_types?: string[];
  app_type?: string;
  token_endpoint_auth_method?: string;
}

export interface UpdateAppRequest {
  name?: string;
  description?: string;
  redirect_uris?: string[];
  post_logout_redirect_uris?: string[];
  scopes?: string[];
  allowed_scopes?: string[];
  grant_types?: string[];
  app_type?: string;
  token_endpoint_auth_method?: string;
}

export interface SAMLIdPServiceProviderConfig {
  id?: string;
  app_id: string;
  sp_entity_id?: string;
  acs_url?: string;
  certificate_configured: boolean;
  name_id_format: string;
  attribute_mappings?: Record<string, string>;
  enabled: boolean;
  idp_entity_id: string;
  idp_metadata_url: string;
  idp_sso_url: string;
}

export interface SAMLIdPServiceProviderUpdateRequest {
  sp_entity_id: string;
  acs_url: string;
  certificate_pem?: string;
  name_id_format?: string;
  attribute_mappings?: Record<string, string>;
  enabled: boolean;
}

// OAuth types
export interface AuthorizeRequest {
  response_type: string;
  client_id: string;
  redirect_uri: string;
  scope?: string;
  state?: string;
  nonce?: string;
  max_age?: string;
  prompt?: string;
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
    retryAfter?: number;
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
  login_type: 'direct' | 'oauth' | 'sdk' | 'ldap' | 'saml';
  ip_address: string;
  user_agent: string;
  success: boolean;
  failure_reason?: string;
  email?: string;
  created_at: string;
  user?: {
    id: string;
    email: string;
    username: string;
  };
  app?: {
    id: string;
    name: string;
  };
}

export interface RiskEvent {
  id: string;
  user_id?: string;
  risk_score: number;
  decision: 'pass' | 'challenge' | 'mfa' | 'block';
  ip_address?: string;
  user_agent?: string;
  reason?: string;
  created_at: string;
  user?: {
    id: string;
    email: string;
    username: string;
    avatar?: string;
    status: string;
  };
}

export interface RiskEventsResponse {
  events: RiskEvent[];
  total: number;
  page: number;
  limit: number;
  decision: string;
  reason: string;
  reasons: string[];
}

export interface AppStats {
  total_authorizations: number;
  unique_users: number;
  active_authorizations: number;
  revoked_authorizations: number;
  last_24h_authorizations: number;
  last_7d_authorizations: number;
}

export interface AuthUserSummary {
  id: string;
  email: string;
  username: string;
  display_name: string;
  avatar?: string;
  role: string;
  status: string;
  email_verified: boolean;
  last_login_at?: string;
}

export interface AuthAppSummary {
  id: string;
  client_id: string;
  name: string;
  description?: string;
  scopes?: string[];
  grant_types?: string[];
}

export interface UserAuthorization {
  id: string;
  user_id: string;
  app_id: string;
  scope: string;
  scopes?: string[];
  grant_type?: string;
  authorized_at: string;
  expires_at?: string;
  revoked: boolean;
  revoked_at?: string;
  is_active?: boolean;
  created_at?: string;
  user?: AuthUserSummary | User;
  app?: AuthAppSummary | Application;
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

export interface EnterpriseProviderPublic {
  slug: string;
  name: string;
  description?: string;
  icon_url?: string;
  button_text?: string;
}

export interface EnterpriseProvidersResponse {
  ldap_providers: EnterpriseProviderPublic[];
  saml_providers: EnterpriseProviderPublic[];
}

export interface LDAPProviderConfig {
  id: string;
  name: string;
  slug: string;
  description?: string;
  ldap_url: string;
  use_starttls: boolean;
  insecure_skip_verify: boolean;
  bind_dn?: string;
  bind_password_configured: boolean;
  base_dn: string;
  user_filter?: string;
  external_id_attr?: string;
  principal_attr?: string;
  email_attr?: string;
  username_attr?: string;
  employee_id_attr?: string;
  display_name_attr?: string;
  given_name_attr?: string;
  family_name_attr?: string;
  group_attr?: string;
  role_mappings?: Record<string, string>;
  default_role: UserRole;
  enabled: boolean;
  auto_create_user: boolean;
  trust_email_verified: boolean;
  sync_profile: boolean;
  sync_enabled: boolean;
  sync_interval_min: number;
  sync_page_size: number;
  last_sync_at?: string;
  last_sync_status?: string;
  icon_url?: string;
  button_text?: string;
  created_at: string;
  updated_at: string;
}

export interface LDAPProviderUpdateRequest {
  name?: string;
  slug?: string;
  description?: string;
  ldap_url?: string;
  use_starttls?: boolean;
  insecure_skip_verify?: boolean;
  bind_dn?: string;
  bind_password?: string;
  base_dn?: string;
  user_filter?: string;
  external_id_attr?: string;
  principal_attr?: string;
  email_attr?: string;
  username_attr?: string;
  employee_id_attr?: string;
  display_name_attr?: string;
  given_name_attr?: string;
  family_name_attr?: string;
  group_attr?: string;
  role_mappings?: Record<string, string>;
  default_role?: UserRole;
  enabled?: boolean;
  auto_create_user?: boolean;
  trust_email_verified?: boolean;
  sync_profile?: boolean;
  sync_enabled?: boolean;
  sync_interval_min?: number;
  sync_page_size?: number;
  icon_url?: string;
  button_text?: string;
}

export interface SAMLProviderConfig {
  id: string;
  name: string;
  slug: string;
  description?: string;
  metadata_url?: string;
  metadata_xml_configured: boolean;
  sp_entity_id?: string;
  certificate_configured: boolean;
  private_key_configured: boolean;
  sign_requests: boolean;
  allow_idp_initiated: boolean;
  default_redirect_path?: string;
  name_id_format?: string;
  email_attribute?: string;
  username_attribute?: string;
  employee_id_attribute?: string;
  display_name_attribute?: string;
  given_name_attribute?: string;
  family_name_attribute?: string;
  group_attribute?: string;
  role_mappings?: Record<string, string>;
  default_role: UserRole;
  enabled: boolean;
  auto_create_user: boolean;
  trust_email_verified: boolean;
  sync_profile: boolean;
  metadata_fetched_at?: string;
  icon_url?: string;
  button_text?: string;
  created_at: string;
  updated_at: string;
}

export interface SAMLProviderUpdateRequest {
  name?: string;
  slug?: string;
  description?: string;
  metadata_url?: string;
  metadata_xml?: string;
  sp_entity_id?: string;
  certificate_pem?: string;
  private_key_pem?: string;
  sign_requests?: boolean;
  allow_idp_initiated?: boolean;
  default_redirect_path?: string;
  name_id_format?: string;
  email_attribute?: string;
  username_attribute?: string;
  employee_id_attribute?: string;
  display_name_attribute?: string;
  given_name_attribute?: string;
  family_name_attribute?: string;
  group_attribute?: string;
  role_mappings?: Record<string, string>;
  default_role?: UserRole;
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
    id_token_ttl_hours: number;
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
      client_secret_configured: boolean;
    };
    google: {
      enabled: boolean;
      client_id: string;
      client_secret_configured: boolean;
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
