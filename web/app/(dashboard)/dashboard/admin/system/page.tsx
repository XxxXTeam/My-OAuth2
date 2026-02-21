'use client';

import { useState, useEffect, useCallback } from 'react';
import { useI18n } from '@/lib/i18n';
import { api } from '@/lib/api';
import type { SystemConfig, SystemConfigUpdate } from '@/lib/types';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { 
  Settings, 
  Server, 
  Key, 
  Mail, 
  Users, 
  Loader2, 
  Save, 
  RefreshCw,
  AlertTriangle,
  CheckCircle,
  Github,
  Shield
} from 'lucide-react';

export default function SystemConfigPage() {
  const { t } = useI18n();
  const [config, setConfig] = useState<SystemConfig | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  
  // Form states
  const [jwtForm, setJwtForm] = useState({
    access_token_ttl_minutes: 15,
    refresh_token_ttl_days: 7,
    issuer: '',
    new_secret: '',
  });
  
  const [oauthForm, setOauthForm] = useState({
    auth_code_ttl_minutes: 10,
    access_token_ttl_hours: 1,
    refresh_token_ttl_days: 30,
    frontend_url: '',
  });
  
  const [emailForm, setEmailForm] = useState({
    host: '',
    port: 587,
    username: '',
    password: '',
    from: '',
    from_name: '',
    use_tls: true,
  });
  
  const [socialForm, setSocialForm] = useState({
    enabled: false,
    github: { enabled: false, client_id: '', client_secret: '' },
    google: { enabled: false, client_id: '', client_secret: '' },
  });

  const [generalForm, setGeneralForm] = useState({
    allow_registration: true,
    frontend_url: '',
    server_url: '',
    site_name: '',
  });

  const [savingGeneral, setSavingGeneral] = useState(false);

  const loadConfig = useCallback(async () => {
    setLoading(true);
    try {
      const response = await api.getSystemConfig();
      if (response.success && response.data) {
        setConfig(response.data);
        // Initialize forms with loaded data
        setJwtForm({
          access_token_ttl_minutes: response.data.jwt.access_token_ttl_minutes,
          refresh_token_ttl_days: response.data.jwt.refresh_token_ttl_days,
          issuer: response.data.jwt.issuer,
          new_secret: '',
        });
        setOauthForm({
          auth_code_ttl_minutes: response.data.oauth.auth_code_ttl_minutes,
          access_token_ttl_hours: response.data.oauth.access_token_ttl_hours,
          refresh_token_ttl_days: response.data.oauth.refresh_token_ttl_days,
          frontend_url: response.data.oauth.frontend_url || '',
        });
        setEmailForm({
          host: response.data.email.host || '',
          port: response.data.email.port,
          username: response.data.email.username || '',
          password: '',
          from: response.data.email.from || '',
          from_name: response.data.email.from_name || '',
          use_tls: response.data.email.use_tls,
        });
        setSocialForm({
          enabled: response.data.social.enabled,
          github: {
            enabled: response.data.social.github.enabled,
            client_id: response.data.social.github.client_id || '',
            client_secret: '',
          },
          google: {
            enabled: response.data.social.google.enabled,
            client_id: response.data.social.google.client_id || '',
            client_secret: '',
          },
        });
        const sysData = response.data;
        setGeneralForm(prev => ({
          ...prev,
          allow_registration: sysData.server.allow_registration,
        }));
      }
    } catch {
      setMessage({ type: 'error', text: t('admin.system.loadFailed') });
    }
    setLoading(false);
  }, [t]);

  /* 从数据库加载站点配置（frontend_url、server_url、site_name） */
  const loadSiteConfig = useCallback(async () => {
    const response = await api.getAdminConfig();
    if (response.success && response.data) {
      const data = response.data;
      setGeneralForm(prev => ({
        ...prev,
        frontend_url: data.frontend_url || '',
        server_url: data.server_url || '',
        site_name: data.site_name || '',
      }));
    }
  }, []);

  useEffect(() => {
    loadConfig();
    loadSiteConfig();
  }, [loadConfig, loadSiteConfig]);

  const handleSave = async (section: string, data: SystemConfigUpdate) => {
    setSaving(true);
    setMessage(null);
    try {
      const response = await api.updateSystemConfig(data);
      if (response.success) {
        setMessage({ type: 'success', text: t('admin.system.saveSuccess').replace('{section}', section) });
        loadConfig();
      } else {
        const errorMsg = typeof response.error === 'string' ? response.error : response.error?.message || t('admin.system.saveFailed');
        setMessage({ type: 'error', text: errorMsg });
      }
    } catch {
      setMessage({ type: 'error', text: t('admin.system.saveFailed') });
    }
    setSaving(false);
  };

  const handleRegenerateJWT = async () => {
    if (!confirm(t('admin.system.regenerateConfirm'))) {
      return;
    }
    setSaving(true);
    try {
      const response = await api.regenerateJWTSecret();
      if (response.success) {
        setMessage({ type: 'success', text: t('admin.system.regenerateSuccess') });
        loadConfig();
      } else {
        const errorMsg = typeof response.error === 'string' ? response.error : response.error?.message || t('admin.system.operationFailed');
        setMessage({ type: 'error', text: errorMsg });
      }
    } catch {
      setMessage({ type: 'error', text: t('admin.system.regenerateFailed') });
    }
    setSaving(false);
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h1 className="text-xl sm:text-2xl font-bold flex items-center gap-2">
            <Settings className="h-5 w-5 sm:h-6 sm:w-6" />
            {t('admin.system.title')}
          </h1>
          <p className="text-muted-foreground mt-1 text-sm">{t('admin.system.description')}</p>
        </div>
        <Button variant="outline" onClick={loadConfig} disabled={loading} className="w-full sm:w-auto">
          <RefreshCw className={`h-4 w-4 mr-2 ${loading ? 'animate-spin' : ''}`} />
          {t('admin.system.refresh')}
        </Button>
      </div>

      {message && (
        <Alert variant={message.type === 'error' ? 'destructive' : 'default'}>
          {message.type === 'error' ? (
            <AlertTriangle className="h-4 w-4" />
          ) : (
            <CheckCircle className="h-4 w-4" />
          )}
          <AlertDescription>{message.text}</AlertDescription>
        </Alert>
      )}

      <Tabs defaultValue="jwt" className="space-y-4">
        <TabsList className="flex w-full overflow-x-auto">
          <TabsTrigger value="general" className="flex items-center gap-1.5 flex-1 min-w-0">
            <Shield className="h-4 w-4 shrink-0 hidden sm:block" />
            {t('admin.system.general')}
          </TabsTrigger>
          <TabsTrigger value="jwt" className="flex items-center gap-1.5 flex-1 min-w-0">
            <Key className="h-4 w-4 shrink-0 hidden sm:block" />
            JWT
          </TabsTrigger>
          <TabsTrigger value="oauth" className="flex items-center gap-1.5 flex-1 min-w-0">
            <Server className="h-4 w-4 shrink-0 hidden sm:block" />
            OAuth
          </TabsTrigger>
          <TabsTrigger value="email" className="flex items-center gap-1.5 flex-1 min-w-0">
            <Mail className="h-4 w-4 shrink-0 hidden sm:block" />
            {t('admin.system.email')}
          </TabsTrigger>
          <TabsTrigger value="social" className="flex items-center gap-1.5 flex-1 min-w-0">
            <Users className="h-4 w-4 shrink-0 hidden sm:block" />
            {t('admin.system.social')}
          </TabsTrigger>
        </TabsList>

        {/* General Configuration */}
        <TabsContent value="general">
          <div className="space-y-4">
            {/* 站点配置 - 存储在数据库 */}
            <Card>
              <CardHeader>
                <CardTitle>{t('admin.system.siteConfig')}</CardTitle>
                <CardDescription>{t('admin.system.siteConfigDesc')}</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="site_name">{t('admin.system.siteName')}</Label>
                  <Input
                    id="site_name"
                    placeholder="My OAuth2"
                    value={generalForm.site_name}
                    onChange={(e) => setGeneralForm({ ...generalForm, site_name: e.target.value })}
                  />
                  <p className="text-xs text-muted-foreground">{t('admin.system.siteNameHint')}</p>
                </div>
                <div className="grid gap-4 sm:grid-cols-2">
                  <div className="space-y-2">
                    <Label htmlFor="frontend_url">{t('admin.system.frontendUrl')}</Label>
                    <Input
                      id="frontend_url"
                      placeholder="http://localhost:3000"
                      value={generalForm.frontend_url}
                      onChange={(e) => setGeneralForm({ ...generalForm, frontend_url: e.target.value })}
                    />
                    <p className="text-xs text-muted-foreground">{t('admin.system.frontendUrlHint')}</p>
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="server_url">{t('admin.system.serverUrl')}</Label>
                    <Input
                      id="server_url"
                      placeholder="http://localhost:8080"
                      value={generalForm.server_url}
                      onChange={(e) => setGeneralForm({ ...generalForm, server_url: e.target.value })}
                    />
                    <p className="text-xs text-muted-foreground">{t('admin.system.serverUrlHint')}</p>
                  </div>
                </div>
                <Button
                  onClick={async () => {
                    setSavingGeneral(true);
                    setMessage(null);
                    const res = await api.setAdminConfig({
                      frontend_url: generalForm.frontend_url,
                      server_url: generalForm.server_url,
                      site_name: generalForm.site_name,
                    });
                    if (res.success) {
                      setMessage({ type: 'success', text: t('admin.system.siteConfigSaved') });
                    } else {
                      setMessage({ type: 'error', text: res.error?.message || t('admin.system.saveFailed') });
                    }
                    setSavingGeneral(false);
                  }}
                  disabled={savingGeneral}
                >
                  {savingGeneral ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <Save className="h-4 w-4 mr-2" />}
                  {t('admin.system.saveSiteConfig')}
                </Button>
              </CardContent>
            </Card>

            {/* 功能开关 - 存储在运行时配置 */}
            <Card>
              <CardHeader>
                <CardTitle>{t('admin.system.featureToggle')}</CardTitle>
                <CardDescription>{t('admin.system.featureToggleDesc')}</CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                <div className="flex items-center justify-between p-4 rounded-lg border">
                  <div>
                    <p className="font-medium">{t('admin.system.allowRegistration')}</p>
                    <p className="text-sm text-muted-foreground">{t('admin.system.allowRegistrationDesc')}</p>
                  </div>
                  <Switch
                    checked={generalForm.allow_registration}
                    onCheckedChange={(checked) => setGeneralForm({ ...generalForm, allow_registration: checked })}
                  />
                </div>
                <Button
                  onClick={() => handleSave(t('admin.system.featureToggle'), {
                    server: {
                      allow_registration: generalForm.allow_registration,
                    }
                  })}
                  disabled={saving}
                >
                  {saving ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <Save className="h-4 w-4 mr-2" />}
                  {t('admin.system.saveFeatureSettings')}
                </Button>
              </CardContent>
            </Card>

            {/* 服务器信息（只读） */}
            <Card>
              <CardHeader>
                <CardTitle>{t('admin.system.serverInfo')}</CardTitle>
                <CardDescription>{t('admin.system.serverInfoDesc')}</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="grid gap-3 text-sm">
                  <div className="flex justify-between p-2 rounded bg-muted/50"><span className="text-muted-foreground">{t('admin.system.listenAddress')}</span><code>{config?.server.host}:{config?.server.port}</code></div>
                  <div className="flex justify-between p-2 rounded bg-muted/50"><span className="text-muted-foreground">{t('admin.system.runMode')}</span><code>{config?.server.mode}</code></div>
                  <div className="flex justify-between p-2 rounded bg-muted/50"><span className="text-muted-foreground">{t('admin.system.dbDriver')}</span><code>{config?.database.driver}</code></div>
                </div>
              </CardContent>
            </Card>

            {/* 数据库连接池（只读） */}
            <Card>
              <CardHeader>
                <CardTitle>{t('admin.system.dbPool')}</CardTitle>
                <CardDescription>{t('admin.system.dbPoolDesc')}</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="grid gap-3 text-sm">
                  <div className="flex justify-between p-2 rounded bg-muted/50">
                    <span className="text-muted-foreground">{t('admin.system.maxOpenConns')}</span>
                    <code>{config?.database.max_open_conns || t('admin.system.default')}</code>
                  </div>
                  <div className="flex justify-between p-2 rounded bg-muted/50">
                    <span className="text-muted-foreground">{t('admin.system.maxIdleConns')}</span>
                    <code>{config?.database.max_idle_conns || t('admin.system.default')}</code>
                  </div>
                  <div className="flex justify-between p-2 rounded bg-muted/50">
                    <span className="text-muted-foreground">{t('admin.system.connMaxLifetime')}</span>
                    <code>{config?.database.conn_max_lifetime_min ? `${config.database.conn_max_lifetime_min} ${t('admin.system.minutes')}` : t('admin.system.default')}</code>
                  </div>
                  <div className="flex justify-between p-2 rounded bg-muted/50">
                    <span className="text-muted-foreground">{t('admin.system.connMaxIdleTime')}</span>
                    <code>{config?.database.conn_max_idle_time_min ? `${config.database.conn_max_idle_time_min} ${t('admin.system.minutes')}` : t('admin.system.default')}</code>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* JWT Configuration */}
        <TabsContent value="jwt">
          <Card>
            <CardHeader>
              <CardTitle>{t('admin.system.jwtConfig')}</CardTitle>
              <CardDescription>{t('admin.system.jwtConfigDesc')}</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex items-center justify-between p-4 bg-muted rounded-lg">
                <div>
                  <p className="font-medium">{t('admin.system.jwtSecretStatus')}</p>
                  <p className="text-sm text-muted-foreground">
                    {config?.jwt.secret_configured ? t('admin.system.jwtSecretConfigured') : t('admin.system.jwtSecretDefault')}
                  </p>
                </div>
                <Button variant="outline" onClick={handleRegenerateJWT} disabled={saving}>
                  <RefreshCw className="h-4 w-4 mr-2" />
                  {t('admin.system.regenerateSecret')}
                </Button>
              </div>
              
              <div className="grid gap-4 md:grid-cols-2">
                <div className="space-y-2">
                  <Label>{t('admin.system.accessTokenTTL')}</Label>
                  <Input
                    type="number"
                    value={jwtForm.access_token_ttl_minutes}
                    onChange={(e) => setJwtForm({ ...jwtForm, access_token_ttl_minutes: parseInt(e.target.value) || 15 })}
                  />
                </div>
                <div className="space-y-2">
                  <Label>{t('admin.system.refreshTokenTTLDays')}</Label>
                  <Input
                    type="number"
                    value={jwtForm.refresh_token_ttl_days}
                    onChange={(e) => setJwtForm({ ...jwtForm, refresh_token_ttl_days: parseInt(e.target.value) || 7 })}
                  />
                </div>
                <div className="space-y-2 md:col-span-2">
                  <Label>Issuer</Label>
                  <Input
                    value={jwtForm.issuer}
                    onChange={(e) => setJwtForm({ ...jwtForm, issuer: e.target.value })}
                    placeholder="my-oauth2"
                  />
                </div>
              </div>
              
              <Button
                onClick={() => handleSave('JWT', {
                  jwt: {
                    access_token_ttl_minutes: jwtForm.access_token_ttl_minutes,
                    refresh_token_ttl_days: jwtForm.refresh_token_ttl_days,
                    issuer: jwtForm.issuer,
                  }
                })}
                disabled={saving}
              >
                {saving ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <Save className="h-4 w-4 mr-2" />}
                {t('admin.system.saveJwt')}
              </Button>
            </CardContent>
          </Card>
        </TabsContent>

        {/* OAuth Configuration */}
        <TabsContent value="oauth">
          <Card>
            <CardHeader>
              <CardTitle>{t('admin.system.oauthConfig')}</CardTitle>
              <CardDescription>{t('admin.system.oauthConfigDesc')}</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid gap-4 md:grid-cols-2">
                <div className="space-y-2">
                  <Label>{t('admin.system.authCodeTTL')}</Label>
                  <Input
                    type="number"
                    value={oauthForm.auth_code_ttl_minutes}
                    onChange={(e) => setOauthForm({ ...oauthForm, auth_code_ttl_minutes: parseInt(e.target.value) || 10 })}
                  />
                </div>
                <div className="space-y-2">
                  <Label>{t('admin.system.oauthAccessTokenTTL')}</Label>
                  <Input
                    type="number"
                    value={oauthForm.access_token_ttl_hours}
                    onChange={(e) => setOauthForm({ ...oauthForm, access_token_ttl_hours: parseInt(e.target.value) || 1 })}
                  />
                </div>
                <div className="space-y-2">
                  <Label>{t('admin.system.oauthRefreshTokenTTL')}</Label>
                  <Input
                    type="number"
                    value={oauthForm.refresh_token_ttl_days}
                    onChange={(e) => setOauthForm({ ...oauthForm, refresh_token_ttl_days: parseInt(e.target.value) || 30 })}
                  />
                </div>
                <div className="space-y-2">
                  <Label>{t('admin.system.oauthFrontendUrl')}</Label>
                  <Input
                    value={oauthForm.frontend_url}
                    onChange={(e) => setOauthForm({ ...oauthForm, frontend_url: e.target.value })}
                    placeholder="http://localhost:3000"
                  />
                </div>
              </div>
              
              <Button
                onClick={() => handleSave('OAuth', { oauth: oauthForm })}
                disabled={saving}
              >
                {saving ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <Save className="h-4 w-4 mr-2" />}
                {t('admin.system.saveOauth')}
              </Button>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Email Configuration */}
        <TabsContent value="email">
          <Card>
            <CardHeader>
              <CardTitle>{t('admin.system.emailConfig')}</CardTitle>
              <CardDescription>{t('admin.system.emailConfigDesc')}</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid gap-4 md:grid-cols-2">
                <div className="space-y-2">
                  <Label>{t('admin.system.smtpServer')}</Label>
                  <Input
                    value={emailForm.host}
                    onChange={(e) => setEmailForm({ ...emailForm, host: e.target.value })}
                    placeholder="smtp.gmail.com"
                  />
                </div>
                <div className="space-y-2">
                  <Label>{t('admin.system.port')}</Label>
                  <Input
                    type="number"
                    value={emailForm.port}
                    onChange={(e) => setEmailForm({ ...emailForm, port: parseInt(e.target.value) || 587 })}
                  />
                </div>
                <div className="space-y-2">
                  <Label>{t('admin.system.username')}</Label>
                  <Input
                    value={emailForm.username}
                    onChange={(e) => setEmailForm({ ...emailForm, username: e.target.value })}
                    placeholder="your-email@gmail.com"
                  />
                </div>
                <div className="space-y-2">
                  <Label>{t('admin.system.password')} {config?.email.password_set && <span className="text-muted-foreground">({t('admin.system.passwordSet')})</span>}</Label>
                  <Input
                    type="password"
                    value={emailForm.password}
                    onChange={(e) => setEmailForm({ ...emailForm, password: e.target.value })}
                    placeholder={t('admin.system.passwordKeepEmpty')}
                  />
                </div>
                <div className="space-y-2">
                  <Label>{t('admin.system.senderEmail')}</Label>
                  <Input
                    value={emailForm.from}
                    onChange={(e) => setEmailForm({ ...emailForm, from: e.target.value })}
                    placeholder="noreply@example.com"
                  />
                </div>
                <div className="space-y-2">
                  <Label>{t('admin.system.senderName')}</Label>
                  <Input
                    value={emailForm.from_name}
                    onChange={(e) => setEmailForm({ ...emailForm, from_name: e.target.value })}
                    placeholder="OAuth2 Service"
                  />
                </div>
              </div>
              
              <div className="flex items-center space-x-2">
                <Switch
                  checked={emailForm.use_tls}
                  onCheckedChange={(checked) => setEmailForm({ ...emailForm, use_tls: checked })}
                />
                <Label>{t('admin.system.enableTLS')}</Label>
              </div>
              
              <Button
                onClick={() => handleSave(t('admin.system.email'), {
                  email: {
                    host: emailForm.host,
                    port: emailForm.port,
                    username: emailForm.username,
                    password: emailForm.password || undefined,
                    from: emailForm.from,
                    from_name: emailForm.from_name,
                    use_tls: emailForm.use_tls,
                  }
                })}
                disabled={saving}
              >
                {saving ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <Save className="h-4 w-4 mr-2" />}
                {t('admin.system.saveEmail')}
              </Button>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Social Login Configuration */}
        <TabsContent value="social">
          <Card>
            <CardHeader>
              <CardTitle>{t('admin.system.socialConfig')}</CardTitle>
              <CardDescription>{t('admin.system.socialConfigDesc')}</CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="flex items-center space-x-2">
                <Switch
                  checked={socialForm.enabled}
                  onCheckedChange={(checked) => setSocialForm({ ...socialForm, enabled: checked })}
                />
                <Label>{t('admin.system.enableSocial')}</Label>
              </div>

              {socialForm.enabled && (
                <>
                  {/* GitHub */}
                  <div className="border rounded-lg p-4 space-y-4">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <Github className="h-5 w-5" />
                        <span className="font-medium">GitHub</span>
                      </div>
                      <Switch
                        checked={socialForm.github.enabled}
                        onCheckedChange={(checked) => setSocialForm({
                          ...socialForm,
                          github: { ...socialForm.github, enabled: checked }
                        })}
                      />
                    </div>
                    {socialForm.github.enabled && (
                      <div className="grid gap-4 md:grid-cols-2">
                        <div className="space-y-2">
                          <Label>{t('admin.federation.clientId')}</Label>
                          <Input
                            value={socialForm.github.client_id}
                            onChange={(e) => setSocialForm({
                              ...socialForm,
                              github: { ...socialForm.github, client_id: e.target.value }
                            })}
                            placeholder="GitHub OAuth App Client ID"
                          />
                        </div>
                        <div className="space-y-2">
                          <Label>{t('admin.federation.clientSecret')}</Label>
                          <Input
                            type="password"
                            value={socialForm.github.client_secret}
                            onChange={(e) => setSocialForm({
                              ...socialForm,
                              github: { ...socialForm.github, client_secret: e.target.value }
                            })}
                            placeholder={t('admin.system.passwordKeepEmpty')}
                          />
                        </div>
                      </div>
                    )}
                  </div>

                  {/* Google */}
                  <div className="border rounded-lg p-4 space-y-4">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <svg className="h-5 w-5" viewBox="0 0 24 24">
                          <path fill="currentColor" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
                          <path fill="currentColor" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
                          <path fill="currentColor" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/>
                          <path fill="currentColor" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/>
                        </svg>
                        <span className="font-medium">Google</span>
                      </div>
                      <Switch
                        checked={socialForm.google.enabled}
                        onCheckedChange={(checked) => setSocialForm({
                          ...socialForm,
                          google: { ...socialForm.google, enabled: checked }
                        })}
                      />
                    </div>
                    {socialForm.google.enabled && (
                      <div className="grid gap-4 md:grid-cols-2">
                        <div className="space-y-2">
                          <Label>{t('admin.federation.clientId')}</Label>
                          <Input
                            value={socialForm.google.client_id}
                            onChange={(e) => setSocialForm({
                              ...socialForm,
                              google: { ...socialForm.google, client_id: e.target.value }
                            })}
                            placeholder="Google OAuth Client ID"
                          />
                        </div>
                        <div className="space-y-2">
                          <Label>{t('admin.federation.clientSecret')}</Label>
                          <Input
                            type="password"
                            value={socialForm.google.client_secret}
                            onChange={(e) => setSocialForm({
                              ...socialForm,
                              google: { ...socialForm.google, client_secret: e.target.value }
                            })}
                            placeholder={t('admin.system.passwordKeepEmpty')}
                          />
                        </div>
                      </div>
                    )}
                  </div>
                </>
              )}
              
              <Button
                onClick={() => handleSave(t('admin.system.social'), {
                  social: {
                    enabled: socialForm.enabled,
                    github: {
                      enabled: socialForm.github.enabled,
                      client_id: socialForm.github.client_id,
                      client_secret: socialForm.github.client_secret || undefined,
                    },
                    google: {
                      enabled: socialForm.google.enabled,
                      client_id: socialForm.google.client_id,
                      client_secret: socialForm.google.client_secret || undefined,
                    },
                  }
                })}
                disabled={saving}
              >
                {saving ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <Save className="h-4 w-4 mr-2" />}
                {t('admin.system.saveSocial')}
              </Button>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
