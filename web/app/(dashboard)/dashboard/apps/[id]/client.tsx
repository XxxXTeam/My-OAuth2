'use client';

import { useEffect, useState, Suspense, useCallback } from 'react';
import { useParams, useSearchParams } from 'next/navigation';
import Link from 'next/link';
import { api } from '@/lib/api';
import { useI18n } from '@/lib/i18n';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Tooltip, TooltipTrigger, TooltipContent, TooltipProvider } from '@/components/ui/tooltip';
import { ArrowLeft, Copy, Check, Loader2, Eye, EyeOff, AlertTriangle, RefreshCw, Save, Plus, X, Pencil, Users, Info, ChevronDown, KeyRound, ShieldCheck } from 'lucide-react';
import { WebhookManager } from '@/components/webhook-manager';
import type { Application, AuthUserSummary, SAMLIdPServiceProviderConfig, UserAuthorization } from '@/lib/types';

/** Scope 与 UserInfo / ID Token Claim 的映射关系，用于开发者对接指引展示 */
const SCOPE_CLAIM_MAP: Array<{ scope: string; claims: string[] }> = [
  { scope: 'openid', claims: ['sub'] },
  { scope: 'profile', claims: ['name', 'preferred_username', 'nickname', 'given_name', 'family_name', 'picture', 'website', 'gender', 'birthdate', 'zoneinfo', 'locale', 'updated_at'] },
  { scope: 'email', claims: ['email', 'email_verified'] },
  { scope: 'phone', claims: ['phone_number', 'phone_number_verified'] },
  { scope: 'address', claims: ['address'] },
];

function AppDetailContent() {
  const params = useParams();
  const searchParams = useSearchParams();
  const { t, dateLocale } = useI18n();
  const isNew = searchParams.get('new') === 'true';

  // For static export, get ID from URL path instead of useParams
  // useParams returns '_placeholder_' in static export
  const [appId, setAppId] = useState<string | null>(null);
  const [app, setApp] = useState<Application | null>(null);

  useEffect(() => {
    // Extract actual ID from URL path
    const pathParts = window.location.pathname.split('/').filter(Boolean);
    const idFromPath = pathParts[pathParts.length - 1];
    if (idFromPath && idFromPath !== '_placeholder_') {
      setAppId(idFromPath);
    } else if (params.id && params.id !== '_placeholder_') {
      setAppId(params.id as string);
    }
  }, [params.id]);
  const [stats, setStats] = useState<{ total_authorizations: number; active_tokens: number; total_users: number; last_24h_tokens: number } | null>(null);
  const [authorizedUsers, setAuthorizedUsers] = useState<UserAuthorization[]>([]);
  const [authorizedUsersTotal, setAuthorizedUsersTotal] = useState(0);
  const [isLoading, setIsLoading] = useState(true);
  const [showSecret, setShowSecret] = useState(isNew);
  const [copiedField, setCopiedField] = useState<string | null>(null);
  const [showScopeMap, setShowScopeMap] = useState(false);
  const [isResetting, setIsResetting] = useState(false);
  const [isEditing, setIsEditing] = useState(false);
  const [isSaving, setIsSaving] = useState(false);
  const [samlIdPConfig, setSamlIdPConfig] = useState<SAMLIdPServiceProviderConfig | null>(null);
  const [isEditingSAMLIdP, setIsEditingSAMLIdP] = useState(false);
  const [isSavingSAMLIdP, setIsSavingSAMLIdP] = useState(false);
  const [samlIdPForm, setSamlIdPForm] = useState({
    sp_entity_id: '',
    acs_url: '',
    certificate_pem: '',
    name_id_format: 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
    attribute_mappings: '{\n  "email": "email",\n  "username": "username",\n  "displayName": "displayName"\n}',
    enabled: true,
  });
  const [editForm, setEditForm] = useState({
    name: '',
    description: '',
    redirect_uris: [''],
    post_logout_redirect_uris: [''],
    scopes: 'openid profile email phone address',
    allowed_scopes: 'api.read api.write',
    grant_types: ['authorization_code', 'refresh_token'],
  });
  const [message, setMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  const loadApp = useCallback(async () => {
    if (!appId) return;

    const response = await api.getApp(appId);
    if (response.success && response.data) {
      const storedSecret = sessionStorage.getItem(`app_secret_${appId}`);
      if (storedSecret) {
        response.data.client_secret = storedSecret;
        sessionStorage.removeItem(`app_secret_${appId}`);
      }
      setApp(response.data);

      const statsResponse = await api.getAppStats(appId);
      if (statsResponse.success && statsResponse.data) {
        setStats(statsResponse.data);
      }

      const usersResponse = await api.getAppAuthorizedUsers(appId, 1, 50);
      if (usersResponse.success && usersResponse.data) {
        setAuthorizedUsers(usersResponse.data.authorizations || []);
        setAuthorizedUsersTotal(usersResponse.data.total || 0);
      }

      const samlResponse = await api.getAppSAMLIdPConfig(appId);
      if (samlResponse.success && samlResponse.data) {
        setSamlIdPConfig(samlResponse.data);
        setSamlIdPForm({
          sp_entity_id: samlResponse.data.sp_entity_id || '',
          acs_url: samlResponse.data.acs_url || '',
          certificate_pem: '',
          name_id_format: samlResponse.data.name_id_format || 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
          attribute_mappings: JSON.stringify(samlResponse.data.attribute_mappings || {
            email: 'email',
            username: 'username',
            displayName: 'displayName',
          }, null, 2),
          enabled: samlResponse.data.enabled,
        });
      }
    }
    setIsLoading(false);
  }, [appId]);

  useEffect(() => {
    if (appId) {
      loadApp();
    }
  }, [appId, loadApp]);

  const copyToClipboard = async (text: string, field: string) => {
    await navigator.clipboard.writeText(text);
    setCopiedField(field);
    setTimeout(() => setCopiedField(null), 2000);
  };

  const handleResetSecret = async () => {
    if (!app || !confirm(t('apps.resetSecretConfirm'))) return;

    setIsResetting(true);
    const response = await api.resetAppSecret(app.id);
    if (response.success && response.data) {
      setApp(response.data);
      setShowSecret(true);
      setMessage({ type: 'success', text: t('toast.success') });
    } else {
      setMessage({ type: 'error', text: response.error?.message || t('toast.error') });
    }
    setIsResetting(false);
    setTimeout(() => setMessage(null), 3000);
  };

  const startEditing = () => {
    if (!app) return;
    setEditForm({
      name: app.name,
      description: app.description || '',
      redirect_uris: app.redirect_uris.length > 0 ? [...app.redirect_uris] : [''],
      post_logout_redirect_uris: app.post_logout_redirect_uris && app.post_logout_redirect_uris.length > 0 ? [...app.post_logout_redirect_uris] : [''],
      scopes: Array.isArray(app.scopes) && app.scopes.length > 0 ? app.scopes.join(' ') : 'openid profile email phone address',
      allowed_scopes: Array.isArray(app.allowed_scopes) && app.allowed_scopes.length > 0 ? app.allowed_scopes.join(' ') : 'api.read api.write',
      grant_types: Array.isArray(app.grant_types) && app.grant_types.length > 0 ? [...app.grant_types] : ['authorization_code', 'refresh_token'],
    });
    setIsEditing(true);
  };

  const cancelEditing = () => {
    setIsEditing(false);
    setEditForm({
      name: '',
      description: '',
      redirect_uris: [''],
      post_logout_redirect_uris: [''],
      scopes: 'openid profile email phone address',
      allowed_scopes: 'api.read api.write',
      grant_types: ['authorization_code', 'refresh_token'],
    });
  };

  const handleAddUri = () => {
    setEditForm({ ...editForm, redirect_uris: [...editForm.redirect_uris, ''] });
  };

  const handleRemoveUri = (index: number) => {
    if (editForm.redirect_uris.length > 1) {
      setEditForm({
        ...editForm,
        redirect_uris: editForm.redirect_uris.filter((_, i) => i !== index),
      });
    }
  };

  const handleUriChange = (index: number, value: string) => {
    const newUris = [...editForm.redirect_uris];
    newUris[index] = value;
    setEditForm({ ...editForm, redirect_uris: newUris });
  };

  const handleAddPostLogoutUri = () => {
    setEditForm({ ...editForm, post_logout_redirect_uris: [...editForm.post_logout_redirect_uris, ''] });
  };

  const handleRemovePostLogoutUri = (index: number) => {
    if (editForm.post_logout_redirect_uris.length > 1) {
      setEditForm({
        ...editForm,
        post_logout_redirect_uris: editForm.post_logout_redirect_uris.filter((_, i) => i !== index),
      });
    }
  };

  const handlePostLogoutUriChange = (index: number, value: string) => {
    const newUris = [...editForm.post_logout_redirect_uris];
    newUris[index] = value;
    setEditForm({ ...editForm, post_logout_redirect_uris: newUris });
  };

  const handleSave = async () => {
    if (!app) return;

    const validUris = editForm.redirect_uris.filter(uri => uri.trim() !== '');
    const validPostLogoutUris = editForm.post_logout_redirect_uris.filter(uri => uri.trim() !== '');
    if (validUris.length === 0) {
      setMessage({ type: 'error', text: t('apps.detail.atLeastOneUri') });
      return;
    }

    const scopeList = editForm.scopes.split(/\s+/).map((s) => s.trim()).filter(Boolean);
    const allowedList = editForm.allowed_scopes.split(/\s+/).map((s) => s.trim()).filter(Boolean);

    setIsSaving(true);
    const response = await api.updateApp(app.id, {
      name: editForm.name,
      description: editForm.description,
      redirect_uris: validUris,
      post_logout_redirect_uris: validPostLogoutUris,
      scopes: scopeList,
      allowed_scopes: allowedList,
      grant_types: editForm.grant_types,
    });

    if (response.success && response.data) {
      setApp(response.data);
      setIsEditing(false);
      setMessage({ type: 'success', text: t('toast.saved') });
    } else {
      setMessage({ type: 'error', text: response.error?.message || t('toast.error') });
    }
    setIsSaving(false);
    setTimeout(() => setMessage(null), 3000);
  };

  const cancelSAMLIdPEditing = () => {
    if (samlIdPConfig) {
      setSamlIdPForm({
        sp_entity_id: samlIdPConfig.sp_entity_id || '',
        acs_url: samlIdPConfig.acs_url || '',
        certificate_pem: '',
        name_id_format: samlIdPConfig.name_id_format || 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
        attribute_mappings: JSON.stringify(samlIdPConfig.attribute_mappings || {
          email: 'email',
          username: 'username',
          displayName: 'displayName',
        }, null, 2),
        enabled: samlIdPConfig.enabled,
      });
    }
    setIsEditingSAMLIdP(false);
  };

  const handleSaveSAMLIdP = async () => {
    if (!app) return;
    let mappings: Record<string, string>;
    try {
      mappings = JSON.parse(samlIdPForm.attribute_mappings || '{}');
    } catch {
      setMessage({ type: 'error', text: t('apps.detail.samlIdpInvalidMappings') });
      setTimeout(() => setMessage(null), 3000);
      return;
    }

    setIsSavingSAMLIdP(true);
    const response = await api.updateAppSAMLIdPConfig(app.id, {
      sp_entity_id: samlIdPForm.sp_entity_id,
      acs_url: samlIdPForm.acs_url,
      certificate_pem: samlIdPForm.certificate_pem.trim() || undefined,
      name_id_format: samlIdPForm.name_id_format,
      attribute_mappings: mappings,
      enabled: samlIdPForm.enabled,
    });

    if (response.success && response.data) {
      setSamlIdPConfig(response.data);
      setSamlIdPForm({
        sp_entity_id: response.data.sp_entity_id || '',
        acs_url: response.data.acs_url || '',
        certificate_pem: '',
        name_id_format: response.data.name_id_format,
        attribute_mappings: JSON.stringify(response.data.attribute_mappings || {}, null, 2),
        enabled: response.data.enabled,
      });
      setIsEditingSAMLIdP(false);
      setMessage({ type: 'success', text: t('toast.saved') });
    } else {
      setMessage({ type: 'error', text: response.error?.message || t('toast.error') });
    }
    setIsSavingSAMLIdP(false);
    setTimeout(() => setMessage(null), 3000);
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
      </div>
    );
  }

  if (!app) {
    return (
      <div className="text-center py-12">
        <h2 className="text-xl font-semibold">{t('errors.appNotFound')}</h2>
        <Link href="/dashboard/apps">
          <Button variant="outline" className="mt-4">
            {t('common.back')}
          </Button>
        </Link>
      </div>
    );
  }

  return (
    <div className="max-w-3xl mx-auto space-y-8">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <Link href="/dashboard/apps">
            <Button variant="outline" size="icon">
              <ArrowLeft className="h-4 w-4" />
            </Button>
          </Link>
          <div>
            <h1 className="text-3xl font-bold">{app.name}</h1>
            <p className="text-muted-foreground mt-1">
              {app.description || t('apps.create.descriptionPlaceholder')}
            </p>
          </div>
        </div>
      </div>

      {/* Message */}
      {message && (
        <div className={`p-4 rounded-md ${
          message.type === 'success'
            ? 'bg-green-50 text-green-700 dark:bg-green-900/20 dark:text-green-400'
            : 'bg-red-50 text-red-700 dark:bg-red-900/20 dark:text-red-400'
        }`}>
          {message.text}
        </div>
      )}

      {/* New App Warning */}
      {isNew && app.client_secret && (
        <Card className="border-yellow-500 bg-yellow-50 dark:bg-yellow-900/20">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-yellow-700 dark:text-yellow-500">
              <AlertTriangle className="h-5 w-5" />
              {t('apps.detail.saveSecretWarning')}
            </CardTitle>
            <CardDescription className="text-yellow-600 dark:text-yellow-400">
              {t('apps.detail.saveSecretDesc')}
            </CardDescription>
          </CardHeader>
        </Card>
      )}

      {/* Stats */}
      {stats && (
        <div className="grid gap-4 md:grid-cols-4">
          <Card>
            <CardHeader className="pb-2">
              <CardDescription>{t('dashboard.stats.totalApps')}</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{stats.total_authorizations}</div>
              <p className="text-xs text-muted-foreground">{t('apps.detail.totalAuthorizations')}</p>
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="pb-2">
              <CardDescription>{t('dashboard.stats.activeTokens')}</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{stats.active_tokens}</div>
              <p className="text-xs text-muted-foreground">{t('apps.detail.activeTokens')}</p>
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="pb-2">
              <CardDescription>{t('dashboard.stats.users')}</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{stats.total_users}</div>
              <p className="text-xs text-muted-foreground">{t('apps.detail.authorizedUsers')}</p>
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="pb-2">
              <CardDescription>{t('dashboard.stats.apiCalls')}</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{stats.last_24h_tokens}</div>
              <p className="text-xs text-muted-foreground">{t('apps.detail.last24h')}</p>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Authorized Users */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Users className="h-5 w-5" />
            {t('apps.detail.authorizedUsersList')}
          </CardTitle>
          <CardDescription>
            {t('apps.detail.authorizedUsersDesc')}
            {authorizedUsersTotal > 0 && (
              <span className="ml-1 text-foreground">({authorizedUsersTotal})</span>
            )}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {authorizedUsers.length === 0 ? (
            <p className="text-sm text-muted-foreground">{t('apps.detail.noAuthorizedUsers')}</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b text-left text-muted-foreground">
                    <th className="pb-2 pr-4 font-medium">{t('apps.detail.colUser')}</th>
                    <th className="pb-2 pr-4 font-medium">{t('apps.detail.colScope')}</th>
                    <th className="pb-2 pr-4 font-medium">{t('apps.detail.colGrantType')}</th>
                    <th className="pb-2 pr-4 font-medium">{t('apps.detail.colStatus')}</th>
                    <th className="pb-2 font-medium">{t('apps.detail.colAuthorizedAt')}</th>
                  </tr>
                </thead>
                <tbody>
                  {authorizedUsers.map((auth) => {
                    const u = auth.user as AuthUserSummary | undefined;
                    const displayName = u?.display_name || u?.username || u?.email || auth.user_id.slice(0, 8);
                    const scopes = auth.scopes?.length ? auth.scopes : auth.scope?.split(' ').filter(Boolean);
                    return (
                      <tr key={auth.id} className="border-b last:border-0 align-top">
                        <td className="py-3 pr-4">
                          <div className="font-medium">{displayName}</div>
                          {u?.email && (
                            <div className="text-xs text-muted-foreground">{u.email}</div>
                          )}
                          {u?.username && u.email !== u.username && (
                            <div className="text-xs text-muted-foreground font-mono">@{u.username}</div>
                          )}
                        </td>
                        <td className="py-3 pr-4">
                          <div className="flex flex-wrap gap-1 max-w-xs">
                            {(scopes || []).map((s) => (
                              <span key={s} className="px-1.5 py-0.5 rounded bg-muted text-xs font-mono">{s}</span>
                            ))}
                            {(!scopes || scopes.length === 0) && (
                              <span className="text-muted-foreground text-xs">—</span>
                            )}
                          </div>
                        </td>
                        <td className="py-3 pr-4 font-mono text-xs">{auth.grant_type || '—'}</td>
                        <td className="py-3 pr-4">
                          <span className={`inline-flex px-2 py-0.5 rounded-full text-xs font-medium ${
                            auth.is_active ?? !auth.revoked
                              ? 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400'
                              : 'bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-400'
                          }`}>
                            {(auth.is_active ?? !auth.revoked)
                              ? t('apps.detail.authStatusActive')
                              : t('apps.detail.authStatusRevoked')}
                          </span>
                        </td>
                        <td className="py-3 text-muted-foreground whitespace-nowrap">
                          {new Date(auth.authorized_at).toLocaleString(dateLocale)}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Credentials */}
      <Card>
        <CardHeader>
          <CardTitle>{t('apps.detail.credentials')}</CardTitle>
          <CardDescription>{t('apps.detail.credentialsDesc')}</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label>{t('apps.detail.clientId')}</Label>
            <div className="flex gap-2">
              <Input value={app.client_id} readOnly className="font-mono" />
              <Button variant="outline" size="icon" onClick={() => copyToClipboard(app.client_id, 'client_id')}>
                {copiedField === 'client_id' ? <Check className="h-4 w-4 text-green-500" /> : <Copy className="h-4 w-4" />}
              </Button>
            </div>
          </div>

          <div className="space-y-2">
            <Label>{t('apps.detail.clientSecret')}</Label>
            {app.client_secret ? (
              <div className="flex gap-2">
                <Input type={showSecret ? 'text' : 'password'} value={app.client_secret} readOnly className="font-mono" />
                <Button variant="outline" size="icon" onClick={() => setShowSecret(!showSecret)}>
                  {showSecret ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </Button>
                <Button variant="outline" size="icon" onClick={() => copyToClipboard(app.client_secret!, 'client_secret')}>
                  {copiedField === 'client_secret' ? <Check className="h-4 w-4 text-green-500" /> : <Copy className="h-4 w-4" />}
                </Button>
              </div>
            ) : (
              <div className="flex gap-2 items-center">
                <Input value="••••••••••••••••••••••••••••••••" readOnly className="font-mono text-muted-foreground" />
                <Button variant="outline" onClick={handleResetSecret} disabled={isResetting}>
                  {isResetting ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : <RefreshCw className="h-4 w-4 mr-2" />}
                  {t('apps.resetSecret')}
                </Button>
              </div>
            )}
            <p className="text-xs text-muted-foreground">{t('apps.detail.saveSecretDesc')}</p>
          </div>
        </CardContent>
      </Card>

      {/* Grant Types - Inline Editable */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle>{t('apps.detail.grantTypes')}</CardTitle>
              <CardDescription>{t('apps.detail.grantTypesDesc')}</CardDescription>
            </div>
            {!isEditing && (
              <Button variant="outline" size="sm" onClick={startEditing}>
                <Pencil className="h-4 w-4 mr-2" />
                {t('common.edit')}
              </Button>
            )}
          </div>
        </CardHeader>
        <CardContent>
          {isEditing ? (
            <div className="space-y-3">
              <div className="grid sm:grid-cols-2 gap-3">
                {['authorization_code','refresh_token','client_credentials','device_code','token_exchange'].map(key => (
                  <label key={key} className="flex items-start gap-2 cursor-pointer select-none">
                    <input
                      type="checkbox"
                      className="mt-1 h-4 w-4"
                      checked={editForm.grant_types.includes(key)}
                      onChange={(e) => {
                        setEditForm(prev => {
                          const exists = prev.grant_types.includes(key);
                          const grant_types = e.target.checked
                            ? (exists ? prev.grant_types : [...prev.grant_types, key])
                            : prev.grant_types.filter(x => x !== key);
                          return { ...prev, grant_types };
                        });
                      }}
                    />
                    <div>
                      <div className="text-sm font-medium">{t(`apps.grantType.${key}`)}</div>
                      <div className="text-xs text-muted-foreground">{t(`apps.grantType.${key}_desc`)}</div>
                    </div>
                  </label>
                ))}
              </div>
            </div>
          ) : (
            <div className="flex flex-wrap gap-2">
              {(app.grant_types || []).map((gt: string, i: number) => (
                <span key={i} className="px-2 py-1 rounded border text-xs">{t(`apps.grantType.${gt}`)}</span>
              ))}
              {(app.grant_types || []).length === 0 && (
                <p className="text-muted-foreground text-sm">-</p>
              )}
            </div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>{t('apps.detail.scopes')}</CardTitle>
          <CardDescription>{t('apps.detail.scopesDesc')}</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {isEditing ? (
            <>
              <div className="space-y-2">
                <Label className="text-xs text-muted-foreground">{t('apps.detail.scopes')}</Label>
                <Input
                  value={editForm.scopes}
                  onChange={(e) => setEditForm({ ...editForm, scopes: e.target.value })}
                  placeholder={t('apps.detail.scopesPlaceholder')}
                  className="font-mono text-sm"
                  spellCheck={false}
                />
              </div>
              <div className="space-y-2">
                <Label className="text-xs text-muted-foreground">{t('apps.detail.allowedScopes')}</Label>
                <Input
                  value={editForm.allowed_scopes}
                  onChange={(e) => setEditForm({ ...editForm, allowed_scopes: e.target.value })}
                  placeholder={t('apps.detail.allowedScopesPlaceholder')}
                  className="font-mono text-sm"
                  spellCheck={false}
                />
              </div>
            </>
          ) : (
            <>
              <div>
                <p className="text-xs text-muted-foreground mb-2">{t('apps.detail.scopes')}</p>
                <div className="flex flex-wrap gap-2">
                  {(app.scopes || []).map((s) => (
                    <span key={s} className="px-2 py-1 rounded border text-xs font-mono bg-primary/5">
                      {s}
                    </span>
                  ))}
                </div>
              </div>
              {(app.allowed_scopes || []).length > 0 && (
                <div>
                  <p className="text-xs text-muted-foreground mb-2">{t('apps.detail.allowedScopes')}</p>
                  <div className="flex flex-wrap gap-2">
                    {app.allowed_scopes!.map((s) => (
                      <span key={s} className="px-2 py-1 rounded border text-xs font-mono">
                        {s}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>{t('apps.detail.oauthMetadata')}</CardTitle>
        </CardHeader>
        <CardContent className="space-y-2 text-sm">
          <div className="flex justify-between gap-4">
            <span className="text-muted-foreground">{t('apps.detail.appType')}</span>
            <span className="font-mono">{app.app_type || 'confidential'}</span>
          </div>
          <div className="flex justify-between gap-4">
            <span className="text-muted-foreground">{t('apps.detail.tokenEndpointAuthMethod')}</span>
            <span className="font-mono text-right">{app.token_endpoint_auth_method || 'client_secret_basic'}</span>
          </div>
          <div className="flex justify-between gap-4">
            <span className="text-muted-foreground">{t('apps.detail.responseTypes')}</span>
            <span className="font-mono text-right">{(app.response_types_supported || ['code']).join(' ')}</span>
          </div>
          <div>
            <p className="text-xs text-muted-foreground mb-2">{t('apps.detail.issuedTokenTypes')}</p>
            <div className="flex flex-wrap gap-2">
              {(app.issued_token_types || ['access_token', 'refresh_token', 'id_token']).map((tok) => (
                <span key={tok} className="px-2 py-1 rounded bg-primary/10 border text-xs font-mono">
                  {tok}
                </span>
              ))}
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Redirect URIs - Inline Editable */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle>{t('apps.detail.redirectUris')}</CardTitle>
              <CardDescription>{t('apps.detail.redirectUrisDesc')}</CardDescription>
            </div>
            {!isEditing && (
              <Button variant="outline" size="sm" onClick={startEditing}>
                <Pencil className="h-4 w-4 mr-2" />
                {t('common.edit')}
              </Button>
            )}
          </div>
        </CardHeader>
        <CardContent>
          {isEditing ? (
            <div className="space-y-3">
              {editForm.redirect_uris.map((uri, index) => (
                <div key={index} className="flex gap-2">
                  <Input
                    value={uri}
                    onChange={(e) => handleUriChange(index, e.target.value)}
                    placeholder="https://example.com/callback"
                    className="font-mono text-sm"
                  />
                  {editForm.redirect_uris.length > 1 && (
                    <Button variant="outline" size="icon" onClick={() => handleRemoveUri(index)}>
                      <X className="h-4 w-4" />
                    </Button>
                  )}
                </div>
              ))}
              <div className="flex gap-2">
                <Button variant="outline" size="sm" onClick={handleAddUri}>
                  <Plus className="h-4 w-4 mr-2" />
                  {t('common.add')}
                </Button>
              </div>
              <div className="space-y-2 pt-4 border-t">
                <Label className="text-xs text-muted-foreground">{t('apps.detail.postLogoutRedirectUris')}</Label>
                {(editForm.post_logout_redirect_uris || ['']).map((uri, index) => (
                  <div key={index} className="flex gap-2">
                    <Input
                      value={uri}
                      onChange={(e) => handlePostLogoutUriChange(index, e.target.value)}
                      placeholder="https://example.com/logout-callback"
                      className="font-mono text-sm"
                    />
                    {editForm.post_logout_redirect_uris.length > 1 && (
                      <Button variant="outline" size="icon" onClick={() => handleRemovePostLogoutUri(index)}>
                        <X className="h-4 w-4" />
                      </Button>
                    )}
                  </div>
                ))}
                <Button variant="outline" size="sm" onClick={handleAddPostLogoutUri}>
                  <Plus className="h-4 w-4 mr-2" />
                  {t('common.add')}
                </Button>
              </div>
              <div className="flex gap-2 pt-2 border-t mt-4">
                <Button size="sm" onClick={handleSave} disabled={isSaving}>
                  {isSaving ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : <Save className="h-4 w-4 mr-2" />}
                  {t('common.save')}
                </Button>
                <Button variant="outline" size="sm" onClick={cancelEditing}>
                  {t('common.cancel')}
                </Button>
              </div>
            </div>
          ) : (
            <div className="space-y-4">
              <div className="space-y-2">
                <p className="text-xs text-muted-foreground">{t('apps.detail.redirectUris')}</p>
                {app.redirect_uris.length > 0 ? app.redirect_uris.map((uri, index) => (
                  <div key={index} className="flex gap-2">
                    <Input value={uri} readOnly className="font-mono text-sm bg-slate-50" />
                    <Button variant="outline" size="icon" onClick={() => copyToClipboard(uri, `uri_${index}`)}>
                      {copiedField === `uri_${index}` ? <Check className="h-4 w-4 text-green-500" /> : <Copy className="h-4 w-4" />}
                    </Button>
                  </div>
                )) : (
                  <p className="text-muted-foreground text-sm">{t('apps.detail.noRedirectUris')}</p>
                )}
              </div>
              <div className="space-y-2">
                <p className="text-xs text-muted-foreground">{t('apps.detail.postLogoutRedirectUris')}</p>
                {(app.post_logout_redirect_uris || []).length > 0 ? app.post_logout_redirect_uris!.map((uri, index) => (
                  <div key={index} className="flex gap-2">
                    <Input value={uri} readOnly className="font-mono text-sm bg-slate-50" />
                    <Button variant="outline" size="icon" onClick={() => copyToClipboard(uri, `post_logout_uri_${index}`)}>
                      {copiedField === `post_logout_uri_${index}` ? <Check className="h-4 w-4 text-green-500" /> : <Copy className="h-4 w-4" />}
                    </Button>
                  </div>
                )) : (
                  <p className="text-muted-foreground text-sm">{t('apps.detail.noPostLogoutRedirectUris')}</p>
                )}
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* OAuth2 Endpoints */}
      <Card>
        <CardHeader>
          <CardTitle>{t('apps.detail.endpoints')}</CardTitle>
          <CardDescription>{t('apps.detail.endpointsDesc')}</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {[
            ['discoveryUrl', '/.well-known/openid-configuration'],
            ['oauthMetadataUrl', '/.well-known/oauth-authorization-server'],
            ['jwksUrl', '/.well-known/jwks.json'],
            ['authUrl', '/oauth/authorize'],
            ['tokenUrl', '/oauth/token'],
            ['userInfoUrl', '/oauth/userinfo'],
            ['revokeUrl', '/oauth/revoke'],
            ['introspectUrl', '/oauth/introspect'],
            ['logoutUrl', '/oauth/logout'],
            ['deviceUrl', '/oauth/device/code'],
            ['samlIdpMetadataUrl', '/saml/idp/metadata'],
            ['samlIdpSsoUrl', '/saml/idp/sso'],
            ['samlIdpSloUrl', '/saml/idp/slo'],
          ].map(([labelKey, path]) => {
            const value = `${typeof window !== 'undefined' ? window.location.origin : ''}${path}`;
            return (
              <div key={path} className="space-y-2">
                <Label>{t(`apps.detail.${labelKey}`)}</Label>
                <div className="flex gap-2">
                  <Input value={value} readOnly className="font-mono text-sm" />
                  <Button variant="outline" size="icon" onClick={() => copyToClipboard(value, `endpoint_${labelKey}`)}>
                    {copiedField === `endpoint_${labelKey}` ? <Check className="h-4 w-4 text-green-500" /> : <Copy className="h-4 w-4" />}
                  </Button>
                </div>
              </div>
            );
          })}
        </CardContent>
      </Card>

      {/* Developer Integration Guide —— 开发者对接指引 */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <KeyRound className="h-5 w-5" />
            {t('apps.detail.devGuide')}
          </CardTitle>
          <CardDescription>{t('apps.detail.devGuideDesc')}</CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          {/* Issuer URL —— 单独一行展示 iss */}
          <div className="space-y-2">
            <div className="flex items-center gap-1.5">
              <Label>{t('apps.detail.issuer')}</Label>
              <TooltipProvider>
                <Tooltip>
                  <TooltipTrigger asChild>
                    <Info className="h-3.5 w-3.5 text-muted-foreground cursor-help" />
                  </TooltipTrigger>
                  <TooltipContent className="max-w-xs">
                    {t('apps.detail.issuerHint')}
                  </TooltipContent>
                </Tooltip>
              </TooltipProvider>
            </div>
            {(() => {
              const issuer = typeof window !== 'undefined' ? window.location.origin : '';
              return (
                <div className="flex gap-2">
                  <Input value={issuer} readOnly className="font-mono text-sm" />
                  <Button variant="outline" size="icon" onClick={() => copyToClipboard(issuer, 'issuer')}>
                    {copiedField === 'issuer' ? <Check className="h-4 w-4 text-green-500" /> : <Copy className="h-4 w-4" />}
                  </Button>
                </div>
              );
            })()}
          </div>

          {/* ID Token 签名算法说明 */}
          <div className="space-y-1.5">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="text-sm text-muted-foreground">{t('apps.detail.idTokenAlg')}:</span>
              <Badge variant="info" className="font-mono">{t('apps.detail.idTokenAlgValue')}</Badge>
            </div>
            <p className="flex items-start gap-1.5 text-xs text-muted-foreground">
              <ShieldCheck className="h-3.5 w-3.5 mt-0.5 shrink-0" />
              {t('apps.detail.idTokenAlgHint')}
            </p>
          </div>

          {/* Scope → Claim 映射（可折叠） */}
          <div className="space-y-2">
            <button
              type="button"
              onClick={() => setShowScopeMap((v) => !v)}
              className="flex items-center gap-2 text-sm font-medium hover:text-primary transition-colors"
            >
              <ChevronDown className={`h-4 w-4 transition-transform ${showScopeMap ? 'rotate-0' : '-rotate-90'}`} />
              {t('apps.detail.scopeClaimTitle')}
            </button>
            <p className="text-xs text-muted-foreground">{t('apps.detail.scopeClaimHint')}</p>
            {showScopeMap && (
              <div className="overflow-x-auto rounded-md border">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b bg-muted/50 text-left text-muted-foreground">
                      <th className="px-3 py-2 font-medium">{t('apps.detail.colScopeName')}</th>
                      <th className="px-3 py-2 font-medium">{t('apps.detail.colClaims')}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {SCOPE_CLAIM_MAP.map(({ scope, claims }) => (
                      <tr key={scope} className="border-b last:border-0 align-top">
                        <td className="px-3 py-2">
                          <span className="px-1.5 py-0.5 rounded bg-primary/10 border text-xs font-mono">{scope}</span>
                        </td>
                        <td className="px-3 py-2">
                          <div className="flex flex-wrap gap-1">
                            {claims.map((c) => (
                              <span key={c} className="px-1.5 py-0.5 rounded bg-muted text-xs font-mono">{c}</span>
                            ))}
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          {/* PKCE 提示 —— 仅公开客户端展示 */}
          {app.app_type === 'public' && (
            <div className="flex items-start gap-2 rounded-md border border-yellow-500/50 bg-yellow-50 p-3 text-sm dark:bg-yellow-900/20">
              <AlertTriangle className="h-4 w-4 mt-0.5 shrink-0 text-yellow-600 dark:text-yellow-500" />
              <div className="space-y-0.5">
                <p className="font-medium text-yellow-700 dark:text-yellow-500">{t('apps.detail.pkceRequiredTitle')}</p>
                <p className="text-yellow-600 dark:text-yellow-400">{t('apps.detail.pkceRequiredDesc')}</p>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* SAML IdP */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle>{t('apps.detail.samlIdpTitle')}</CardTitle>
              <CardDescription>{t('apps.detail.samlIdpDesc')}</CardDescription>
            </div>
            {!isEditingSAMLIdP && (
              <Button variant="outline" size="sm" onClick={() => setIsEditingSAMLIdP(true)}>
                <Pencil className="h-4 w-4 mr-2" />
                {t('common.edit')}
              </Button>
            )}
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          {isEditingSAMLIdP ? (
            <div className="space-y-4">
              <label className="flex items-center gap-2 text-sm">
                <input
                  type="checkbox"
                  checked={samlIdPForm.enabled}
                  onChange={(e) => setSamlIdPForm({ ...samlIdPForm, enabled: e.target.checked })}
                />
                {t('apps.detail.samlIdpEnabled')}
              </label>
              <div className="space-y-2">
                <Label>{t('apps.detail.samlIdpSpEntityId')}</Label>
                <Input
                  value={samlIdPForm.sp_entity_id}
                  onChange={(e) => setSamlIdPForm({ ...samlIdPForm, sp_entity_id: e.target.value })}
                  placeholder="https://sp.example.com/saml/metadata"
                  className="font-mono text-sm"
                  spellCheck={false}
                />
              </div>
              <div className="space-y-2">
                <Label>{t('apps.detail.samlIdpAcsUrl')}</Label>
                <Input
                  value={samlIdPForm.acs_url}
                  onChange={(e) => setSamlIdPForm({ ...samlIdPForm, acs_url: e.target.value })}
                  placeholder="https://sp.example.com/saml/acs"
                  className="font-mono text-sm"
                  spellCheck={false}
                />
              </div>
              <div className="space-y-2">
                <Label>{t('apps.detail.samlIdpNameIdFormat')}</Label>
                <select
                  value={samlIdPForm.name_id_format}
                  onChange={(e) => setSamlIdPForm({ ...samlIdPForm, name_id_format: e.target.value })}
                  className="w-full h-10 rounded-md border border-input bg-background px-3 py-2 text-sm font-mono"
                >
                  <option value="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</option>
                  <option value="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</option>
                  <option value="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</option>
                  <option value="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">urn:oasis:names:tc:SAML:2.0:nameid-format:transient</option>
                </select>
              </div>
              <div className="space-y-2">
                <Label>{t('apps.detail.samlIdpCertificate')}</Label>
                <Textarea
                  value={samlIdPForm.certificate_pem}
                  onChange={(e) => setSamlIdPForm({ ...samlIdPForm, certificate_pem: e.target.value })}
                  placeholder="-----BEGIN CERTIFICATE-----"
                  className="min-h-[120px] font-mono text-xs"
                  spellCheck={false}
                />
                {samlIdPConfig?.certificate_configured && (
                  <p className="text-xs text-muted-foreground">{t('apps.detail.samlIdpCertificateConfigured')}</p>
                )}
              </div>
              <div className="space-y-2">
                <Label>{t('apps.detail.samlIdpAttributeMappings')}</Label>
                <Textarea
                  value={samlIdPForm.attribute_mappings}
                  onChange={(e) => setSamlIdPForm({ ...samlIdPForm, attribute_mappings: e.target.value })}
                  className="min-h-[130px] font-mono text-xs"
                  spellCheck={false}
                />
              </div>
              <div className="flex gap-2 pt-2 border-t">
                <Button size="sm" onClick={handleSaveSAMLIdP} disabled={isSavingSAMLIdP}>
                  {isSavingSAMLIdP ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : <Save className="h-4 w-4 mr-2" />}
                  {t('common.save')}
                </Button>
                <Button variant="outline" size="sm" onClick={cancelSAMLIdPEditing}>
                  {t('common.cancel')}
                </Button>
              </div>
            </div>
          ) : (
            <div className="space-y-4">
              {samlIdPConfig?.sp_entity_id ? (
                <>
                  <div className="flex justify-between gap-4 text-sm">
                    <span className="text-muted-foreground">{t('common.status')}</span>
                    <span>{samlIdPConfig.enabled ? t('common.enabled') : t('common.disabled')}</span>
                  </div>
                  {[
                    ['samlIdpSpEntityId', samlIdPConfig.sp_entity_id],
                    ['samlIdpAcsUrl', samlIdPConfig.acs_url],
                    ['samlIdpNameIdFormat', samlIdPConfig.name_id_format],
                  ].map(([labelKey, value]) => (
                    <div key={labelKey} className="space-y-2">
                      <Label>{t(`apps.detail.${labelKey}`)}</Label>
                      <div className="flex gap-2">
                        <Input value={value || ''} readOnly className="font-mono text-sm" />
                        <Button variant="outline" size="icon" onClick={() => copyToClipboard(value || '', `saml_${labelKey}`)}>
                          {copiedField === `saml_${labelKey}` ? <Check className="h-4 w-4 text-green-500" /> : <Copy className="h-4 w-4" />}
                        </Button>
                      </div>
                    </div>
                  ))}
                </>
              ) : (
                <p className="text-sm text-muted-foreground">{t('apps.detail.samlIdpNotConfigured')}</p>
              )}
              {[
                ['samlIdpEntityId', samlIdPConfig?.idp_entity_id],
                ['samlIdpMetadataUrl', samlIdPConfig?.idp_metadata_url],
                ['samlIdpSsoUrl', samlIdPConfig?.idp_sso_url],
              ].map(([labelKey, value]) => (
                <div key={labelKey} className="space-y-2">
                  <Label>{t(`apps.detail.${labelKey}`)}</Label>
                  <div className="flex gap-2">
                    <Input value={value || ''} readOnly className="font-mono text-sm" />
                    <Button variant="outline" size="icon" onClick={() => copyToClipboard(value || '', `saml_${labelKey}`)} disabled={!value}>
                      {copiedField === `saml_${labelKey}` ? <Check className="h-4 w-4 text-green-500" /> : <Copy className="h-4 w-4" />}
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Info */}
      <Card>
        <CardHeader>
          <CardTitle>{t('apps.detail.appInfo')}</CardTitle>
        </CardHeader>
        <CardContent>
          <dl className="grid grid-cols-2 gap-4 text-sm">
            <div>
              <dt className="text-muted-foreground">{t('apps.detail.created')}</dt>
              <dd className="font-medium">{new Date(app.created_at).toLocaleString(dateLocale)}</dd>
            </div>
            <div>
              <dt className="text-muted-foreground">ID</dt>
              <dd className="font-mono">{app.id}</dd>
            </div>
          </dl>
        </CardContent>
      </Card>

      {/* Webhooks */}
      <WebhookManager appId={app.id} />
    </div>
  );
}

export default function AppDetailClient() {
  return (
    <Suspense fallback={
      <div className="flex items-center justify-center py-12">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
      </div>
    }>
      <AppDetailContent />
    </Suspense>
  );
}
