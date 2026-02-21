'use client';

import { useEffect, useState, Suspense, useCallback } from 'react';
import { useParams, useSearchParams } from 'next/navigation';
import Link from 'next/link';
import { api } from '@/lib/api';
import { useI18n } from '@/lib/i18n';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { ArrowLeft, Copy, Check, Loader2, Eye, EyeOff, AlertTriangle, RefreshCw, Save, Plus, X, Pencil } from 'lucide-react';
import { WebhookManager } from '@/components/webhook-manager';
import type { Application } from '@/lib/types';

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
    const pathParts = window.location.pathname.split('/');
    const idFromPath = pathParts[pathParts.length - 1];
    if (idFromPath && idFromPath !== '_placeholder_') {
      setAppId(idFromPath);
    } else if (params.id && params.id !== '_placeholder_') {
      setAppId(params.id as string);
    }
  }, [params.id]);
  const [stats, setStats] = useState<{ total_authorizations: number; active_tokens: number; total_users: number; last_24h_tokens: number } | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [showSecret, setShowSecret] = useState(isNew);
  const [copiedField, setCopiedField] = useState<string | null>(null);
  const [isResetting, setIsResetting] = useState(false);
  const [isEditing, setIsEditing] = useState(false);
  const [isSaving, setIsSaving] = useState(false);
  const [editForm, setEditForm] = useState({ name: '', description: '', redirect_uris: [''], grant_types: ['authorization_code', 'refresh_token'] });
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
      grant_types: Array.isArray(app.grant_types) && app.grant_types.length > 0 ? [...app.grant_types] : ['authorization_code', 'refresh_token'],
    });
    setIsEditing(true);
  };

  const cancelEditing = () => {
    setIsEditing(false);
    setEditForm({ name: '', description: '', redirect_uris: [''], grant_types: ['authorization_code', 'refresh_token'] });
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

  const handleSave = async () => {
    if (!app) return;
    
    const validUris = editForm.redirect_uris.filter(uri => uri.trim() !== '');
    if (validUris.length === 0) {
      setMessage({ type: 'error', text: t('apps.detail.atLeastOneUri') });
      return;
    }

    setIsSaving(true);
    const response = await api.updateApp(app.id, {
      name: editForm.name,
      description: editForm.description,
      redirect_uris: validUris,
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
            <div className="space-y-2">
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
          <div className="space-y-2">
            <Label>{t('apps.detail.authUrl')}</Label>
            <Input value={`${typeof window !== 'undefined' ? window.location.origin : ''}/oauth/authorize`} readOnly className="font-mono text-sm" />
          </div>
          <div className="space-y-2">
            <Label>{t('apps.detail.tokenUrl')}</Label>
            <Input value={`${typeof window !== 'undefined' ? window.location.origin : ''}/oauth/token`} readOnly className="font-mono text-sm" />
          </div>
          <div className="space-y-2">
            <Label>{t('apps.detail.userInfoUrl')}</Label>
            <Input value={`${typeof window !== 'undefined' ? window.location.origin : ''}/oauth/userinfo`} readOnly className="font-mono text-sm" />
          </div>
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
