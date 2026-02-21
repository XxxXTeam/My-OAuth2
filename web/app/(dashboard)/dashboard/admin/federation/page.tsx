'use client';

import { useState, useEffect, useCallback } from 'react';
import { useAuth } from '@/lib/auth-context';
import { useI18n } from '@/lib/i18n';
import { api } from '@/lib/api';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Switch } from '@/components/ui/switch';
import { PageHeader } from '@/components/ui/page-header';
import { EmptyState } from '@/components/ui/empty-state';
import { Skeleton } from '@/components/ui/skeleton';
import {
  Globe, Plus, Trash2, Edit, Loader2, AlertCircle, Check, ExternalLink, X
} from 'lucide-react';
import type { FederationProvider, CreateFederationProviderRequest } from '@/lib/types';

/* 联邦提供商表单组件 */
function ProviderForm({
  provider,
  onSave,
  onCancel,
}: {
  provider?: FederationProvider;
  onSave: (data: CreateFederationProviderRequest) => Promise<void>;
  onCancel: () => void;
}) {
  const { t } = useI18n();
  const [form, setForm] = useState<CreateFederationProviderRequest>({
    name: provider?.name || '',
    slug: provider?.slug || '',
    description: provider?.description || '',
    auth_url: provider?.auth_url || '',
    token_url: provider?.token_url || '',
    userinfo_url: provider?.userinfo_url || '',
    client_id: provider?.client_id || '',
    client_secret: '',
    scopes: provider?.scopes || 'openid profile email',
    enabled: provider?.enabled ?? true,
    auto_create_user: provider?.auto_create_user ?? true,
    trust_email_verified: provider?.trust_email_verified ?? true,
    sync_profile: provider?.sync_profile ?? true,
    icon_url: provider?.icon_url || '',
    button_text: provider?.button_text || '',
  });
  const [isSaving, setIsSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async () => {
    setError(null);
    if (!form.name || !form.slug || !form.auth_url || !form.token_url || !form.userinfo_url || !form.client_id) {
      setError(t('admin.federation.requiredFields'));
      return;
    }
    if (!provider && !form.client_secret) {
      setError(t('admin.federation.secretRequired'));
      return;
    }
    setIsSaving(true);
    try {
      await onSave(form);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : t('admin.federation.saveFailed'));
    }
    setIsSaving(false);
  };

  const updateForm = (field: keyof CreateFederationProviderRequest, value: string | boolean) => {
    setForm(prev => ({ ...prev, [field]: value }));
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Globe className="h-5 w-5" />
          {provider ? t('admin.federation.editProvider') : t('admin.federation.addProviderTitle')}
        </CardTitle>
        <CardDescription>
          {t('admin.federation.formDescription')}
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        {error && (
          <div className="flex items-center gap-2 p-3 bg-red-50 dark:bg-red-950/30 text-red-600 dark:text-red-400 rounded-lg text-sm">
            <AlertCircle className="h-4 w-4 flex-shrink-0" />
            {error}
          </div>
        )}

        {/* 基本信息 */}
        <div className="space-y-4">
          <h3 className="text-sm font-semibold text-muted-foreground uppercase tracking-wider">{t('admin.federation.basicInfo')}</h3>
          <div className="grid gap-4 md:grid-cols-2">
            <div className="space-y-2">
              <Label>{t('admin.federation.name')} *</Label>
              <Input
                value={form.name}
                onChange={(e) => updateForm('name', e.target.value)}
                placeholder={t('admin.federation.namePlaceholder')}
              />
            </div>
            <div className="space-y-2">
              <Label>{t('admin.federation.slug')} *</Label>
              <Input
                value={form.slug}
                onChange={(e) => updateForm('slug', e.target.value.toLowerCase().replace(/[^a-z0-9-]/g, ''))}
                placeholder={t('admin.federation.slugPlaceholder')}
                disabled={!!provider}
              />
            </div>
          </div>
          <div className="space-y-2">
            <Label>{t('admin.federation.descriptionLabel')}</Label>
            <Input
              value={form.description || ''}
              onChange={(e) => updateForm('description', e.target.value)}
              placeholder={t('admin.federation.descriptionPlaceholder')}
            />
          </div>
        </div>

        {/* OAuth2 配置 */}
        <div className="space-y-4">
          <h3 className="text-sm font-semibold text-muted-foreground uppercase tracking-wider">{t('admin.federation.oauthEndpoints')}</h3>
          <div className="space-y-2">
            <Label>{t('admin.federation.authUrl')} *</Label>
            <Input
              value={form.auth_url}
              onChange={(e) => updateForm('auth_url', e.target.value)}
              placeholder="https://provider.com/oauth/authorize"
            />
          </div>
          <div className="space-y-2">
            <Label>{t('admin.federation.tokenUrl')} *</Label>
            <Input
              value={form.token_url}
              onChange={(e) => updateForm('token_url', e.target.value)}
              placeholder="https://provider.com/oauth/token"
            />
          </div>
          <div className="space-y-2">
            <Label>{t('admin.federation.userinfoUrl')} *</Label>
            <Input
              value={form.userinfo_url}
              onChange={(e) => updateForm('userinfo_url', e.target.value)}
              placeholder="https://provider.com/userinfo"
            />
          </div>
          <div className="grid gap-4 md:grid-cols-2">
            <div className="space-y-2">
              <Label>Client ID *</Label>
              <Input
                value={form.client_id}
                onChange={(e) => updateForm('client_id', e.target.value)}
                placeholder="OAuth2 Client ID"
              />
            </div>
            <div className="space-y-2">
              <Label>{t('admin.federation.clientSecret')} {provider ? '' : '*'}</Label>
              <Input
                type="password"
                value={form.client_secret}
                onChange={(e) => updateForm('client_secret', e.target.value)}
                placeholder={provider ? t('admin.federation.clientSecretEditPlaceholder') : 'OAuth2 Client Secret'}
              />
            </div>
          </div>
          <div className="space-y-2">
            <Label>{t('admin.federation.scopes')}</Label>
            <Input
              value={form.scopes || ''}
              onChange={(e) => updateForm('scopes', e.target.value)}
              placeholder={t('admin.federation.scopesPlaceholder')}
            />
          </div>
        </div>

        {/* 显示配置 */}
        <div className="space-y-4">
          <h3 className="text-sm font-semibold text-muted-foreground uppercase tracking-wider">{t('admin.federation.displayConfig')}</h3>
          <div className="grid gap-4 md:grid-cols-2">
            <div className="space-y-2">
              <Label>{t('admin.federation.iconUrl')}</Label>
              <Input
                value={form.icon_url || ''}
                onChange={(e) => updateForm('icon_url', e.target.value)}
                placeholder="https://example.com/icon.svg"
              />
            </div>
            <div className="space-y-2">
              <Label>{t('admin.federation.buttonText')}</Label>
              <Input
                value={form.button_text || ''}
                onChange={(e) => updateForm('button_text', e.target.value)}
                placeholder={t('admin.federation.buttonTextPlaceholder')}
              />
            </div>
          </div>
        </div>

        {/* 功能开关 */}
        <div className="space-y-4">
          <h3 className="text-sm font-semibold text-muted-foreground uppercase tracking-wider">{t('admin.federation.featureSettings')}</h3>
          <div className="space-y-3">
            <div className="flex items-center justify-between p-3 rounded-lg border">
              <div>
                <p className="font-medium text-sm">{t('admin.federation.enableProvider')}</p>
                <p className="text-xs text-muted-foreground">{t('admin.federation.enableProviderDesc')}</p>
              </div>
              <Switch
                checked={form.enabled}
                onCheckedChange={(checked) => updateForm('enabled', checked)}
              />
            </div>
            <div className="flex items-center justify-between p-3 rounded-lg border">
              <div>
                <p className="font-medium text-sm">{t('admin.federation.autoCreateUser')}</p>
                <p className="text-xs text-muted-foreground">{t('admin.federation.autoCreateUserDesc')}</p>
              </div>
              <Switch
                checked={form.auto_create_user}
                onCheckedChange={(checked) => updateForm('auto_create_user', checked)}
              />
            </div>
            <div className="flex items-center justify-between p-3 rounded-lg border">
              <div>
                <p className="font-medium text-sm">{t('admin.federation.trustEmailVerified')}</p>
                <p className="text-xs text-muted-foreground">{t('admin.federation.trustEmailVerifiedDesc')}</p>
              </div>
              <Switch
                checked={form.trust_email_verified}
                onCheckedChange={(checked) => updateForm('trust_email_verified', checked)}
              />
            </div>
            <div className="flex items-center justify-between p-3 rounded-lg border">
              <div>
                <p className="font-medium text-sm">{t('admin.federation.syncProfile')}</p>
                <p className="text-xs text-muted-foreground">{t('admin.federation.syncProfileDesc')}</p>
              </div>
              <Switch
                checked={form.sync_profile}
                onCheckedChange={(checked) => updateForm('sync_profile', checked)}
              />
            </div>
          </div>
        </div>

        {/* 操作按钮 */}
        <div className="flex justify-end gap-3 pt-4 border-t">
          <Button variant="outline" onClick={onCancel}>
            <X className="mr-2 h-4 w-4" />
            {t('common.cancel')}
          </Button>
          <Button onClick={handleSubmit} disabled={isSaving}>
            {isSaving ? (
              <>
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                {t('admin.federation.saving')}
              </>
            ) : (
              <>
                <Check className="mr-2 h-4 w-4" />
                {provider ? t('admin.federation.update') : t('common.create')}
              </>
            )}
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

export default function FederationPage() {
  const { user } = useAuth();
  const { t } = useI18n();
  const [providers, setProviders] = useState<FederationProvider[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [editingProvider, setEditingProvider] = useState<FederationProvider | undefined>();
  const [deleteConfirm, setDeleteConfirm] = useState<string | null>(null);

  const loadProviders = useCallback(async () => {
    const response = await api.getAdminFederationProviders();
    if (response.success && response.data) {
      setProviders(response.data.providers || []);
    }
    setIsLoading(false);
  }, []);

  useEffect(() => {
    loadProviders();
  }, [loadProviders]);

  /* 非管理员重定向 */
  if (user?.role !== 'admin') {
    return (
      <div className="flex items-center justify-center py-12">
        <p className="text-muted-foreground">{t('common.noAccess')}</p>
      </div>
    );
  }

  const handleSave = async (data: CreateFederationProviderRequest) => {
    if (editingProvider) {
      const response = await api.updateFederationProvider(editingProvider.id, data);
      if (!response.success) {
        throw new Error(response.error?.message || t('admin.federation.updateFailed'));
      }
    } else {
      const response = await api.createFederationProvider(data);
      if (!response.success) {
        throw new Error(response.error?.message || t('admin.federation.createFailed'));
      }
    }
    setShowForm(false);
    setEditingProvider(undefined);
    await loadProviders();
  };

  const handleDelete = async (id: string) => {
    const response = await api.deleteFederationProvider(id);
    if (response.success) {
      setDeleteConfirm(null);
      await loadProviders();
    }
  };

  const handleEdit = (provider: FederationProvider) => {
    setEditingProvider(provider);
    setShowForm(true);
  };

  const handleCancel = () => {
    setShowForm(false);
    setEditingProvider(undefined);
  };

  if (showForm) {
    return (
      <div className="max-w-3xl mx-auto space-y-6">
        <PageHeader
          icon={Globe}
          title={editingProvider ? t('admin.federation.editProvider') : t('admin.federation.addProviderTitle')}
          description={t('admin.federation.editPageDesc')}
        />
        <ProviderForm
          provider={editingProvider}
          onSave={handleSave}
          onCancel={handleCancel}
        />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <PageHeader
          icon={Globe}
          title={t('admin.federation.title')}
          description={t('admin.federation.description')}
        />
        <Button onClick={() => setShowForm(true)}>
          <Plus className="mr-2 h-4 w-4" />
          {t('admin.federation.addProvider')}
        </Button>
      </div>

      {isLoading ? (
        <div className="space-y-4">
          {[...Array(3)].map((_, i) => (
            <Card key={i}>
              <CardContent className="p-6">
                <div className="flex items-center gap-4">
                  <Skeleton className="h-12 w-12 rounded-lg" />
                  <div className="flex-1">
                    <Skeleton className="h-5 w-32 mb-2" />
                    <Skeleton className="h-4 w-48" />
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      ) : providers.length === 0 ? (
        <Card>
          <CardContent className="py-12">
            <EmptyState
              icon={Globe}
              title={t('admin.federation.noProviders')}
              description={t('admin.federation.noProvidersDesc')}
              action={{
                label: t('admin.federation.addProvider'),
                onClick: () => setShowForm(true),
              }}
            />
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-4">
          {providers.map((provider) => (
            <Card key={provider.id} className="hover:shadow-md transition-shadow">
              <CardContent className="p-6">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-4">
                    <div className="h-12 w-12 rounded-lg bg-primary/10 flex items-center justify-center">
                      {provider.icon_url ? (
                        <img src={provider.icon_url} alt={provider.name} className="h-7 w-7" />
                      ) : (
                        <ExternalLink className="h-6 w-6 text-primary" />
                      )}
                    </div>
                    <div>
                      <div className="flex items-center gap-2">
                        <h3 className="font-semibold">{provider.name}</h3>
                        <Badge variant={provider.enabled ? 'default' : 'secondary'} className="text-xs">
                          {provider.enabled ? t('common.enabled') : t('common.disabled')}
                        </Badge>
                      </div>
                      <p className="text-sm text-muted-foreground mt-0.5">
                        {provider.description || provider.slug}
                      </p>
                      <div className="flex items-center gap-4 mt-2 text-xs text-muted-foreground">
                        <span>Slug: <code className="bg-muted px-1 rounded">{provider.slug}</code></span>
                        <span>Client ID: <code className="bg-muted px-1 rounded">{provider.client_id.slice(0, 16)}...</code></span>
                        {provider.auto_create_user && <Badge variant="outline" className="text-[10px]">{t('admin.federation.autoCreateUser')}</Badge>}
                        {provider.sync_profile && <Badge variant="outline" className="text-[10px]">{t('admin.federation.syncProfile')}</Badge>}
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <Button variant="ghost" size="sm" onClick={() => handleEdit(provider)}>
                      <Edit className="h-4 w-4" />
                    </Button>
                    {deleteConfirm === provider.id ? (
                      <div className="flex items-center gap-1">
                        <Button
                          variant="destructive"
                          size="sm"
                          onClick={() => handleDelete(provider.id)}
                        >
                          {t('common.confirm')}
                        </Button>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => setDeleteConfirm(null)}
                        >
                          {t('common.cancel')}
                        </Button>
                      </div>
                    ) : (
                      <Button
                        variant="ghost"
                        size="sm"
                        className="text-red-500 hover:text-red-600"
                        onClick={() => setDeleteConfirm(provider.id)}
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    )}
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}
