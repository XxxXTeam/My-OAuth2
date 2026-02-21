'use client';

import { useEffect, useState, useCallback } from 'react';
import { useAuth } from '@/lib/auth-context';
import { useI18n } from '@/lib/i18n';
import { api } from '@/lib/api';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Loader2, Save, Settings } from 'lucide-react';

export default function AdminConfigPage() {
  const { user } = useAuth();
  const { t } = useI18n();
  const [isLoading, setIsLoading] = useState(true);
  const [isSaving, setIsSaving] = useState(false);
  const [message, setMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  
  const [config, setConfig] = useState({
    frontend_url: '',
    server_url: '',
    site_name: '',
  });

  const loadConfig = useCallback(async () => {
    const response = await api.getAdminConfig();
    if (response.success && response.data) {
      setConfig({
        frontend_url: response.data.frontend_url || '',
        server_url: response.data.server_url || '',
        site_name: response.data.site_name || '',
      });
    }
    setIsLoading(false);
  }, []);

  useEffect(() => {
    loadConfig();
  }, [loadConfig]);

  const handleSave = async () => {
    setIsSaving(true);
    setMessage(null);
    
    const response = await api.setAdminConfig(config);
    if (response.success) {
      setMessage({ type: 'success', text: t('admin.config.saveSuccess') });
    } else {
      setMessage({ type: 'error', text: response.error?.message || t('admin.config.saveFailed') });
    }
    
    setIsSaving(false);
    setTimeout(() => setMessage(null), 3000);
  };

  if (user?.role !== 'admin') {
    return (
      <div className="flex items-center justify-center py-12">
        <p className="text-muted-foreground">{t('errors.forbidden')}</p>
      </div>
    );
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
      </div>
    );
  }

  return (
    <div className="max-w-2xl mx-auto space-y-8">
      {/* Header */}
      <div className="flex items-center gap-4">
        <div className="h-12 w-12 rounded-full bg-primary/10 flex items-center justify-center">
          <Settings className="h-6 w-6 text-primary" />
        </div>
        <div>
          <h1 className="text-3xl font-bold">{t('admin.config.title')}</h1>
          <p className="text-muted-foreground mt-1">{t('admin.config.description')}</p>
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

      {/* Config Form */}
      <Card>
        <CardHeader>
          <CardTitle>{t('admin.config.title')}</CardTitle>
          <CardDescription>{t('admin.config.description')}</CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          <div className="space-y-2">
            <Label htmlFor="frontend_url">{t('admin.config.frontendUrl')}</Label>
            <Input
              id="frontend_url"
              placeholder="http://localhost:3000"
              value={config.frontend_url}
              onChange={(e) => setConfig({ ...config, frontend_url: e.target.value })}
            />
            <p className="text-sm text-muted-foreground">
              {t('admin.config.frontendUrlDesc')}
            </p>
          </div>

          <div className="space-y-2">
            <Label htmlFor="server_url">{t('admin.config.serverUrl')}</Label>
            <Input
              id="server_url"
              placeholder="http://localhost:8080"
              value={config.server_url}
              onChange={(e) => setConfig({ ...config, server_url: e.target.value })}
            />
            <p className="text-sm text-muted-foreground">
              {t('admin.config.serverUrlDesc')}
            </p>
          </div>

          <div className="space-y-2">
            <Label htmlFor="site_name">{t('admin.config.siteName')}</Label>
            <Input
              id="site_name"
              placeholder="My OAuth2"
              value={config.site_name}
              onChange={(e) => setConfig({ ...config, site_name: e.target.value })}
            />
            <p className="text-sm text-muted-foreground">
              {t('admin.config.siteNameDesc')}
            </p>
          </div>

          <Button onClick={handleSave} disabled={isSaving}>
            {isSaving ? (
              <>
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                {t('common.loading')}
              </>
            ) : (
              <>
                <Save className="mr-2 h-4 w-4" />
                {t('common.save')}
              </>
            )}
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}
