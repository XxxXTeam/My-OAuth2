'use client';

import { useState, useCallback, useEffect } from 'react';
import { api } from '@/lib/api';
import { useI18n } from '@/lib/i18n';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { 
  Webhook, 
  Plus, 
  Trash2, 
  Send, 
  CheckCircle, 
  XCircle,
  Loader2,
  ChevronDown,
  ChevronUp,
  RefreshCw
} from 'lucide-react';
import type { Webhook as WebhookType, WebhookDelivery } from '@/lib/types';

interface WebhookManagerProps {
  appId: string;
}

const WEBHOOK_EVENTS = [
  'user.registered',
  'user.login',
  'user.updated',
  'oauth.authorized',
  'oauth.revoked',
  'token.issued',
  'token.refreshed',
];

export function WebhookManager({ appId }: WebhookManagerProps) {
  const { t, dateLocale } = useI18n();
  const [webhooks, setWebhooks] = useState<WebhookType[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [expandedWebhook, setExpandedWebhook] = useState<string | null>(null);
  const [deliveries, setDeliveries] = useState<Record<string, WebhookDelivery[]>>({});
  const [isSaving, setIsSaving] = useState(false);
  const [testingId, setTestingId] = useState<string | null>(null);

  // Form state
  const [formData, setFormData] = useState({
    url: '',
    secret: '',
    events: [] as string[],
  });

  const loadWebhooks = useCallback(async () => {
    const response = await api.getWebhooks(appId);
    if (response.success && response.data) {
      setWebhooks(response.data);
    }
    setIsLoading(false);
  }, [appId]);

  useEffect(() => {
    loadWebhooks();
  }, [loadWebhooks]);

  const [loadingDeliveries, setLoadingDeliveries] = useState<string | null>(null);
  const [testResult, setTestResult] = useState<{ webhookId: string; success: boolean; time: number } | null>(null);

  const loadDeliveries = useCallback(async (webhookId: string) => {
    setLoadingDeliveries(webhookId);
    try {
      const response = await api.getWebhookDeliveries(appId, webhookId);
      if (response.success && response.data) {
        setDeliveries(prev => ({ ...prev, [webhookId]: response.data!.deliveries || [] }));
      } else {
        setDeliveries(prev => ({ ...prev, [webhookId]: [] }));
      }
    } catch {
      setDeliveries(prev => ({ ...prev, [webhookId]: [] }));
    }
    setLoadingDeliveries(null);
  }, [appId]);

  const handleToggleExpand = (webhookId: string) => {
    if (expandedWebhook === webhookId) {
      setExpandedWebhook(null);
    } else {
      setExpandedWebhook(webhookId);
      if (!deliveries[webhookId]) {
        loadDeliveries(webhookId);
      }
    }
  };

  const handleEventToggle = (event: string) => {
    if (event === '*') {
      // Toggle all: if all selected, deselect all; otherwise select all
      setFormData(prev => ({
        ...prev,
        events: prev.events.length === WEBHOOK_EVENTS.length ? [] : [...WEBHOOK_EVENTS]
      }));
      return;
    }
    setFormData(prev => ({
      ...prev,
      events: prev.events.includes(event)
        ? prev.events.filter(e => e !== event)
        : [...prev.events, event]
    }));
  };

  const handleSubmit = async () => {
    if (!formData.url || formData.events.length === 0) return;

    setIsSaving(true);
    const response = await api.createWebhook(appId, {
      url: formData.url,
      secret: formData.secret || undefined,
      events: formData.events.join(','),
    });

    if (response.success) {
      await loadWebhooks();
      setShowForm(false);
      setFormData({ url: '', secret: '', events: [] });
    }
    setIsSaving(false);
  };

  const handleDelete = async (webhookId: string) => {
    if (!confirm(t('webhooks.confirmDelete'))) return;

    const response = await api.deleteWebhook(appId, webhookId);
    if (response.success) {
      setWebhooks(webhooks.filter(w => w.id !== webhookId));
    }
  };

  const handleTest = useCallback(async (webhookId: string) => {
    setTestingId(webhookId);
    setTestResult(null);
    const startTime = performance.now();
    try {
      const response = await api.testWebhook(appId, webhookId);
      const elapsed = Math.round(performance.now() - startTime);
      setTestResult({ webhookId, success: response.success, time: elapsed });
      setTimeout(() => setTestResult(null), 3000);
      await loadDeliveries(webhookId);
    } catch {
      setTestResult({ webhookId, success: false, time: 0 });
      setTimeout(() => setTestResult(null), 3000);
    }
    setTestingId(null);
  }, [appId, loadDeliveries]);

  if (isLoading) {
    return (
      <div className="flex justify-center py-8">
        <Loader2 className="h-6 w-6 animate-spin" />
      </div>
    );
  }

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between">
        <div>
          <CardTitle className="flex items-center gap-2">
            <Webhook className="h-5 w-5" />
            {t('webhooks.title')}
          </CardTitle>
          <CardDescription>{t('webhooks.description')}</CardDescription>
        </div>
        <Button onClick={() => setShowForm(!showForm)} size="sm">
          <Plus className="h-4 w-4 mr-1" />
          {t('webhooks.add')}
        </Button>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Add Webhook Form */}
        {showForm && (
          <div className="border rounded-lg p-4 space-y-4 bg-slate-50 dark:bg-slate-900">
            <div className="space-y-2">
              <Label>{t('webhooks.url')}</Label>
              <Input
                placeholder="https://your-server.com/webhook"
                value={formData.url}
                onChange={(e) => setFormData(prev => ({ ...prev, url: e.target.value }))}
              />
            </div>
            <div className="space-y-2">
              <Label>{t('webhooks.secret')}</Label>
              <Input
                type="password"
                placeholder={t('webhooks.secretPlaceholder')}
                value={formData.secret}
                onChange={(e) => setFormData(prev => ({ ...prev, secret: e.target.value }))}
              />
            </div>
            <div className="space-y-2">
              <Label>{t('webhooks.events')}</Label>
              <div className="flex flex-wrap gap-2">
                <button
                  type="button"
                  onClick={() => handleEventToggle('*')}
                  className={`px-3 py-1 text-sm rounded-full border transition-colors font-medium ${
                    formData.events.length === WEBHOOK_EVENTS.length
                      ? 'bg-primary text-primary-foreground border-primary'
                      : 'bg-background hover:bg-slate-100 dark:hover:bg-slate-800'
                  }`}
                >
                  * {t('webhooks.selectAll')}
                </button>
                {WEBHOOK_EVENTS.map(event => (
                  <button
                    key={event}
                    type="button"
                    onClick={() => handleEventToggle(event)}
                    className={`px-3 py-1 text-sm rounded-full border transition-colors ${
                      formData.events.includes(event)
                        ? 'bg-primary text-primary-foreground border-primary'
                        : 'bg-background hover:bg-slate-100 dark:hover:bg-slate-800'
                    }`}
                  >
                    {event}
                  </button>
                ))}
              </div>
            </div>
            <div className="flex gap-2">
              <Button onClick={handleSubmit} disabled={isSaving}>
                {isSaving && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
                {t('common.save')}
              </Button>
              <Button variant="outline" onClick={() => setShowForm(false)}>
                {t('common.cancel')}
              </Button>
            </div>
          </div>
        )}

        {/* Webhooks List */}
        {webhooks.length === 0 ? (
          <div className="text-center py-8 text-muted-foreground">
            <Webhook className="h-12 w-12 mx-auto mb-4 opacity-50" />
            <p>{t('webhooks.empty')}</p>
          </div>
        ) : (
          <div className="space-y-3">
            {webhooks.map((webhook) => (
              <div key={webhook.id} className="border rounded-lg">
                <div className="flex items-center justify-between p-4">
                  <div className="flex items-center gap-3 flex-1 min-w-0">
                    <div className={`w-2 h-2 rounded-full ${webhook.active ? 'bg-green-500' : 'bg-slate-300'}`} />
                    <div className="min-w-0 flex-1">
                      <p className="font-medium truncate">{webhook.url}</p>
                      <p className="text-sm text-muted-foreground">
                        {webhook.events.split(',').length} {t('webhooks.eventsCount')}
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => handleTest(webhook.id)}
                      disabled={testingId === webhook.id}
                    >
                      {testingId === webhook.id ? (
                        <Loader2 className="h-4 w-4 animate-spin" />
                      ) : (
                        <Send className="h-4 w-4" />
                      )}
                    </Button>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => handleToggleExpand(webhook.id)}
                    >
                      {expandedWebhook === webhook.id ? (
                        <ChevronUp className="h-4 w-4" />
                      ) : (
                        <ChevronDown className="h-4 w-4" />
                      )}
                    </Button>
                    <Button
                      variant="outline"
                      size="sm"
                      className="text-red-500 hover:text-red-600"
                      onClick={() => handleDelete(webhook.id)}
                    >
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  </div>
                </div>

                {/* Test Result Toast */}
                {testResult && testResult.webhookId === webhook.id && (
                  <div className={`border-t p-3 flex items-center gap-2 ${testResult.success ? 'bg-green-50 dark:bg-green-950/30 text-green-700 dark:text-green-400' : 'bg-red-50 dark:bg-red-950/30 text-red-700 dark:text-red-400'}`}>
                    {testResult.success ? (
                      <CheckCircle className="h-4 w-4" />
                    ) : (
                      <XCircle className="h-4 w-4" />
                    )}
                    <span className="text-sm font-medium">
                      {testResult.success ? t('webhooks.testSuccess') : t('webhooks.testFailed')}
                    </span>
                    <span className="text-sm opacity-75">({testResult.time}ms)</span>
                  </div>
                )}

                {/* Deliveries */}
                {expandedWebhook === webhook.id && (
                  <div className="border-t p-4 bg-slate-50 dark:bg-slate-900">
                    <div className="flex items-center justify-between mb-3">
                      <h4 className="font-medium">{t('webhooks.recentDeliveries')}</h4>
                      <Button 
                        variant="ghost" 
                        size="sm"
                        onClick={() => loadDeliveries(webhook.id)}
                        disabled={loadingDeliveries === webhook.id}
                      >
                        <RefreshCw className={`h-4 w-4 ${loadingDeliveries === webhook.id ? 'animate-spin' : ''}`} />
                      </Button>
                    </div>
                    {loadingDeliveries === webhook.id ? (
                      <div className="flex justify-center py-4">
                        <Loader2 className="h-5 w-5 animate-spin" />
                      </div>
                    ) : !deliveries[webhook.id] || deliveries[webhook.id].length === 0 ? (
                      <p className="text-sm text-muted-foreground text-center py-4">
                        {t('webhooks.noDeliveries')}
                      </p>
                    ) : (
                      <div className="space-y-2">
                        {deliveries[webhook.id].slice(0, 10).map((delivery) => (
                          <div
                            key={delivery.id}
                            className="flex items-center justify-between text-sm p-2 bg-background rounded"
                          >
                            <div className="flex items-center gap-2">
                              {delivery.delivered ? (
                                <CheckCircle className="h-4 w-4 text-green-500" />
                              ) : (
                                <XCircle className="h-4 w-4 text-red-500" />
                              )}
                              <span className="font-mono text-xs">{delivery.event}</span>
                            </div>
                            <div className="flex items-center gap-3 text-muted-foreground text-xs">
                              <span className={delivery.status_code === 200 ? 'text-green-600' : 'text-red-500'}>
                                {delivery.status_code || '-'}
                              </span>
                              <span>{new Date(delivery.created_at).toLocaleString(dateLocale)}</span>
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
