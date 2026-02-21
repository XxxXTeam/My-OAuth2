'use client';

import { useEffect, useState, useCallback } from 'react';
import Link from 'next/link';
import { api } from '@/lib/api';
import { useI18n } from '@/lib/i18n';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { AppWindow, Plus, Trash2, ExternalLink, Loader2 } from 'lucide-react';
import type { Application } from '@/lib/types';

export default function AppsPage() {
  const { t, dateLocale } = useI18n();
  const [apps, setApps] = useState<Application[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [deletingId, setDeletingId] = useState<string | null>(null);

  const loadApps = useCallback(async () => {
    const response = await api.getApps();
    if (response.success && response.data) {
      setApps(response.data);
    }
    setIsLoading(false);
  }, []);

  useEffect(() => {
    loadApps();
  }, [loadApps]);

  const handleDelete = async (id: string) => {
    if (!confirm(t('apps.confirmDelete'))) {
      return;
    }

    setDeletingId(id);
    const response = await api.deleteApp(id);
    if (response.success) {
      setApps(apps.filter(app => app.id !== id));
    }
    setDeletingId(null);
  };

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl sm:text-3xl font-bold">{t('apps.title')}</h1>
          <p className="text-muted-foreground mt-1 text-sm sm:text-base">
            {t('apps.description')}
          </p>
        </div>
        <Link href="/dashboard/apps/new">
          <Button className="w-full sm:w-auto">
            <Plus className="mr-2 h-4 w-4" />
            {t('apps.new')}
          </Button>
        </Link>
      </div>

      {/* Apps List */}
      {isLoading ? (
        <div className="flex items-center justify-center py-12">
          <Loader2 className="h-8 w-8 animate-spin text-primary" />
        </div>
      ) : apps.length === 0 ? (
        <Card>
          <CardContent className="py-12">
            <div className="text-center">
              <AppWindow className="h-12 w-12 mx-auto text-muted-foreground mb-4" />
              <h3 className="text-lg font-medium">{t('apps.noApps')}</h3>
              <p className="text-muted-foreground mb-4">
                {t('apps.createFirst')}
              </p>
              <Link href="/dashboard/apps/new">
                <Button>
                  <Plus className="mr-2 h-4 w-4" />
                  {t('common.create')}
                </Button>
              </Link>
            </div>
          </CardContent>
        </Card>
      ) : (
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
          {apps.map((app) => (
            <Card key={app.id} className="hover:shadow-md transition-shadow">
              <CardHeader>
                <div className="flex items-start justify-between">
                  <div className="flex items-center gap-3">
                    <div className="h-10 w-10 rounded-lg bg-primary/10 flex items-center justify-center">
                      <AppWindow className="h-5 w-5 text-primary" />
                    </div>
                    <div>
                      <CardTitle className="text-lg">{app.name}</CardTitle>
                      <CardDescription className="text-xs font-mono">
                        {app.client_id}
                      </CardDescription>
                    </div>
                  </div>
                </div>
              </CardHeader>
              <CardContent>
                <p className="text-sm text-muted-foreground mb-4 line-clamp-2">
                  {app.description || t('apps.create.descriptionPlaceholder')}
                </p>
                <div className="flex items-center justify-between">
                  <span className="text-xs text-muted-foreground">
                    {t('apps.detail.created')} {new Date(app.created_at).toLocaleDateString(dateLocale)}
                  </span>
                  <div className="flex gap-2">
                    <Link href={`/dashboard/apps/${app.id}`}>
                      <Button variant="outline" size="sm">
                        <ExternalLink className="h-4 w-4" />
                      </Button>
                    </Link>
                    <Button 
                      variant="outline" 
                      size="sm"
                      className="text-red-500 hover:text-red-600 hover:bg-red-50"
                      onClick={() => handleDelete(app.id)}
                      disabled={deletingId === app.id}
                    >
                      {deletingId === app.id ? (
                        <Loader2 className="h-4 w-4 animate-spin" />
                      ) : (
                        <Trash2 className="h-4 w-4" />
                      )}
                    </Button>
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
