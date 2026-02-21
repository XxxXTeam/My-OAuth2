'use client';

import { useEffect, useState, useCallback } from 'react';
import { useI18n } from '@/lib/i18n';
import { api } from '@/lib/api';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { 
  AppWindow, 
  Loader2, 
  Shield, 
  X, 
  CheckCircle, 
  XCircle,
  AlertTriangle,
  Monitor,
  KeyRound,
  Code2
} from 'lucide-react';
import type { UserAuthorization } from '@/lib/types';

export default function AuthorizationsPage() {
  const { t, dateLocale } = useI18n();
  const [authorizations, setAuthorizations] = useState<UserAuthorization[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [revoking, setRevoking] = useState<string | null>(null);

  const loadAuthorizations = useCallback(async () => {
    setIsLoading(true);
    const response = await api.getUserAuthorizations();
    if (response.success && response.data) {
      setAuthorizations(response.data.authorizations || []);
    }
    setIsLoading(false);
  }, []);

  useEffect(() => {
    loadAuthorizations();
  }, [loadAuthorizations]);

  const handleRevoke = async (id: string) => {
    setRevoking(id);
    const response = await api.revokeAuthorization(id);
    if (response.success) {
      setAuthorizations(prev => prev.map(auth => 
        auth.id === id ? { ...auth, revoked: true } : auth
      ));
    }
    setRevoking(null);
  };

  const getGrantTypeInfo = (grantType?: string) => {
    switch (grantType) {
      case 'authorization_code':
        return { icon: Code2, label: t('authorizations.grantTypes.authorization_code'), color: 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400' };
      case 'device_code':
        return { icon: Monitor, label: t('authorizations.grantTypes.device_code'), color: 'bg-purple-100 text-purple-700 dark:bg-purple-900/30 dark:text-purple-400' };
      case 'client_credentials':
        return { icon: KeyRound, label: t('authorizations.grantTypes.client_credentials'), color: 'bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-400' };
      default:
        return { icon: AppWindow, label: t('authorizations.grantTypes.unknown'), color: 'bg-gray-100 text-gray-700 dark:bg-gray-900/30 dark:text-gray-400' };
    }
  };

  const activeAuths = authorizations.filter(a => !a.revoked);
  const revokedAuths = authorizations.filter(a => a.revoked);

  return (
    <div className="space-y-8">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold">{t('authorizations.title')}</h1>
        <p className="text-muted-foreground mt-1">
          {t('authorizations.description')}
        </p>
      </div>

      {isLoading ? (
        <div className="flex items-center justify-center py-12">
          <Loader2 className="h-8 w-8 animate-spin text-primary" />
        </div>
      ) : authorizations.length === 0 ? (
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-12">
            <Shield className="h-12 w-12 text-muted-foreground mb-4" />
            <h3 className="text-lg font-medium">{t('authorizations.noAuthorizations')}</h3>
            <p className="text-muted-foreground text-center mt-2">
              {t('authorizations.noAuthorizationsDesc')}
            </p>
          </CardContent>
        </Card>
      ) : (
        <>
          {/* Active Authorizations */}
          {activeAuths.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <CheckCircle className="h-5 w-5 text-green-500" />
                  {t('authorizations.active')}
                </CardTitle>
                <CardDescription>
                  {t('authorizations.activeDesc')}
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                {activeAuths.map((auth) => {
                  const grantInfo = getGrantTypeInfo(auth.grant_type);
                  const GrantIcon = grantInfo.icon;
                  return (
                  <div 
                    key={auth.id} 
                    className="flex items-center justify-between p-4 rounded-lg border hover:bg-slate-50 dark:hover:bg-slate-800 transition-colors"
                  >
                    <div className="flex items-center gap-4">
                      <div className="h-10 w-10 rounded-lg bg-primary/10 flex items-center justify-center">
                        <AppWindow className="h-5 w-5 text-primary" />
                      </div>
                      <div>
                        <div className="flex items-center gap-2">
                          <h4 className="font-medium">{auth.app?.name || t('common.unknownApp')}</h4>
                          <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium ${grantInfo.color}`}>
                            <GrantIcon className="h-3 w-3" />
                            {grantInfo.label}
                          </span>
                        </div>
                        <p className="text-sm text-muted-foreground">
                          {auth.scope?.split(' ').join(', ') || t('common.noScope')}
                        </p>
                        <p className="text-xs text-muted-foreground">
                          {t('authorizations.authorizedAt')}: {new Date(auth.authorized_at).toLocaleDateString(dateLocale)}
                        </p>
                      </div>
                    </div>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => handleRevoke(auth.id)}
                      disabled={revoking === auth.id}
                      className="text-red-500 hover:text-red-600 hover:bg-red-50"
                    >
                      {revoking === auth.id ? (
                        <Loader2 className="h-4 w-4 animate-spin" />
                      ) : (
                        <>
                          <X className="h-4 w-4 mr-1" />
                          {t('authorizations.revoke')}
                        </>
                      )}
                    </Button>
                  </div>
                  );
                })}
              </CardContent>
            </Card>
          )}

          {/* Revoked Authorizations */}
          {revokedAuths.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <XCircle className="h-5 w-5 text-red-500" />
                  {t('authorizations.revoked')}
                </CardTitle>
                <CardDescription>
                  {t('authorizations.revokedDesc')}
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                {revokedAuths.map((auth) => {
                  const grantInfo = getGrantTypeInfo(auth.grant_type);
                  const GrantIcon = grantInfo.icon;
                  return (
                  <div 
                    key={auth.id} 
                    className="flex items-center justify-between p-4 rounded-lg border bg-slate-50 dark:bg-slate-800/50 opacity-60"
                  >
                    <div className="flex items-center gap-4">
                      <div className="h-10 w-10 rounded-lg bg-slate-200 flex items-center justify-center">
                        <AppWindow className="h-5 w-5 text-slate-500" />
                      </div>
                      <div>
                        <div className="flex items-center gap-2">
                          <h4 className="font-medium">{auth.app?.name || t('common.unknownApp')}</h4>
                          <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium ${grantInfo.color}`}>
                            <GrantIcon className="h-3 w-3" />
                            {grantInfo.label}
                          </span>
                        </div>
                        <p className="text-sm text-muted-foreground">
                          {auth.scope?.split(' ').join(', ') || t('common.noScope')}
                        </p>
                        <p className="text-xs text-muted-foreground">
                          {t('authorizations.revokedAt')}: {auth.revoked_at ? new Date(auth.revoked_at).toLocaleDateString(dateLocale) : '-'}
                        </p>
                      </div>
                    </div>
                    <span className="text-sm text-muted-foreground flex items-center gap-1">
                      <AlertTriangle className="h-4 w-4" />
                      {t('authorizations.revokedStatus')}
                    </span>
                  </div>
                  );
                })}
              </CardContent>
            </Card>
          )}
        </>
      )}
    </div>
  );
}
