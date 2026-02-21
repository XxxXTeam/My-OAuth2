'use client';

import { useEffect, useState, useCallback } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useAuth } from '@/lib/auth-context';
import { useI18n } from '@/lib/i18n';
import { api } from '@/lib/api';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { StatsCard } from '@/components/ui/stats-card';
import { PageHeader } from '@/components/ui/page-header';
import { EmptyState } from '@/components/ui/empty-state';
import { Skeleton } from '@/components/ui/skeleton';
import { OnboardingCard } from '@/components/onboarding';
import { 
  AppWindow, Plus, Key, Users, Activity, LayoutDashboard, ArrowRight, Clock,
  User, Shield, Mail, Calendar, Settings, ExternalLink, Monitor, KeyRound, Code2
} from 'lucide-react';
import type { Application, UserAuthorization } from '@/lib/types';

interface DashboardStats {
  total_apps: number;
  total_authorizations: number;
  active_tokens: number;
  unique_users: number;
}

/* 管理员仪表盘 - 显示应用管理和系统统计 */
function AdminDashboard() {
  const { user } = useAuth();
  const { t, dateLocale } = useI18n();
  const router = useRouter();
  const [apps, setApps] = useState<Application[]>([]);
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [statsLoading, setStatsLoading] = useState(true);

  const loadApps = useCallback(async () => {
    const response = await api.getApps();
    if (response.success && response.data) {
      setApps(response.data);
    }
    setIsLoading(false);
  }, []);

  const loadStats = useCallback(async () => {
    setStatsLoading(true);
    const response = await api.getDashboardStats();
    if (response.success && response.data) {
      setStats(response.data);
    }
    setStatsLoading(false);
  }, []);

  useEffect(() => {
    loadApps();
    loadStats();
  }, [loadApps, loadStats]);

  return (
    <div className="space-y-8">
      <PageHeader 
        icon={LayoutDashboard}
        title={t('dashboard.welcome', { name: user?.nickname || user?.username || '' })}
        description={t('dashboard.overview')}
      />

      <OnboardingCard />

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        {statsLoading ? (
          <>
            {[...Array(4)].map((_, i) => (
              <Card key={i}>
                <CardHeader className="pb-2">
                  <Skeleton className="h-4 w-24" />
                </CardHeader>
                <CardContent>
                  <Skeleton className="h-8 w-16 mb-2" />
                  <Skeleton className="h-3 w-20" />
                </CardContent>
              </Card>
            ))}
          </>
        ) : (
          <>
            <StatsCard
              title={t('dashboard.stats.totalApps')}
              value={stats?.total_apps ?? apps.length}
              description={`OAuth2 ${t('common.applications')}`}
              icon={AppWindow}
            />
            <StatsCard
              title={t('dashboard.stats.activeTokens')}
              value={stats?.active_tokens ?? 0}
              description={t('dashboard.stats.activeTokens')}
              icon={Key}
            />
            <StatsCard
              title={t('dashboard.stats.users')}
              value={stats?.unique_users ?? 0}
              description={t('common.authorized')}
              icon={Users}
            />
            <StatsCard
              title={t('dashboard.stats.apiCalls')}
              value={stats?.total_authorizations ?? 0}
              description={t('common.totalAuthorizations')}
              icon={Activity}
            />
          </>
        )}
      </div>

      <Card>
        <CardHeader className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <CardTitle className="flex items-center gap-2">
              <AppWindow className="h-5 w-5" />
              {t('dashboard.yourApps')}
            </CardTitle>
            <CardDescription>
              {t('dashboard.manageApps')}
            </CardDescription>
          </div>
          <Link href="/dashboard/apps/new">
            <Button className="w-full sm:w-auto">
              <Plus className="mr-2 h-4 w-4" />
              {t('dashboard.newApp')}
            </Button>
          </Link>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="space-y-4">
              {[...Array(3)].map((_, i) => (
                <div key={i} className="flex items-center gap-4 p-4 rounded-lg border">
                  <Skeleton className="h-10 w-10 rounded-lg" />
                  <div className="flex-1">
                    <Skeleton className="h-4 w-32 mb-2" />
                    <Skeleton className="h-3 w-48" />
                  </div>
                </div>
              ))}
            </div>
          ) : apps.length === 0 ? (
            <EmptyState
              icon={AppWindow}
              title={t('dashboard.noApps')}
              description={t('dashboard.createFirst')}
              action={{
                label: t('common.create'),
                onClick: () => router.push('/dashboard/apps/new'),
              }}
            />
          ) : (
            <div className="space-y-3">
              {apps.slice(0, 5).map((app) => (
                <Link key={app.id} href={`/dashboard/apps/${app.id}`}>
                  <div className="group flex items-center justify-between p-4 rounded-lg border hover:border-primary/50 hover:bg-primary/5 transition-all">
                    <div className="flex items-center gap-4">
                      <div className="h-10 w-10 rounded-lg bg-primary/10 flex items-center justify-center group-hover:bg-primary/20 transition-colors">
                        <AppWindow className="h-5 w-5 text-primary" />
                      </div>
                      <div>
                        <div className="flex items-center gap-2">
                          <h4 className="font-medium group-hover:text-primary transition-colors">
                            {app.name}
                          </h4>
                          <Badge variant="outline" className="text-[10px]">
                            OAuth2
                          </Badge>
                        </div>
                        <p className="text-sm text-muted-foreground font-mono">
                          {app.client_id.slice(0, 16)}...
                        </p>
                      </div>
                    </div>
                    <div className="flex items-center gap-3">
                      <div className="text-right hidden sm:block">
                        <div className="flex items-center gap-1 text-xs text-muted-foreground">
                          <Clock className="h-3 w-3" />
                          {new Date(app.created_at).toLocaleDateString(dateLocale)}
                        </div>
                      </div>
                      <ArrowRight className="h-4 w-4 text-muted-foreground opacity-0 group-hover:opacity-100 transition-opacity" />
                    </div>
                  </div>
                </Link>
              ))}
              {apps.length > 5 && (
                <Link href="/dashboard/apps" className="block">
                  <Button variant="outline" className="w-full">
                    {t('dashboard.viewAll')}
                    <ArrowRight className="ml-2 h-4 w-4" />
                  </Button>
                </Link>
              )}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

/* 普通用户仪表盘 - 显示个人信息概览和授权管理 */
function UserDashboard() {
  const { user } = useAuth();
  const { t, dateLocale } = useI18n();
  const [authorizations, setAuthorizations] = useState<UserAuthorization[]>([]);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    const loadAuthorizations = async () => {
      const response = await api.getUserAuthorizations();
      if (response.success && response.data) {
        setAuthorizations(response.data.authorizations || []);
      }
      setIsLoading(false);
    };
    loadAuthorizations();
  }, []);

  const activeAuths = authorizations.filter(a => !a.revoked);

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

  return (
    <div className="space-y-8">
      <PageHeader 
        icon={LayoutDashboard}
        title={t('dashboard.welcome', { name: user?.nickname || user?.username || '' })}
        description={t('dashboard.user.overview')}
      />

      {/* 用户信息概览 */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <StatsCard
          title={t('dashboard.user.authorizedApps')}
          value={activeAuths.length}
          description={t('dashboard.user.activeAuthorizations')}
          icon={Shield}
        />
        <StatsCard
          title={t('dashboard.user.emailStatus')}
          value={user?.email_verified ? t('dashboard.user.verified') : t('dashboard.user.unverified')}
          description={user?.email || ''}
          icon={Mail}
        />
        <StatsCard
          title={t('dashboard.user.profileStatus')}
          value={user?.profile_completed ? t('dashboard.user.profileCompleted') : t('dashboard.user.profileIncomplete')}
          description={user?.profile_completed ? t('dashboard.user.profileCompletedDesc') : t('dashboard.user.profileIncompleteDesc')}
          icon={User}
        />
        <StatsCard
          title={t('dashboard.user.accountCreated')}
          value={user?.created_at ? new Date(user.created_at).toLocaleDateString(dateLocale) : '-'}
          description={t('dashboard.user.registrationTime')}
          icon={Calendar}
        />
      </div>

      {/* 快捷操作 */}
      <div className="grid gap-4 grid-cols-1 sm:grid-cols-2 md:grid-cols-3">
        <Link href="/dashboard/profile">
          <Card className="group hover:border-primary/50 hover:shadow-md transition-all cursor-pointer h-full">
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-base group-hover:text-primary transition-colors">
                <User className="h-5 w-5" />
                {t('dashboard.user.editProfile')}
                <ArrowRight className="h-4 w-4 ml-auto opacity-0 group-hover:opacity-100 transition-opacity" />
              </CardTitle>
              <CardDescription>{t('dashboard.user.editProfileDesc')}</CardDescription>
            </CardHeader>
          </Card>
        </Link>
        <Link href="/dashboard/authorizations">
          <Card className="group hover:border-primary/50 hover:shadow-md transition-all cursor-pointer h-full">
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-base group-hover:text-primary transition-colors">
                <Shield className="h-5 w-5" />
                {t('dashboard.user.authManagement')}
                <ArrowRight className="h-4 w-4 ml-auto opacity-0 group-hover:opacity-100 transition-opacity" />
              </CardTitle>
              <CardDescription>{t('dashboard.user.authManagementDesc')}</CardDescription>
            </CardHeader>
          </Card>
        </Link>
        <Link href="/dashboard/profile">
          <Card className="group hover:border-primary/50 hover:shadow-md transition-all cursor-pointer h-full">
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-base group-hover:text-primary transition-colors">
                <Settings className="h-5 w-5" />
                {t('dashboard.user.securitySettings')}
                <ArrowRight className="h-4 w-4 ml-auto opacity-0 group-hover:opacity-100 transition-opacity" />
              </CardTitle>
              <CardDescription>{t('dashboard.user.securitySettingsDesc')}</CardDescription>
            </CardHeader>
          </Card>
        </Link>
      </div>

      {/* 最近授权的应用 */}
      <Card>
        <CardHeader className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <CardTitle className="flex items-center gap-2">
              <Shield className="h-5 w-5" />
              {t('dashboard.user.recentAuthorizations')}
            </CardTitle>
            <CardDescription>{t('dashboard.user.recentAuthorizationsDesc')}</CardDescription>
          </div>
          <Link href="/dashboard/authorizations">
            <Button variant="outline" size="sm" className="w-full sm:w-auto">
              {t('dashboard.viewAll')}
              <ArrowRight className="ml-2 h-4 w-4" />
            </Button>
          </Link>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="space-y-4">
              {[...Array(3)].map((_, i) => (
                <div key={i} className="flex items-center gap-4 p-4 rounded-lg border">
                  <Skeleton className="h-10 w-10 rounded-lg" />
                  <div className="flex-1">
                    <Skeleton className="h-4 w-32 mb-2" />
                    <Skeleton className="h-3 w-48" />
                  </div>
                </div>
              ))}
            </div>
          ) : activeAuths.length === 0 ? (
            <EmptyState
              icon={Shield}
              title={t('authorizations.noAuthorizations')}
              description={t('authorizations.noAuthorizationsDesc')}
            />
          ) : (
            <div className="space-y-3">
              {activeAuths.slice(0, 5).map((auth) => {
                const grantInfo = getGrantTypeInfo(auth.grant_type);
                const GrantIcon = grantInfo.icon;
                return (
                <div key={auth.id} className="flex items-center justify-between p-4 rounded-lg border">
                  <div className="flex items-center gap-4">
                    <div className="h-10 w-10 rounded-lg bg-primary/10 flex items-center justify-center">
                      <ExternalLink className="h-5 w-5 text-primary" />
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
                        {auth.scope || t('common.noScope')}
                      </p>
                    </div>
                  </div>
                  <div className="text-right">
                    <div className="flex items-center gap-1 text-xs text-muted-foreground">
                      <Clock className="h-3 w-3" />
                      {new Date(auth.authorized_at).toLocaleDateString(dateLocale)}
                    </div>
                  </div>
                </div>
                );
              })}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

export default function DashboardPage() {
  const { user } = useAuth();

  /* 根据用户角色显示不同的仪表盘 */
  if (user?.role === 'admin') {
    return <AdminDashboard />;
  }

  return <UserDashboard />;
}
