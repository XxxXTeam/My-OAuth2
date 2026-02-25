'use client';

import { useEffect, useState } from 'react';
import { useRouter, usePathname } from 'next/navigation';
import Link from 'next/link';
import { useAuth } from '@/lib/auth-context';
import { useI18n, LanguageSwitcher } from '@/lib/i18n';
import { Button } from '@/components/ui/button';
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar';
import { Badge } from '@/components/ui/badge';
import { Separator } from '@/components/ui/separator';
import { 
  LayoutDashboard, 
  AppWindow, 
  User, 
  LogOut,
  Shield,
  Users,
  Activity,
  Settings,
  Menu,
  X,
  ChevronRight,
  Globe,
  Moon,
  Sun
} from 'lucide-react';
import { cn } from '@/lib/utils';

interface NavItemProps {
  href: string;
  icon: React.ElementType;
  label: string;
  isActive?: boolean;
  badge?: string;
  onClick?: () => void;
}

function NavItem({ href, icon: Icon, label, isActive, badge, onClick }: NavItemProps) {
  return (
    <Link href={href} onClick={onClick}>
      <div className={cn(
        "flex items-center gap-3 px-3 py-2.5 rounded-lg transition-all duration-200 group",
        isActive 
          ? "bg-primary text-primary-foreground shadow-md" 
          : "hover:bg-muted text-muted-foreground hover:text-foreground"
      )}>
        <Icon className={cn("h-5 w-5 transition-transform group-hover:scale-110", isActive && "text-primary-foreground")} />
        <span className="flex-1 font-medium">{label}</span>
        {badge && (
          <Badge variant={isActive ? "secondary" : "outline"} className="text-xs">
            {badge}
          </Badge>
        )}
        <ChevronRight className={cn(
          "h-4 w-4 opacity-0 -translate-x-2 transition-all",
          "group-hover:opacity-100 group-hover:translate-x-0",
          isActive && "opacity-100 translate-x-0"
        )} />
      </div>
    </Link>
  );
}

export default function DashboardLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const router = useRouter();
  const pathname = usePathname();
  const { user, isLoading, isAuthenticated, logout } = useAuth();
  const { t } = useI18n();
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [isDark, setIsDark] = useState(false);

  /* 前端构建ID，构建时由 next.config.ts 注入 */
  const frontendBuildId = process.env.NEXT_PUBLIC_BUILD_ID || 'dev';

  useEffect(() => {
    if (!isLoading && !isAuthenticated) {
      router.push('/login');
    }
  }, [isLoading, isAuthenticated, router]);

  // 路由变化时关闭移动端侧边栏
  useEffect(() => {
    setSidebarOpen(false);
  }, [pathname]);

  /* 初始化暗色模式状态（与 layout.tsx 内联脚本保持一致） */
  useEffect(() => {
    setIsDark(document.documentElement.classList.contains('dark'));
  }, []);

  /* 切换暗色模式：同步 DOM class + localStorage */
  const toggleDarkMode = () => {
    const next = !isDark;
    setIsDark(next);
    document.documentElement.classList.toggle('dark', next);
    localStorage.setItem('theme', next ? 'dark' : 'light');
  };

  const handleLogout = async () => {
    await logout();
    router.push('/login');
  };

  const isActive = (path: string) => pathname === path;

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-slate-50 to-slate-100 dark:from-slate-950 dark:to-slate-900">
        <div className="text-center animate-fade-in">
          <div className="relative">
            <div className="h-16 w-16 rounded-full border-4 border-primary/20 border-t-primary animate-spin mx-auto" />
            <Shield className="h-6 w-6 text-primary absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2" />
          </div>
          <p className="mt-4 text-muted-foreground">{t('common.loading')}</p>
        </div>
      </div>
    );
  }

  if (!isAuthenticated) {
    return null;
  }

  /* 普通用户导航 - 仅个人信息管理 */
  const navItems = [
    { href: '/dashboard', icon: LayoutDashboard, label: t('nav.dashboard') },
    { href: '/dashboard/profile', icon: User, label: t('nav.profile') },
    { href: '/dashboard/authorizations', icon: Shield, label: t('nav.authorizations') },
  ];

  /* 管理员专属导航 - 应用管理、用户管理、系统配置等 */
  const adminItems = [
    { href: '/dashboard/apps', icon: AppWindow, label: t('nav.applications') },
    { href: '/dashboard/admin', icon: Users, label: t('nav.users') },
    { href: '/dashboard/admin/logs', icon: Activity, label: t('nav.loginLogs') },
    { href: '/dashboard/admin/federation', icon: Globe, label: t('nav.federation') },
    { href: '/dashboard/events', icon: Activity, label: t('nav.liveEvents') },
    { href: '/dashboard/admin/system', icon: Settings, label: t('nav.systemConfig') },
  ];

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-white to-slate-100 dark:from-slate-950 dark:via-slate-900 dark:to-slate-950">
      {/* Mobile header */}
      <header className="lg:hidden fixed top-0 left-0 right-0 z-50 h-16 border-b bg-white/80 dark:bg-slate-950/80 backdrop-blur-lg">
        <div className="flex items-center justify-between h-full px-4">
          <button 
            onClick={() => setSidebarOpen(true)}
            className="p-2 rounded-lg hover:bg-muted transition-colors"
          >
            <Menu className="h-6 w-6" />
          </button>
          <div className="flex items-center gap-2">
            <Shield className="h-6 w-6 text-primary" />
            <span className="font-bold text-lg">OAuth2</span>
          </div>
          <Avatar className="h-8 w-8">
            <AvatarImage src={user?.avatar} />
            <AvatarFallback className="bg-primary/10 text-primary text-sm">
              {user?.username?.charAt(0).toUpperCase()}
            </AvatarFallback>
          </Avatar>
        </div>
      </header>

      {/* Mobile sidebar overlay */}
      {sidebarOpen && (
        <div 
          className="lg:hidden fixed inset-0 z-50 bg-black/50 backdrop-blur-sm animate-fade-in"
          onClick={() => setSidebarOpen(false)}
        />
      )}

      {/* Sidebar */}
      <aside className={cn(
        "fixed top-0 left-0 z-50 h-screen w-72 border-r bg-white dark:bg-slate-950 dark:border-slate-800 transition-transform duration-300 ease-in-out",
        "lg:translate-x-0",
        sidebarOpen ? "translate-x-0" : "-translate-x-full"
      )}>
        <div className="flex h-full flex-col">
          {/* Logo */}
          <div className="flex h-16 items-center justify-between px-6 border-b dark:border-slate-800">
            <div className="flex items-center gap-2">
              <div className="h-9 w-9 rounded-xl bg-gradient-to-br from-primary to-primary/70 flex items-center justify-center shadow-lg shadow-primary/20">
                <Shield className="h-5 w-5 text-primary-foreground" />
              </div>
              <div>
                <span className="text-lg font-bold">OAuth2</span>
                <p className="text-[10px] text-muted-foreground -mt-0.5">{t('common.brandSubtitle')}</p>
              </div>
            </div>
            <button 
              onClick={() => setSidebarOpen(false)}
              className="lg:hidden p-1.5 rounded-lg hover:bg-muted transition-colors"
            >
              <X className="h-5 w-5" />
            </button>
          </div>

          {/* Navigation */}
          <nav className="flex-1 overflow-y-auto p-4 space-y-1 hide-scrollbar">
            <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider px-3 mb-2">
              {t('common.menu')}
            </p>
            {navItems.map((item) => (
              <NavItem
                key={item.href}
                {...item}
                isActive={isActive(item.href)}
                onClick={() => setSidebarOpen(false)}
              />
            ))}

            {user?.role === 'admin' && (
              <>
                <Separator className="my-4" />
                <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider px-3 mb-2">
                  {t('common.admin')}
                </p>
                {adminItems.map((item) => (
                  <NavItem
                    key={item.href}
                    {...item}
                    isActive={isActive(item.href)}
                    onClick={() => setSidebarOpen(false)}
                  />
                ))}
              </>
            )}
          </nav>

          {/* User section */}
          <div className="border-t dark:border-slate-800 p-4">
            <div className="flex items-center gap-3 mb-4 p-3 rounded-xl bg-muted/50">
              <Avatar className="h-11 w-11 ring-2 ring-primary/20">
                <AvatarImage src={user?.avatar} />
                <AvatarFallback className="bg-gradient-to-br from-primary to-primary/70 text-primary-foreground font-semibold">
                  {user?.username?.charAt(0).toUpperCase()}
                </AvatarFallback>
              </Avatar>
              <div className="flex-1 min-w-0">
                <p className="text-sm font-semibold truncate">{user?.nickname || user?.username}</p>
                <p className="text-xs text-muted-foreground truncate">{user?.email}</p>
              </div>
              {user?.role === 'admin' && (
                <Badge variant="secondary" className="text-[10px]">Admin</Badge>
              )}
            </div>
            <div className="grid grid-cols-3 gap-2">
              <Button 
                variant="outline" 
                size="sm"
                className="text-red-500 hover:text-red-600 hover:bg-red-50 dark:hover:bg-red-950/30"
                onClick={handleLogout}
              >
                <LogOut className="mr-1.5 h-4 w-4" />
                {t('nav.signOut')}
              </Button>
              <LanguageSwitcher />
              <Button
                variant="outline"
                size="sm"
                onClick={toggleDarkMode}
                title={isDark ? 'Light Mode' : 'Dark Mode'}
              >
                {isDark ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
              </Button>
            </div>
            <p className="text-[10px] text-muted-foreground text-center mt-3 font-mono">
              Build {frontendBuildId}
            </p>
          </div>
        </div>
      </aside>

      {/* Main content */}
      <main className="lg:pl-72 pt-16 lg:pt-0 min-h-screen">
        <div key={pathname} className="p-4 sm:p-6 lg:p-8 animate-slide-up">
          {children}
        </div>
      </main>
    </div>
  );
}
