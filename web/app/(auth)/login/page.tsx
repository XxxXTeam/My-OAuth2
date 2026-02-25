'use client';

import { useState, useEffect, Suspense } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import Link from 'next/link';
import { useAuth } from '@/lib/auth-context';
import { useI18n } from '@/lib/i18n';
import { api } from '@/lib/api';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '@/components/ui/card';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Loader2, Mail, Lock, Shield, AlertCircle, ArrowRight, Sparkles, Eye, EyeOff } from 'lucide-react';
import { ProviderIcon } from '@/components/provider-icon';
import type { FederationProvider, SocialProvider } from '@/lib/types';

function LoginForm() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const { login, isAuthenticated, isLoading: authLoading } = useAuth();
  const { t } = useI18n();
  
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [federationProviders, setFederationProviders] = useState<FederationProvider[]>([]);
  const [socialProviders, setSocialProviders] = useState<SocialProvider[]>([]);
  const [redirectUrl, setRedirectUrl] = useState<string | null>(null);

  const returnTo = searchParams.get('return_to') || '/dashboard';

  /* 已登录用户自动跳转，无需重复登录 */
  useEffect(() => {
    if (!authLoading && isAuthenticated) {
      if (returnTo.startsWith('http://') || returnTo.startsWith('https://')) {
        setRedirectUrl(returnTo);
      } else {
        router.replace(returnTo);
      }
    }
  }, [authLoading, isAuthenticated, returnTo, router]);

  /* 外部跳转统一通过 useEffect 处理，避免直接赋值 window.location.href */
  useEffect(() => {
    if (redirectUrl) {
      window.location.href = redirectUrl;
    }
  }, [redirectUrl]);

  /* 加载可用的第三方登录提供商 */
  useEffect(() => {
    const loadProviders = async () => {
      const [fedRes, socialRes] = await Promise.all([
        api.getFederationProviders(),
        api.getSocialProviders(),
      ]);
      if (fedRes.success && fedRes.data) {
        setFederationProviders(fedRes.data.providers || []);
      }
      if (socialRes.success && socialRes.data) {
        setSocialProviders(socialRes.data.providers || []);
      }
    };
    loadProviders();
  }, []);

  /* 检查URL中的错误参数（社交登录回调失败） */
  useEffect(() => {
    const errorParam = searchParams.get('error');
    if (errorParam) {
      setError(decodeURIComponent(errorParam));
    }
  }, [searchParams]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setIsLoading(true);

    const result = await login(email, password);
    
    if (result.success) {
      if (returnTo.startsWith('http://') || returnTo.startsWith('https://')) {
        setRedirectUrl(returnTo);
      } else {
        router.push(returnTo);
      }
    } else {
      setError(result.error || t('auth.callback.loginFailed'));
    }
    
    setIsLoading(false);
  };

  /* 处理第三方 OAuth 一键登录 */
  const handleSocialLogin = (provider: string, type: 'federation' | 'social') => {
    if (type === 'federation') {
      setRedirectUrl(api.getFederationLoginUrl(provider, returnTo));
    } else {
      setRedirectUrl(api.getSocialLoginUrl(provider, returnTo));
    }
  };

  const allProviders = [
    ...socialProviders.map(p => ({ ...p, type: 'social' as const })),
    ...federationProviders.map(p => ({ slug: p.slug, name: p.name, icon_url: p.icon_url, button_text: p.button_text, type: 'federation' as const })),
  ];

  /* 正在检查登录状态或已登录正在跳转 */
  if (authLoading || isAuthenticated) {
    return (
      <div className="w-full max-w-md mx-auto flex items-center justify-center min-h-[400px]">
        <div className="text-center">
          <Loader2 className="h-8 w-8 animate-spin text-primary mx-auto" />
          <p className="mt-2 text-sm text-muted-foreground">
            {isAuthenticated ? t('auth.login.redirecting') : t('common.loading')}
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="w-full max-w-md mx-auto animate-slide-up">
      {/* Logo Section */}
      <div className="text-center mb-8">
        <div className="inline-flex items-center justify-center h-16 w-16 rounded-2xl bg-gradient-to-br from-primary to-primary/70 shadow-xl shadow-primary/30 mb-4">
          <Shield className="h-8 w-8 text-primary-foreground" />
        </div>
        <h1 className="text-2xl font-bold">OAuth2</h1>
        <p className="text-sm text-muted-foreground">{t('common.brandSubtitle')}</p>
      </div>

      <Card className="shadow-xl border-0 bg-white/80 dark:bg-slate-900/80 backdrop-blur-xl">
        <CardHeader className="space-y-1 pb-4">
          <CardTitle className="text-xl font-bold text-center">{t('auth.login.title')}</CardTitle>
          <CardDescription className="text-center">
            {t('auth.login.description')}
          </CardDescription>
        </CardHeader>
        <form onSubmit={handleSubmit}>
          <CardContent className="space-y-4">
            {error && (
              <Alert variant="destructive" className="animate-scale-in">
                <AlertCircle className="h-4 w-4" />
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            )}

            {/* 第三方 OAuth 一键登录按钮 */}
            {allProviders.length > 0 && (
              <div className="space-y-3">
                <div className="grid gap-2">
                  {allProviders.map((provider) => (
                    <Button
                      key={`${provider.type}-${provider.slug}`}
                      type="button"
                      variant="outline"
                      className="w-full h-11 gap-3 font-medium hover:bg-muted/80 transition-all"
                      onClick={() => handleSocialLogin(provider.slug, provider.type)}
                    >
                      <ProviderIcon slug={provider.slug} className="h-5 w-5" />
                      {provider.button_text || t('auth.login.signInWith').replace('{provider}', provider.name)}
                    </Button>
                  ))}
                </div>
                <div className="relative">
                  <div className="absolute inset-0 flex items-center">
                    <span className="w-full border-t" />
                  </div>
                  <div className="relative flex justify-center text-xs uppercase">
                    <span className="bg-card px-2 text-muted-foreground">
                      {t('auth.login.or')}
                    </span>
                  </div>
                </div>
              </div>
            )}

            <div className="space-y-2">
              <Label htmlFor="email" className="text-sm font-medium">{t('auth.login.email')}</Label>
              <div className="relative group">
                <Mail className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground transition-colors group-focus-within:text-primary" />
                <Input
                  id="email"
                  type="email"
                  placeholder="name@example.com"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="pl-10 h-11 bg-muted/50 border-muted focus:bg-background transition-colors"
                  autoComplete="email"
                  required
                  disabled={isLoading}
                />
              </div>
            </div>
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <Label htmlFor="password" className="text-sm font-medium">{t('auth.login.password')}</Label>
                <Link 
                  href="/forgot-password" 
                  className="text-xs text-muted-foreground hover:text-primary transition-colors"
                >
                  {t('auth.login.forgotPassword')}
                </Link>
              </div>
              <div className="relative group">
                <Lock className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground transition-colors group-focus-within:text-primary" />
                <Input
                  id="password"
                  type={showPassword ? 'text' : 'password'}
                  placeholder="••••••••"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="pl-10 pr-10 h-11 bg-muted/50 border-muted focus:bg-background transition-colors"
                  autoComplete="current-password"
                  required
                  disabled={isLoading}
                />
                <button
                  type="button"
                  tabIndex={-1}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground transition-colors"
                  onClick={() => setShowPassword(!showPassword)}
                  aria-label={showPassword ? 'Hide password' : 'Show password'}
                >
                  {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </button>
              </div>
            </div>
          </CardContent>
          <CardFooter className="flex flex-col gap-4 pt-2">
            <Button 
              type="submit" 
              className="w-full h-11 text-base font-medium shadow-lg shadow-primary/20 hover:shadow-xl hover:shadow-primary/30 transition-all" 
              disabled={isLoading}
            >
              {isLoading ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  {t('auth.login.submitting')}
                </>
              ) : (
                <>
                  {t('auth.login.submit')}
                  <ArrowRight className="ml-2 h-4 w-4" />
                </>
              )}
            </Button>
            
            {allProviders.length === 0 && (
              <div className="relative w-full">
                <div className="absolute inset-0 flex items-center">
                  <span className="w-full border-t" />
                </div>
                <div className="relative flex justify-center text-xs uppercase">
                  <span className="bg-card px-2 text-muted-foreground">
                    {t('auth.login.or')}
                  </span>
                </div>
              </div>
            )}

            <p className="text-sm text-center text-muted-foreground">
              {t('auth.login.noAccount')}{' '}
              <Link href="/register" className="text-primary hover:underline font-semibold inline-flex items-center gap-1">
                {t('auth.login.signUp')}
                <Sparkles className="h-3 w-3" />
              </Link>
            </p>
          </CardFooter>
        </form>
      </Card>

      {/* Footer */}
      <p className="text-center text-xs text-muted-foreground mt-6">
        {t('common.poweredBy')}
      </p>
    </div>
  );
}

export default function LoginPage() {
  return (
    <Suspense fallback={
      <div className="flex items-center justify-center min-h-[400px]">
        <div className="text-center">
          <Loader2 className="h-8 w-8 animate-spin text-primary mx-auto" />
          <p className="mt-2 text-sm text-muted-foreground animate-pulse">&nbsp;</p>
        </div>
      </div>
    }>
      <LoginForm />
    </Suspense>
  );
}
