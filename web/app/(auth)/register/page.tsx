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
import { Loader2, Mail, Lock, User, Shield, AlertCircle, ArrowRight, CheckCircle, XCircle, Ban, Eye, EyeOff } from 'lucide-react';
import { ProviderIcon } from '@/components/provider-icon';
import { PasswordStrength } from '@/components/ui/password-strength';
import type { FederationProvider, SocialProvider } from '@/lib/types';

function RegisterForm() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const { register, isAuthenticated, isLoading: authLoading } = useAuth();
  const { t } = useI18n();
  
  const [email, setEmail] = useState('');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [error, setError] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [registrationAllowed, setRegistrationAllowed] = useState<boolean | null>(null);
  const [checkingConfig, setCheckingConfig] = useState(true);
  const [success, setSuccess] = useState(false);
  const [federationProviders, setFederationProviders] = useState<FederationProvider[]>([]);
  const [socialProviders, setSocialProviders] = useState<SocialProvider[]>([]);
  const [redirectUrl, setRedirectUrl] = useState<string | null>(null);

  const returnTo = searchParams.get('return_to') || '/dashboard';

  /* 已登录用户自动跳转 */
  useEffect(() => {
    if (!authLoading && isAuthenticated) {
      router.replace(returnTo);
    }
  }, [authLoading, isAuthenticated, returnTo, router]);


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

  /* 检查注册是否开启 */
  useEffect(() => {
    const checkRegistration = async () => {
      try {
        const response = await api.getPublicConfig();
        if (response.success && response.data) {
          const allowed = response.data.allow_registration;
          setRegistrationAllowed(allowed === undefined || allowed === 'true' || allowed === '1');
        } else {
          setRegistrationAllowed(true);
        }
      } catch {
        setRegistrationAllowed(true);
      }
      setCheckingConfig(false);
    };
    checkRegistration();
  }, []);

  /* 外部跳转统一通过 useEffect 处理，避免直接赋值 window.location.href */
  useEffect(() => {
    if (redirectUrl) {
      window.location.href = redirectUrl;
    }
  }, [redirectUrl]);

  /* 处理第三方 OAuth 一键注册/登录 */
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

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    if (password !== confirmPassword) {
      setError(t('auth.register.passwordMismatch'));
      return;
    }

    if (password.length < 8) {
      setError(t('auth.register.passwordTooShort'));
      return;
    }

    setIsLoading(true);

    const result = await register(email, username, password);
    
    if (result.success) {
      setSuccess(true);
      setTimeout(() => router.push('/dashboard'), 1500);
    } else {
      setError(result.error || t('errors.unknownError'));
    }
    
    setIsLoading(false);
  };

  /* 加载中或已登录正在跳转 */
  if (checkingConfig || authLoading || isAuthenticated) {
    return (
      <div className="w-full max-w-md mx-auto">
        <div className="flex items-center justify-center min-h-[300px]">
          <Loader2 className="h-8 w-8 animate-spin text-primary" />
        </div>
      </div>
    );
  }

  /* 注册已关闭 */
  if (registrationAllowed === false) {
    return (
      <div className="w-full max-w-md mx-auto animate-slide-up">
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center h-16 w-16 rounded-2xl bg-gradient-to-br from-orange-500 to-orange-600 shadow-xl shadow-orange-500/30 mb-4">
            <Ban className="h-8 w-8 text-white" />
          </div>
          <h1 className="text-2xl font-bold">{t('auth.register.registrationDisabledTitle')}</h1>
        </div>
        <Card className="shadow-xl border-0 bg-white/80 dark:bg-slate-900/80 backdrop-blur-xl">
          <CardContent className="pt-6">
            <p className="text-center text-muted-foreground mb-4">
              {t('auth.register.registrationDisabledDesc')}
            </p>
          </CardContent>
          <CardFooter>
            <Link href="/login" className="w-full">
              <Button variant="outline" className="w-full">
                {t('passwordReset.backToLogin')}
              </Button>
            </Link>
          </CardFooter>
        </Card>
      </div>
    );
  }

  /* 注册成功 */
  if (success) {
    return (
      <div className="w-full max-w-md mx-auto animate-slide-up">
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center h-16 w-16 rounded-2xl bg-gradient-to-br from-green-500 to-green-600 shadow-xl shadow-green-500/30 mb-4">
            <CheckCircle className="h-8 w-8 text-white" />
          </div>
          <h1 className="text-2xl font-bold">{t('auth.register.success')}</h1>
        </div>
        <Card className="shadow-xl border-0 bg-white/80 dark:bg-slate-900/80 backdrop-blur-xl">
          <CardContent className="pt-6">
            <p className="text-center text-muted-foreground">
              {t('auth.register.successDesc')}
            </p>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="w-full max-w-md mx-auto animate-slide-up">
      {/* Logo */}
      <div className="text-center mb-8">
        <div className="inline-flex items-center justify-center h-16 w-16 rounded-2xl bg-gradient-to-br from-primary to-primary/70 shadow-xl shadow-primary/30 mb-4">
          <Shield className="h-8 w-8 text-primary-foreground" />
        </div>
        <h1 className="text-2xl font-bold">OAuth2</h1>
        <p className="text-sm text-muted-foreground">{t('common.brandSubtitle')}</p>
      </div>

      <Card className="shadow-xl border-0 bg-white/80 dark:bg-slate-900/80 backdrop-blur-xl">
        <CardHeader className="space-y-1 pb-4">
          <CardTitle className="text-xl font-bold text-center">{t('auth.register.title')}</CardTitle>
          <CardDescription className="text-center">
            {t('auth.register.description')}
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

            {/* 第三方 OAuth 一键注册按钮 */}
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
                      {provider.button_text || t('auth.register.signUpWith', { provider: provider.name })}
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
              <Label htmlFor="email" className="text-sm font-medium">{t('auth.register.email')}</Label>
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
              <Label htmlFor="username" className="text-sm font-medium">{t('auth.register.username')}</Label>
              <div className="relative group">
                <User className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground transition-colors group-focus-within:text-primary" />
                <Input
                  id="username"
                  type="text"
                  placeholder={t('auth.register.usernamePlaceholder')}
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  className="pl-10 h-11 bg-muted/50 border-muted focus:bg-background transition-colors"
                  autoComplete="username"
                  required
                  minLength={3}
                  maxLength={50}
                  disabled={isLoading}
                />
              </div>
            </div>
            <div className="space-y-2">
              <Label htmlFor="password" className="text-sm font-medium">{t('auth.register.password')}</Label>
              <div className="relative group">
                <Lock className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground transition-colors group-focus-within:text-primary" />
                <Input
                  id="password"
                  type={showPassword ? 'text' : 'password'}
                  placeholder="••••••••"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="pl-10 pr-10 h-11 bg-muted/50 border-muted focus:bg-background transition-colors"
                  autoComplete="new-password"
                  required
                  minLength={8}
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
              {/* 密码强度指示器（使用 PasswordStrength 组件） */}
              <PasswordStrength password={password} />
              <p className="text-xs text-muted-foreground">{t('auth.register.passwordHint')}</p>
            </div>
            <div className="space-y-2">
              <Label htmlFor="confirmPassword" className="text-sm font-medium">{t('auth.register.confirmPassword')}</Label>
              <div className="relative group">
                <Lock className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground transition-colors group-focus-within:text-primary" />
                <Input
                  id="confirmPassword"
                  type={showConfirmPassword ? 'text' : 'password'}
                  placeholder="••••••••"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  className="pl-10 pr-10 h-11 bg-muted/50 border-muted focus:bg-background transition-colors"
                  autoComplete="new-password"
                  required
                  disabled={isLoading}
                />
                <button
                  type="button"
                  tabIndex={-1}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground transition-colors"
                  onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                  aria-label={showConfirmPassword ? 'Hide password' : 'Show password'}
                >
                  {showConfirmPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </button>
              </div>
              {/* 密码匹配提示 */}
              {confirmPassword && (
                <p className={`text-xs flex items-center gap-1 animate-scale-in ${password === confirmPassword ? 'text-green-500' : 'text-red-500'}`}>
                  {password === confirmPassword ? <CheckCircle className="h-3 w-3" /> : <XCircle className="h-3 w-3" />}
                  {password === confirmPassword ? t('common.success') : t('auth.register.passwordMismatch')}
                </p>
              )}
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
                  {t('auth.register.submitting')}
                </>
              ) : (
                <>
                  {t('auth.register.submit')}
                  <ArrowRight className="ml-2 h-4 w-4" />
                </>
              )}
            </Button>
            <p className="text-sm text-center text-muted-foreground">
              {t('auth.register.hasAccount')}{' '}
              <Link href="/login" className="text-primary hover:underline font-semibold">
                {t('auth.register.signIn')}
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

export default function RegisterPage() {
  return (
    <Suspense fallback={
      <div className="flex items-center justify-center min-h-[400px]">
        <div className="text-center">
          <Loader2 className="h-8 w-8 animate-spin text-primary mx-auto" />
          <p className="mt-2 text-sm text-muted-foreground animate-pulse">&nbsp;</p>
        </div>
      </div>
    }>
      <RegisterForm />
    </Suspense>
  );
}
