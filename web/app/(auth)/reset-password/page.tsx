'use client';

import { useState, useEffect, Suspense } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import Link from 'next/link';
import { useI18n } from '@/lib/i18n';
import { api } from '@/lib/api';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '@/components/ui/card';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Loader2, Lock, Shield, AlertCircle, ArrowLeft, CheckCircle, Eye, EyeOff } from 'lucide-react';
import { PasswordStrength } from '@/components/ui/password-strength';

function ResetPasswordForm() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const { t } = useI18n();
  
  const token = searchParams.get('token') || '';
  
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [isValidating, setIsValidating] = useState(true);
  const [isTokenValid, setIsTokenValid] = useState(false);
  const [userEmail, setUserEmail] = useState('');

  useEffect(() => {
    const validateToken = async () => {
      if (!token) {
        setIsValidating(false);
        setError(t('passwordReset.invalidToken'));
        return;
      }

      try {
        const response = await api.validateResetToken(token);
        if (response.success && response.data?.valid) {
          setIsTokenValid(true);
          setUserEmail(response.data.email || '');
        } else {
          setError(response.error?.message || t('passwordReset.invalidToken'));
        }
      } catch {
        setError(t('errors.networkError'));
      }
      setIsValidating(false);
    };

    validateToken();
  }, [token, t]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    if (password !== confirmPassword) {
      setError(t('auth.register.passwordMismatch'));
      return;
    }

    if (password.length < 8) {
      setError(t('passwordReset.passwordTooShort'));
      return;
    }

    setIsLoading(true);

    try {
      const response = await api.resetPassword(token, password);
      
      if (response.success) {
        setSuccess(true);
        setTimeout(() => {
          router.push('/login');
        }, 3000);
      } else {
        setError(response.error?.message || t('passwordReset.resetFailed'));
      }
    } catch {
      setError(t('errors.networkError'));
    }
    
    setIsLoading(false);
  };

  if (isValidating) {
    return (
      <div className="w-full max-w-md mx-auto">
        <div className="flex items-center justify-center min-h-[300px]">
          <div className="text-center">
            <Loader2 className="h-8 w-8 animate-spin text-primary mx-auto" />
            <p className="mt-2 text-sm text-muted-foreground">{t('passwordReset.validating')}</p>
          </div>
        </div>
      </div>
    );
  }

  if (!isTokenValid) {
    return (
      <div className="w-full max-w-md mx-auto animate-slide-up">
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center h-16 w-16 rounded-2xl bg-gradient-to-br from-red-500 to-red-600 shadow-xl shadow-red-500/30 mb-4">
            <AlertCircle className="h-8 w-8 text-white" />
          </div>
          <h1 className="text-2xl font-bold">{t('passwordReset.invalidLink')}</h1>
        </div>

        <Card className="shadow-xl border-0 bg-white/80 dark:bg-slate-900/80 backdrop-blur-xl">
          <CardContent className="pt-6">
            <p className="text-center text-muted-foreground mb-4">
              {error || t('passwordReset.linkExpiredOrInvalid')}
            </p>
          </CardContent>
          <CardFooter className="flex flex-col gap-4">
            <Link href="/forgot-password" className="w-full">
              <Button className="w-full">
                {t('passwordReset.requestNewLink')}
              </Button>
            </Link>
            <Link 
              href="/login" 
              className="text-sm text-center text-muted-foreground hover:text-primary transition-colors inline-flex items-center justify-center gap-1"
            >
              <ArrowLeft className="h-3 w-3" />
              {t('passwordReset.backToLogin')}
            </Link>
          </CardFooter>
        </Card>
      </div>
    );
  }

  if (success) {
    return (
      <div className="w-full max-w-md mx-auto animate-slide-up">
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center h-16 w-16 rounded-2xl bg-gradient-to-br from-green-500 to-green-600 shadow-xl shadow-green-500/30 mb-4">
            <CheckCircle className="h-8 w-8 text-white" />
          </div>
          <h1 className="text-2xl font-bold">{t('passwordReset.success')}</h1>
        </div>

        <Card className="shadow-xl border-0 bg-white/80 dark:bg-slate-900/80 backdrop-blur-xl">
          <CardContent className="pt-6">
            <p className="text-center text-muted-foreground mb-4">
              {t('passwordReset.successMessage')}
            </p>
            <p className="text-center text-sm text-muted-foreground">
              {t('passwordReset.redirecting')}
            </p>
          </CardContent>
          <CardFooter>
            <Link href="/login" className="w-full">
              <Button className="w-full">
                {t('passwordReset.goToLogin')}
              </Button>
            </Link>
          </CardFooter>
        </Card>
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
          <CardTitle className="text-xl font-bold text-center">{t('passwordReset.newPassword')}</CardTitle>
          <CardDescription className="text-center">
            {userEmail && (
              <span>{t('passwordReset.forAccount')} <strong>{userEmail}</strong></span>
            )}
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
            <div className="space-y-2">
              <Label htmlFor="password" className="text-sm font-medium">{t('passwordReset.newPasswordLabel')}</Label>
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
              <PasswordStrength password={password} />
              <p className="text-xs text-muted-foreground">{t('passwordReset.minLength')}</p>
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
                  {t('passwordReset.resetting')}
                </>
              ) : (
                t('passwordReset.resetButton')
              )}
            </Button>
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

export default function ResetPasswordPage() {
  return (
    <Suspense fallback={
      <div className="flex items-center justify-center min-h-[400px]">
        <div className="text-center">
          <Loader2 className="h-8 w-8 animate-spin text-primary mx-auto" />
          <p className="mt-2 text-sm text-muted-foreground animate-pulse">&nbsp;</p>
        </div>
      </div>
    }>
      <ResetPasswordForm />
    </Suspense>
  );
}
