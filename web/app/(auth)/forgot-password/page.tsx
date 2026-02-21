'use client';

import { useState } from 'react';
import Link from 'next/link';
import { useI18n } from '@/lib/i18n';
import { api } from '@/lib/api';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '@/components/ui/card';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Loader2, Mail, Shield, AlertCircle, ArrowLeft, CheckCircle } from 'lucide-react';

export default function ForgotPasswordPage() {
  const { t } = useI18n();
  
  const [email, setEmail] = useState('');
  const [error, setError] = useState('');
  const [success, setSuccess] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [devToken, setDevToken] = useState('');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setIsLoading(true);

    try {
      const response = await api.forgotPassword(email);
      
      if (response.success) {
        setSuccess(true);
        // In dev mode, token might be returned for testing
        if (response.data?.token) {
          setDevToken(response.data.token);
        }
      } else {
        setError(response.error?.message || t('passwordReset.requestFailed'));
      }
    } catch {
      setError(t('errors.networkError'));
    }
    
    setIsLoading(false);
  };

  if (success) {
    return (
      <div className="w-full max-w-md mx-auto animate-slide-up">
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center h-16 w-16 rounded-2xl bg-gradient-to-br from-green-500 to-green-600 shadow-xl shadow-green-500/30 mb-4">
            <CheckCircle className="h-8 w-8 text-white" />
          </div>
          <h1 className="text-2xl font-bold">{t('passwordReset.emailSent')}</h1>
        </div>

        <Card className="shadow-xl border-0 bg-white/80 dark:bg-slate-900/80 backdrop-blur-xl">
          <CardContent className="pt-6">
            <p className="text-center text-muted-foreground mb-4">
              {t('passwordReset.checkEmail')}
            </p>
            <p className="text-center text-sm text-muted-foreground">
              {t('passwordReset.emailSentTo')} <strong>{email}</strong>
            </p>
            
            {/* Dev mode: show token for testing */}
            {devToken && (
              <div className="mt-4 p-3 bg-yellow-50 dark:bg-yellow-900/20 rounded-lg border border-yellow-200 dark:border-yellow-800">
                <p className="text-xs text-yellow-800 dark:text-yellow-200 font-medium mb-1">
                  {t('passwordReset.devModeToken')}
                </p>
                <code className="text-xs break-all">{devToken}</code>
                <Link 
                  href={`/reset-password?token=${devToken}`}
                  className="block mt-2 text-xs text-primary hover:underline"
                >
                  {t('passwordReset.devModeResetLink')}
                </Link>
              </div>
            )}
          </CardContent>
          <CardFooter className="flex flex-col gap-4">
            <Link href="/login" className="w-full">
              <Button variant="outline" className="w-full">
                <ArrowLeft className="mr-2 h-4 w-4" />
                {t('passwordReset.backToLogin')}
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
          <CardTitle className="text-xl font-bold text-center">{t('passwordReset.title')}</CardTitle>
          <CardDescription className="text-center">
            {t('passwordReset.description')}
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
                  required
                  disabled={isLoading}
                />
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
                  {t('passwordReset.sending')}
                </>
              ) : (
                t('passwordReset.sendLink')
              )}
            </Button>
            
            <Link 
              href="/login" 
              className="text-sm text-center text-muted-foreground hover:text-primary transition-colors inline-flex items-center justify-center gap-1"
            >
              <ArrowLeft className="h-3 w-3" />
              {t('passwordReset.backToLogin')}
            </Link>
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
