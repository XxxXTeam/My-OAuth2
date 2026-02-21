'use client';

import { useState, useEffect, Suspense } from 'react';
import { useSearchParams } from 'next/navigation';
import Link from 'next/link';
import { useI18n } from '@/lib/i18n';
import { api } from '@/lib/api';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardFooter } from '@/components/ui/card';
import { Loader2, CheckCircle, AlertCircle, ArrowLeft } from 'lucide-react';

function VerifyEmailContent() {
  const searchParams = useSearchParams();
  const { t } = useI18n();

  const token = searchParams.get('token') || '';

  const [status, setStatus] = useState<'loading' | 'success' | 'error'>('loading');
  const [errorMessage, setErrorMessage] = useState('');

  useEffect(() => {
    const verify = async () => {
      if (!token) {
        setStatus('error');
        setErrorMessage(t('verifyEmail.invalidToken'));
        return;
      }

      try {
        const response = await api.verifyEmail(token);
        if (response.success) {
          setStatus('success');
        } else {
          setStatus('error');
          setErrorMessage(response.error?.message || t('verifyEmail.failed'));
        }
      } catch {
        setStatus('error');
        setErrorMessage(t('errors.networkError'));
      }
    };

    verify();
  }, [token, t]);

  if (status === 'loading') {
    return (
      <div className="w-full max-w-md mx-auto">
        <div className="flex items-center justify-center min-h-[300px]">
          <div className="text-center">
            <Loader2 className="h-8 w-8 animate-spin text-primary mx-auto" />
            <p className="mt-2 text-sm text-muted-foreground">{t('verifyEmail.verifying')}</p>
          </div>
        </div>
      </div>
    );
  }

  if (status === 'success') {
    return (
      <div className="w-full max-w-md mx-auto animate-slide-up">
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center h-16 w-16 rounded-2xl bg-gradient-to-br from-green-500 to-green-600 shadow-xl shadow-green-500/30 mb-4">
            <CheckCircle className="h-8 w-8 text-white" />
          </div>
          <h1 className="text-2xl font-bold">{t('verifyEmail.success')}</h1>
        </div>

        <Card className="shadow-xl border-0 bg-white/80 dark:bg-slate-900/80 backdrop-blur-xl">
          <CardContent className="pt-6">
            <p className="text-center text-muted-foreground mb-4">
              {t('verifyEmail.successMessage')}
            </p>
          </CardContent>
          <CardFooter className="flex flex-col gap-4">
            <Link href="/dashboard/profile" className="w-full">
              <Button className="w-full">
                {t('verifyEmail.goToProfile')}
              </Button>
            </Link>
            <Link
              href="/login"
              className="text-sm text-center text-muted-foreground hover:text-primary transition-colors inline-flex items-center justify-center gap-1"
            >
              <ArrowLeft className="h-3 w-3" />
              {t('verifyEmail.goToLogin')}
            </Link>
          </CardFooter>
        </Card>
      </div>
    );
  }

  // Error state
  return (
    <div className="w-full max-w-md mx-auto animate-slide-up">
      <div className="text-center mb-8">
        <div className="inline-flex items-center justify-center h-16 w-16 rounded-2xl bg-gradient-to-br from-red-500 to-red-600 shadow-xl shadow-red-500/30 mb-4">
          <AlertCircle className="h-8 w-8 text-white" />
        </div>
        <h1 className="text-2xl font-bold">{t('verifyEmail.failed')}</h1>
      </div>

      <Card className="shadow-xl border-0 bg-white/80 dark:bg-slate-900/80 backdrop-blur-xl">
        <CardContent className="pt-6">
          <p className="text-center text-muted-foreground mb-4">
            {errorMessage || t('verifyEmail.invalidToken')}
          </p>
        </CardContent>
        <CardFooter className="flex flex-col gap-4">
          <Link href="/dashboard/profile" className="w-full">
            <Button className="w-full">
              {t('verifyEmail.goToProfile')}
            </Button>
          </Link>
          <Link
            href="/login"
            className="text-sm text-center text-muted-foreground hover:text-primary transition-colors inline-flex items-center justify-center gap-1"
          >
            <ArrowLeft className="h-3 w-3" />
            {t('verifyEmail.goToLogin')}
          </Link>
        </CardFooter>
      </Card>

      {/* Footer */}
      <p className="text-center text-xs text-muted-foreground mt-6">
        {t('common.poweredBy')}
      </p>
    </div>
  );
}

export default function VerifyEmailPage() {
  return (
    <Suspense fallback={
      <div className="flex items-center justify-center min-h-[400px]">
        <div className="text-center">
          <Loader2 className="h-8 w-8 animate-spin text-primary mx-auto" />
          <p className="mt-2 text-sm text-muted-foreground animate-pulse">&nbsp;</p>
        </div>
      </div>
    }>
      <VerifyEmailContent />
    </Suspense>
  );
}
