'use client';

import { useEffect, useState, Suspense } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import { useAuth } from '@/lib/auth-context';
import { useI18n } from '@/lib/i18n';
import { Loader2, CheckCircle, AlertCircle } from 'lucide-react';

function CallbackHandler() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const { refreshUser } = useAuth();
  const { t } = useI18n();
  const [status, setStatus] = useState<'processing' | 'success' | 'error'>('processing');
  const [message, setMessage] = useState('');

  useEffect(() => {
    const handleCallback = async () => {
      const accessToken = searchParams.get('access_token');
      const refreshToken = searchParams.get('refresh_token');
      const returnTo = searchParams.get('return_to') || '/dashboard';
      const error = searchParams.get('error');

      if (error) {
        setStatus('error');
        setMessage(getErrorMessage(error, t));
        setTimeout(() => {
          router.push('/login');
        }, 3000);
        return;
      }

      if (!accessToken || !refreshToken) {
        setStatus('error');
        setMessage(t('auth.callback.missingTokens'));
        setTimeout(() => {
          router.push('/login');
        }, 3000);
        return;
      }

      try {
        // Store tokens
        localStorage.setItem('access_token', accessToken);
        localStorage.setItem('refresh_token', refreshToken);

        // Refresh user info
        await refreshUser();

        setStatus('success');
        setMessage(t('auth.callback.success'));

        // Redirect to return URL
        setTimeout(() => {
          if (returnTo.startsWith('http://') || returnTo.startsWith('https://')) {
            window.location.href = returnTo;
          } else {
            router.push(returnTo);
          }
        }, 1000);
      } catch (err) {
        console.error('Callback error:', err);
        setStatus('error');
        setMessage(t('auth.callback.loginFailed'));
        setTimeout(() => {
          router.push('/login');
        }, 3000);
      }
    };

    handleCallback();
  }, [searchParams, router, refreshUser, t]);

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-slate-100 to-slate-200 dark:from-slate-900 dark:to-slate-800">
      <div className="text-center">
        {status === 'processing' && (
          <>
            <Loader2 className="h-12 w-12 animate-spin text-primary mx-auto" />
            <p className="mt-4 text-lg text-muted-foreground">{message || t('auth.callback.processing')}</p>
          </>
        )}
        {status === 'success' && (
          <>
            <div className="inline-flex items-center justify-center h-16 w-16 rounded-full bg-green-100 dark:bg-green-900/30 mb-4">
              <CheckCircle className="h-8 w-8 text-green-600 dark:text-green-400" />
            </div>
            <p className="text-lg font-medium text-green-600 dark:text-green-400">{message}</p>
          </>
        )}
        {status === 'error' && (
          <>
            <div className="inline-flex items-center justify-center h-16 w-16 rounded-full bg-red-100 dark:bg-red-900/30 mb-4">
              <AlertCircle className="h-8 w-8 text-red-600 dark:text-red-400" />
            </div>
            <p className="text-lg font-medium text-red-600 dark:text-red-400">{message}</p>
            <p className="mt-2 text-sm text-muted-foreground">{t('auth.callback.redirectingToLogin')}</p>
          </>
        )}
      </div>
    </div>
  );
}

/* getErrorMessage 使用 i18n key 映射错误码 */
function getErrorMessage(error: string, t: (key: string) => string): string {
  const keyMap: Record<string, string> = {
    oauth_denied: 'auth.callback.oauthDenied',
    invalid_state: 'auth.callback.invalidState',
    missing_code: 'auth.callback.missingCode',
    token_exchange_failed: 'auth.callback.tokenExchangeFailed',
    userinfo_failed: 'auth.callback.userinfoFailed',
    login_failed: 'auth.callback.loginError',
  };
  const key = keyMap[error];
  return key ? t(key) : t('auth.callback.unknownError');
}

export default function AuthCallbackPage() {
  return (
    <Suspense fallback={
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-slate-100 to-slate-200 dark:from-slate-900 dark:to-slate-800">
        <div className="text-center">
          <Loader2 className="h-12 w-12 animate-spin text-primary mx-auto" />
          <p className="mt-4 text-lg text-muted-foreground animate-pulse">&nbsp;</p>
        </div>
      </div>
    }>
      <CallbackHandler />
    </Suspense>
  );
}
