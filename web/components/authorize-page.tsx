'use client';

import { useEffect, useState, Suspense, useCallback } from 'react';
import { useSearchParams, useRouter } from 'next/navigation';
import { useAuth } from '@/lib/auth-context';
import { useI18n } from '@/lib/i18n';
import { api } from '@/lib/api';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '@/components/ui/card';
import { Loader2, Shield, Check, X, AlertCircle } from 'lucide-react';

/**
 * 共享的 OAuth 授权页面内容组件
 * @param basePath - 当前路由路径前缀，用于构建 returnUrl（如 '/oauth/authorize' 或 '/auth/authorize'）
 */
function AuthorizeContent({ basePath }: { basePath: string }) {
  const searchParams = useSearchParams();
  const router = useRouter();
  const { isAuthenticated, isLoading: authLoading } = useAuth();
  const { t } = useI18n();
  
  const [appInfo, setAppInfo] = useState<{ id: string; name: string; description: string } | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [redirectUrl, setRedirectUrl] = useState<string | null>(null);

  // OAuth parameters
  const clientId = searchParams.get('client_id');
  const redirectUri = searchParams.get('redirect_uri');
  const responseType = searchParams.get('response_type');
  const scope = searchParams.get('scope') || '';
  const state = searchParams.get('state') || '';
  const codeChallenge = searchParams.get('code_challenge') || '';
  const codeChallengeMethod = searchParams.get('code_challenge_method') || '';

  const loadAppInfo = useCallback(async () => {
    if (!clientId || !redirectUri || responseType !== 'code') {
      setError(t('oauth.authorize.invalidRequest'));
      setIsLoading(false);
      return;
    }

    const response = await api.getOAuthAppInfo(clientId, redirectUri);
    if (response.success && response.data) {
      setAppInfo(response.data.app);
    } else {
      setError(response.error?.message || t('oauth.authorize.loadFailed'));
    }
    setIsLoading(false);
  }, [clientId, redirectUri, responseType, t]);

  useEffect(() => {
    if (!authLoading && !isAuthenticated) {
      const returnUrl = `${basePath}?${searchParams.toString()}`;
      router.push(`/login?return_to=${encodeURIComponent(returnUrl)}`);
      return;
    }

    if (isAuthenticated) {
      loadAppInfo();
    }
  }, [authLoading, isAuthenticated, searchParams, router, loadAppInfo, basePath]);

  // Handle redirect in useEffect
  useEffect(() => {
    if (redirectUrl) {
      window.location.href = redirectUrl;
    }
  }, [redirectUrl]);

  const handleConsent = async (allow: boolean) => {
    if (!clientId || !redirectUri || !responseType) return;
    
    setIsSubmitting(true);
    
    try {
      const response = await api.submitOAuthAuthorize({
        client_id: clientId,
        redirect_uri: redirectUri,
        response_type: responseType,
        scope: scope || undefined,
        state: state || undefined,
        code_challenge: codeChallenge || undefined,
        code_challenge_method: codeChallengeMethod || undefined,
        consent: allow ? 'allow' : 'deny',
      });
      
      if (response.success && response.data?.redirect_url) {
        // Redirect to the callback URL with authorization code
        setRedirectUrl(response.data.redirect_url);
      } else {
        setError(response.error?.message || t('oauth.authorize.authFailed'));
        setIsSubmitting(false);
      }
    } catch {
      setError(t('oauth.authorize.error'));
      setIsSubmitting(false);
    }
  };

  const parseScopes = (scopeString: string): string[] => {
    if (!scopeString) return [];
    return scopeString.split(' ').filter(s => s.trim() !== '');
  };

  const getScopeDescription = (scope: string): string => {
    const key = `oauth.scopes.${scope}`;
    const translated = t(key);
    return translated !== key ? translated : scope;
  };

  if (authLoading || isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-slate-50 to-slate-100 dark:from-slate-900 dark:to-slate-800">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
      </div>
    );
  }

  if (error) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-slate-50 to-slate-100 dark:from-slate-900 dark:to-slate-800 p-4">
        <Card className="w-full max-w-md">
          <CardHeader className="text-center">
            <div className="flex justify-center mb-4">
              <div className="h-12 w-12 rounded-full bg-red-100 flex items-center justify-center">
                <AlertCircle className="h-6 w-6 text-red-500" />
              </div>
            </div>
            <CardTitle>{t('oauth.authorize.error')}</CardTitle>
            <CardDescription>{error}</CardDescription>
          </CardHeader>
          <CardFooter className="justify-center">
            <Button variant="outline" onClick={() => window.history.back()}>
              {t('errors.goBack')}
            </Button>
          </CardFooter>
        </Card>
      </div>
    );
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-slate-50 to-slate-100 dark:from-slate-900 dark:to-slate-800 p-4">
      <Card className="w-full max-w-md">
        <CardHeader className="text-center">
          <div className="flex justify-center mb-4">
            <div className="h-16 w-16 rounded-full bg-primary/10 flex items-center justify-center">
              <Shield className="h-8 w-8 text-primary" />
            </div>
          </div>
          <CardTitle className="text-xl">{t('oauth.authorize.title', { app: appInfo?.name || '' })}</CardTitle>
          <CardDescription>
            {appInfo?.description || t('oauth.authorize.description')}
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {scope && parseScopes(scope).length > 0 && (
            <div className="space-y-2">
              <p className="text-sm font-medium">{t('oauth.authorize.permissions')}</p>
              <ul className="space-y-2">
                {parseScopes(scope).map((s) => (
                  <li key={s} className="flex items-start gap-2 text-sm">
                    <Check className="h-4 w-4 text-green-500 mt-0.5 flex-shrink-0" />
                    <span>{getScopeDescription(s)}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
          
          <div className="text-xs text-muted-foreground bg-slate-100 dark:bg-slate-800 p-3 rounded-md">
            <p>{t('oauth.authorize.redirectTo')}</p>
            <p className="font-mono truncate mt-1">{redirectUri}</p>
          </div>
        </CardContent>
        <CardFooter className="flex gap-3">
          <Button
            variant="outline"
            className="flex-1"
            onClick={() => handleConsent(false)}
            disabled={isSubmitting}
          >
            <X className="mr-2 h-4 w-4" />
            {t('oauth.authorize.deny')}
          </Button>
          <Button
            className="flex-1"
            onClick={() => handleConsent(true)}
            disabled={isSubmitting}
          >
            {isSubmitting ? (
              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
            ) : (
              <Check className="mr-2 h-4 w-4" />
            )}
            {t('oauth.authorize.allow')}
          </Button>
        </CardFooter>
      </Card>
    </div>
  );
}

/**
 * 共享的授权页面包装组件，带 Suspense fallback
 */
export default function AuthorizePage({ basePath }: { basePath: string }) {
  return (
    <Suspense fallback={
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-slate-50 to-slate-100 dark:from-slate-900 dark:to-slate-800">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
      </div>
    }>
      <AuthorizeContent basePath={basePath} />
    </Suspense>
  );
}
