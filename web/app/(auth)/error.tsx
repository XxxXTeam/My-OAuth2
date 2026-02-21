'use client';

import { useEffect, useState } from 'react';
import { useI18n } from '@/lib/i18n';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardFooter, CardHeader, CardTitle } from '@/components/ui/card';
import { AlertTriangle, RefreshCw, ArrowLeft, Copy, Check, ChevronDown, ChevronUp } from 'lucide-react';
import Link from 'next/link';

/**
 * 认证路由段错误边界
 * 功能：捕获 login/register/callback 等认证页面的运行时错误，展示错误详情
 */
export default function AuthError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  const { t } = useI18n();
  const [copied, setCopied] = useState(false);
  const [showStack, setShowStack] = useState(false);

  useEffect(() => {
    console.error('Auth error:', error);
  }, [error]);

  const errorReport = [
    `Error: ${error.message}`,
    error.digest ? `Digest: ${error.digest}` : '',
    `Time: ${new Date().toISOString()}`,
    `URL: ${typeof window !== 'undefined' ? window.location.href : ''}`,
    error.stack ? `\nStack:\n${error.stack}` : '',
  ].filter(Boolean).join('\n');

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(errorReport);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      /* 剪贴板不可用时静默失败 */
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-slate-50 to-slate-100 dark:from-slate-900 dark:to-slate-800 px-4">
      <Card className="w-full max-w-lg">
        <CardHeader className="text-center">
          <div className="inline-flex items-center justify-center h-14 w-14 rounded-full bg-red-100 dark:bg-red-900/30 mx-auto mb-3">
            <AlertTriangle className="h-7 w-7 text-red-500" />
          </div>
          <CardTitle>{t('errors.somethingWentWrong')}</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <p className="text-muted-foreground text-sm text-center">
            {t('errors.somethingWentWrongDesc')}
          </p>

          <div className="p-3 bg-red-50 dark:bg-red-950/30 border border-red-200 dark:border-red-800 rounded-lg">
            <p className="text-sm font-medium text-red-700 dark:text-red-400 break-all">
              {error.message}
            </p>
            {error.digest && (
              <p className="text-xs text-red-500/70 mt-1 font-mono">ID: {error.digest}</p>
            )}
          </div>

          {error.stack && (
            <div>
              <button
                onClick={() => setShowStack(!showStack)}
                className="flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground transition-colors"
              >
                {showStack ? <ChevronUp className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />}
                {t('errors.stackTrace')}
              </button>
              {showStack && (
                <pre className="mt-2 p-3 bg-muted rounded-lg text-xs text-left overflow-auto max-h-48 whitespace-pre-wrap break-all font-mono leading-relaxed">
                  {error.stack}
                </pre>
              )}
            </div>
          )}
        </CardContent>
        <CardFooter className="flex flex-wrap gap-2 justify-center">
          <Button onClick={reset} size="sm">
            <RefreshCw className="mr-2 h-4 w-4" />
            {t('errors.tryAgain')}
          </Button>
          <Button variant="outline" size="sm" onClick={handleCopy}>
            {copied ? <Check className="mr-2 h-4 w-4" /> : <Copy className="mr-2 h-4 w-4" />}
            {copied ? t('errors.copied') : t('errors.copyError')}
          </Button>
          <Link href="/login">
            <Button variant="outline" size="sm">
              <ArrowLeft className="mr-2 h-4 w-4" />
              {t('auth.login.backToLogin')}
            </Button>
          </Link>
        </CardFooter>
      </Card>
    </div>
  );
}
