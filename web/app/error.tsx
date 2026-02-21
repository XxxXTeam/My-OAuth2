'use client';

import { useEffect, useState } from 'react';
import { useI18n } from '@/lib/i18n';
import { Button } from '@/components/ui/button';
import { AlertTriangle, RefreshCw, Home, Copy, Check, ChevronDown, ChevronUp } from 'lucide-react';
import Link from 'next/link';

export default function Error({
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
    console.error('Application error:', error);
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
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-slate-50 to-slate-100 dark:from-slate-900 dark:to-slate-800">
      <div className="px-4 w-full max-w-lg">
        <div className="text-center">
          <div className="inline-flex items-center justify-center h-16 w-16 rounded-full bg-red-100 dark:bg-red-900/30 mb-6">
            <AlertTriangle className="h-8 w-8 text-red-500" />
          </div>
          <h2 className="text-2xl font-semibold mt-4">{t('errors.somethingWentWrong')}</h2>
          <p className="text-muted-foreground mt-2">
            {t('errors.somethingWentWrongDesc')}
          </p>
        </div>

        {/* 错误信息摘要 */}
        <div className="mt-6 p-3 bg-red-50 dark:bg-red-950/30 border border-red-200 dark:border-red-800 rounded-lg">
          <p className="text-sm font-medium text-red-700 dark:text-red-400 break-all">
            {error.message}
          </p>
          {error.digest && (
            <p className="text-xs text-red-500/70 mt-1 font-mono">ID: {error.digest}</p>
          )}
        </div>

        {/* 堆栈详情（可展开） */}
        {error.stack && (
          <div className="mt-3">
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

        <div className="flex flex-wrap gap-3 justify-center mt-8">
          <Button onClick={reset}>
            <RefreshCw className="mr-2 h-4 w-4" />
            {t('errors.tryAgain')}
          </Button>
          <Button variant="outline" onClick={handleCopy}>
            {copied ? <Check className="mr-2 h-4 w-4" /> : <Copy className="mr-2 h-4 w-4" />}
            {copied ? t('errors.copied') : t('errors.copyError')}
          </Button>
          <Link href="/">
            <Button variant="outline">
              <Home className="mr-2 h-4 w-4" />
              {t('errors.goHome')}
            </Button>
          </Link>
        </div>
      </div>
    </div>
  );
}
