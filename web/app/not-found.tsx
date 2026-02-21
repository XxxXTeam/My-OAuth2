'use client';

import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useI18n } from '@/lib/i18n';
import { Button } from '@/components/ui/button';
import { Home, ArrowLeft } from 'lucide-react';

export default function NotFound() {
  const router = useRouter();
  const { t } = useI18n();

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-slate-50 to-slate-100 dark:from-slate-900 dark:to-slate-800">
      <div className="text-center px-4">
        <h1 className="text-9xl font-bold text-primary/20">404</h1>
        <h2 className="text-2xl font-semibold mt-4">{t('errors.notFound')}</h2>
        <p className="text-muted-foreground mt-2 max-w-md mx-auto">
          {t('errors.notFoundDesc')}
        </p>
        <div className="flex gap-4 justify-center mt-8">
          <Link href="/">
            <Button>
              <Home className="mr-2 h-4 w-4" />
              {t('errors.goHome')}
            </Button>
          </Link>
          <Button variant="outline" onClick={() => router.back()}>
            <ArrowLeft className="mr-2 h-4 w-4" />
            {t('errors.goBack')}
          </Button>
        </div>
      </div>
    </div>
  );
}
