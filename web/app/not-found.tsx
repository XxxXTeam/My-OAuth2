import Link from 'next/link';
import { Button } from '@/components/ui/button';
import { Home } from 'lucide-react';
import { GoBackButton } from '@/components/go-back-button';

/*
 * NotFound 404 页面（服务端组件）
 * 优化：主体为服务端渲染，减少客户端 JS bundle
 *       仅 GoBackButton 为客户端组件（需要 router.back()）
 */
export default function NotFound() {
  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-slate-50 to-slate-100 dark:from-slate-900 dark:to-slate-800">
      <div className="text-center px-4">
        <h1 className="text-9xl font-bold text-primary/20">404</h1>
        <h2 className="text-2xl font-semibold mt-4">Page Not Found</h2>
        <p className="text-muted-foreground mt-2 max-w-md mx-auto">
          The page you are looking for does not exist or has been moved.
        </p>
        <div className="flex gap-4 justify-center mt-8">
          <Link href="/">
            <Button>
              <Home className="mr-2 h-4 w-4" />
              Go Home
            </Button>
          </Link>
          <GoBackButton label="Go Back" />
        </div>
      </div>
    </div>
  );
}
