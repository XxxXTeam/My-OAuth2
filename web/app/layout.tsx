import type { Metadata } from "next";
import "./globals.css";
import { AuthProvider } from "@/lib/auth-context";
import { I18nProvider } from "@/lib/i18n";
import ErrorBoundary from "@/components/error-boundary";

export const metadata: Metadata = {
  title: "OAuth2 - Unified Authentication",
  description: "OAuth2 authentication and authorization service",
  manifest: "/manifest.json",
  appleWebApp: {
    capable: true,
    statusBarStyle: "default",
    title: "OAuth2",
  },
  icons: {
    icon: "/icons/icon-192x192.svg",
    apple: "/icons/icon-192x192.svg",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" suppressHydrationWarning translate="no">
      <head>
        <meta name="google" content="notranslate" />
        <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no, viewport-fit=cover" />
        {/* PWA meta 由 metadata export 管理 */}
        <meta name="theme-color" content="#ffffff" media="(prefers-color-scheme: light)" />
        <meta name="theme-color" content="#0f172a" media="(prefers-color-scheme: dark)" />
        {/*
          * 暗色模式初始化脚本（阻塞渲染前执行，防止 FOUC 闪白/闪黑）
          * 优先级：localStorage 用户选择 > 系统偏好 > 默认亮色
          */}
        <script dangerouslySetInnerHTML={{ __html: `(function(){try{var t=localStorage.getItem('theme');if(t==='dark'||(t!=='light'&&window.matchMedia('(prefers-color-scheme:dark)').matches)){document.documentElement.classList.add('dark')}}catch(e){}})()` }} />
        {/* PWA Service Worker 注册 */}
        <script dangerouslySetInnerHTML={{ __html: `if('serviceWorker' in navigator){window.addEventListener('load',function(){navigator.serviceWorker.register('/sw.js')})}` }} />
      </head>
      <body className="antialiased font-sans" suppressHydrationWarning>
        <I18nProvider>
          <ErrorBoundary>
            <AuthProvider>
              {children}
            </AuthProvider>
          </ErrorBoundary>
        </I18nProvider>
      </body>
    </html>
  );
}
