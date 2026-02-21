'use client';

import Link from "next/link";
import { Shield, Key, Users, Zap } from "lucide-react";
import { useI18n, LanguageSwitcher } from "@/lib/i18n";

export default function Home() {
  const { t } = useI18n();

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 to-slate-100 dark:from-slate-900 dark:to-slate-800">
      {/* Header */}
      <header className="border-b bg-white/80 dark:bg-slate-950/80 backdrop-blur-sm sticky top-0 z-50">
        <div className="container mx-auto px-4 h-16 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Shield className="h-6 w-6 text-primary" />
            <span className="text-xl font-bold">OAuth2</span>
          </div>
          <nav className="flex items-center gap-4">
            <LanguageSwitcher />
            <Link 
              href="/login" 
              className="text-sm font-medium text-muted-foreground hover:text-foreground transition-colors"
            >
              {t('nav.signIn')}
            </Link>
            <Link 
              href="/register" 
              className="text-sm font-medium bg-primary text-primary-foreground px-4 py-2 rounded-md hover:bg-primary/90 transition-colors"
            >
              {t('nav.getStarted')}
            </Link>
          </nav>
        </div>
      </header>

      {/* Hero */}
      <main className="container mx-auto px-4 py-20">
        <div className="text-center max-w-3xl mx-auto">
          <h1 className="text-5xl font-bold tracking-tight mb-6">
            {t('home.title')}
            <br />
            <span className="text-primary">{t('home.titleHighlight')}</span>
          </h1>
          <p className="text-xl text-muted-foreground mb-8">
            {t('home.description')}
          </p>
          <div className="flex gap-4 justify-center">
            <Link 
              href="/register" 
              className="bg-primary text-primary-foreground px-6 py-3 rounded-lg font-medium hover:bg-primary/90 transition-colors"
            >
              {t('home.createAccount')}
            </Link>
            <Link 
              href="/login" 
              className="border border-input bg-background px-6 py-3 rounded-lg font-medium hover:bg-accent transition-colors"
            >
              {t('home.signIn')}
            </Link>
          </div>
        </div>

        {/* Features */}
        <div className="grid md:grid-cols-3 gap-8 mt-24">
          <div className="bg-white dark:bg-slate-950 p-6 rounded-xl shadow-sm border">
            <div className="h-12 w-12 rounded-lg bg-primary/10 flex items-center justify-center mb-4">
              <Key className="h-6 w-6 text-primary" />
            </div>
            <h3 className="text-lg font-semibold mb-2">{t('home.features.oauth2.title')}</h3>
            <p className="text-muted-foreground">
              {t('home.features.oauth2.description')}
            </p>
          </div>
          <div className="bg-white dark:bg-slate-950 p-6 rounded-xl shadow-sm border">
            <div className="h-12 w-12 rounded-lg bg-primary/10 flex items-center justify-center mb-4">
              <Users className="h-6 w-6 text-primary" />
            </div>
            <h3 className="text-lg font-semibold mb-2">{t('home.features.userManagement.title')}</h3>
            <p className="text-muted-foreground">
              {t('home.features.userManagement.description')}
            </p>
          </div>
          <div className="bg-white dark:bg-slate-950 p-6 rounded-xl shadow-sm border">
            <div className="h-12 w-12 rounded-lg bg-primary/10 flex items-center justify-center mb-4">
              <Zap className="h-6 w-6 text-primary" />
            </div>
            <h3 className="text-lg font-semibold mb-2">{t('home.features.easyIntegration.title')}</h3>
            <p className="text-muted-foreground">
              {t('home.features.easyIntegration.description')}
            </p>
          </div>
        </div>
      </main>

      {/* Footer */}
      <footer className="border-t mt-20 py-8">
        <div className="container mx-auto px-4 text-center text-sm text-muted-foreground">
          <p>{t('home.footer')}</p>
        </div>
      </footer>
    </div>
  );
}
