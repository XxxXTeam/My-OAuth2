'use client';

import { createContext, useContext, useState, useCallback, ReactNode, useEffect } from 'react';
import en from './locales/en.json';
import zh from './locales/zh.json';

type Locale = 'en' | 'zh';
type Messages = typeof en;

const locales: Record<Locale, Messages> = { en, zh };

interface I18nContextType {
  locale: Locale;
  setLocale: (locale: Locale) => void;
  t: (key: string, params?: Record<string, string>) => string;
  isReady: boolean;
}

const I18nContext = createContext<I18nContextType | undefined>(undefined);

function getNestedValue(obj: Record<string, unknown>, path: string): string {
  const keys = path.split('.');
  let result: unknown = obj;
  
  for (const key of keys) {
    if (result && typeof result === 'object' && key in result) {
      result = (result as Record<string, unknown>)[key];
    } else {
      return path; // Return key if not found
    }
  }
  
  return typeof result === 'string' ? result : path;
}

// Detect browser language
function detectBrowserLanguage(): Locale {
  if (typeof window === 'undefined') return 'zh';
  
  // Check saved preference first
  const saved = localStorage.getItem('locale') as Locale;
  if (saved && (saved === 'en' || saved === 'zh')) {
    return saved;
  }
  
  // Default to Chinese
  return 'zh';
}

export function I18nProvider({ children }: { children: ReactNode }) {
  // Use 'zh' as default for SSR, will be updated on client
  const [locale, setLocaleState] = useState<Locale>('zh');
  const [isReady, setIsReady] = useState(false);

  useEffect(() => {
    // On client, detect and set the correct language
    const detectedLocale = detectBrowserLanguage();
    setLocaleState(detectedLocale);
    setIsReady(true);
  }, []);

  const setLocale = useCallback((newLocale: Locale) => {
    setLocaleState(newLocale);
    localStorage.setItem('locale', newLocale);
  }, []);

  const t = useCallback((key: string, params?: Record<string, string>): string => {
    let text = getNestedValue(locales[locale] as unknown as Record<string, unknown>, key);
    
    if (params) {
      Object.entries(params).forEach(([k, v]) => {
        text = text.replace(new RegExp(`\\{${k}\\}`, 'g'), v);
      });
    }
    
    return text;
  }, [locale]);

  return (
    <I18nContext.Provider value={{ locale, setLocale, t, isReady }}>
      {children}
    </I18nContext.Provider>
  );
}

export function useI18n() {
  const context = useContext(I18nContext);
  if (!context) {
    throw new Error('useI18n must be used within an I18nProvider');
  }
  /* dateLocale: 将内部 locale（'zh'/'en'）映射为 BCP 47 格式，供 toLocaleDateString 等 API 使用 */
  const dateLocale = context.locale === 'zh' ? 'zh-CN' : 'en-US';
  return { ...context, dateLocale };
}

export function LanguageSwitcher() {
  const { locale, setLocale } = useI18n();

  return (
    <button
      onClick={() => setLocale(locale === 'en' ? 'zh' : 'en')}
      className="px-3 py-1 text-sm border rounded-md hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors"
    >
      {locale === 'en' ? '中文' : 'EN'}
    </button>
  );
}
