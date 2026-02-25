'use client';

import { useMemo } from 'react';
import { useI18n } from '@/lib/i18n';

/*
 * PasswordStrength 密码强度指示器组件
 * 功能：实时检测密码强度并以进度条和文字形式展示
 * 强度等级：弱 → 一般 → 良好 → 强 → 极强
 */

interface PasswordStrengthProps {
  password: string;
}

interface StrengthResult {
  score: number;      /* 0-4 */
  level: string;
  hasUpper: boolean;
  hasLower: boolean;
  hasDigit: boolean;
  hasSpecial: boolean;
  lengthValid: boolean;
}

function checkStrength(password: string): StrengthResult {
  const result: StrengthResult = {
    score: 0,
    level: 'weak',
    hasUpper: false,
    hasLower: false,
    hasDigit: false,
    hasSpecial: false,
    lengthValid: password.length >= 8,
  };

  for (const ch of password) {
    if (/[A-Z]/.test(ch)) result.hasUpper = true;
    else if (/[a-z]/.test(ch)) result.hasLower = true;
    else if (/[0-9]/.test(ch)) result.hasDigit = true;
    else if (/[^A-Za-z0-9]/.test(ch)) result.hasSpecial = true;
  }

  let score = 0;
  if (result.lengthValid) score++;
  if (result.hasUpper && result.hasLower) score++;
  if (result.hasDigit) score++;
  if (result.hasSpecial) score++;
  if (password.length >= 12) score++;
  if (score > 4) score = 4;

  result.score = score;
  const levels = ['weak', 'fair', 'good', 'strong', 'very_strong'];
  result.level = levels[score];

  return result;
}

const strengthColors: Record<string, string> = {
  weak: 'bg-red-500',
  fair: 'bg-orange-500',
  good: 'bg-yellow-500',
  strong: 'bg-green-500',
  very_strong: 'bg-emerald-500',
};

export function PasswordStrength({ password }: PasswordStrengthProps) {
  const { t } = useI18n();

  const strength = useMemo(() => checkStrength(password), [password]);

  if (!password) return null;

  const levelLabels: Record<string, string> = {
    weak: t('password_weak'),
    fair: t('password_fair'),
    good: t('password_good'),
    strong: t('password_strong'),
    very_strong: t('password_very_strong'),
  };

  return (
    <div className="space-y-1.5">
      {/* 强度进度条 */}
      <div className="flex gap-1">
        {[0, 1, 2, 3, 4].map((i) => (
          <div
            key={i}
            className={`h-1 flex-1 rounded-full transition-colors duration-200 ${
              i <= strength.score
                ? strengthColors[strength.level]
                : 'bg-muted'
            }`}
          />
        ))}
      </div>
      {/* 强度文字 */}
      <div className="flex items-center justify-between text-xs">
        <span className="text-muted-foreground">
          {levelLabels[strength.level]}
        </span>
        <div className="flex gap-2 text-muted-foreground">
          {!strength.lengthValid && (
            <span className="text-red-500">{t('password_min_8')}</span>
          )}
          {password.length > 72 && (
            <span className="text-red-500">{t('password_max_72')}</span>
          )}
        </div>
      </div>
    </div>
  );
}
