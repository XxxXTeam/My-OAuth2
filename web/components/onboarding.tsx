'use client';

import { useState, useEffect } from 'react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Progress } from '@/components/ui/progress';
import { Badge } from '@/components/ui/badge';
import { 
  CheckCircle2, 
  Circle, 
  User, 
  AppWindow, 
  Shield, 
  ArrowRight,
  Sparkles,
  X
} from 'lucide-react';
import { useAuth } from '@/lib/auth-context';
import { useI18n } from '@/lib/i18n';
import { api } from '@/lib/api';
import { useRouter } from 'next/navigation';

interface OnboardingStep {
  id: string;
  title: string;
  description: string;
  icon: React.ElementType;
  completed: boolean;
  action?: () => void;
  actionLabel?: string;
}

export function OnboardingCard() {
  const { user } = useAuth();
  const { t } = useI18n();
  const router = useRouter();
  const [dismissed, setDismissed] = useState(false);
  const [hasApps, setHasApps] = useState(false);
  const [hasAuthorizations, setHasAuthorizations] = useState(false);

  useEffect(() => {
    // Check localStorage for dismissed state
    const isDismissed = localStorage.getItem('onboarding_dismissed');
    if (isDismissed === 'true') {
      setDismissed(true);
    }
    
    // Check if user has apps and authorizations
    const checkData = async () => {
      try {
        const [appsRes, authsRes] = await Promise.all([
          api.getApps(),
          api.getUserAuthorizations(),
        ]);
        if (appsRes.success && appsRes.data) {
          setHasApps(appsRes.data.length > 0);
        }
        if (authsRes.success && authsRes.data) {
          const auths = authsRes.data.authorizations || [];
          setHasAuthorizations(auths.length > 0);
        }
      } catch {
        // Ignore errors
      }
    };
    checkData();
  }, []);

  const steps: OnboardingStep[] = [
    {
      id: 'profile',
      title: t('dashboard.onboarding.profileTitle'),
      description: t('dashboard.onboarding.profileDesc'),
      icon: User,
      completed: user?.profile_completed || false,
      action: () => router.push('/dashboard/profile'),
      actionLabel: t('dashboard.onboarding.profileAction'),
    },
    {
      id: 'app',
      title: t('dashboard.onboarding.appTitle'),
      description: t('dashboard.onboarding.appDesc'),
      icon: AppWindow,
      completed: hasApps,
      action: () => router.push('/dashboard/apps/new'),
      actionLabel: t('dashboard.onboarding.appAction'),
    },
    {
      id: 'authorize',
      title: t('dashboard.onboarding.authorizeTitle'),
      description: t('dashboard.onboarding.authorizeDesc'),
      icon: Shield,
      completed: hasAuthorizations,
      actionLabel: t('dashboard.onboarding.authorizeAction'),
    },
  ];

  const completedCount = steps.filter(s => s.completed).length;
  const progress = (completedCount / steps.length) * 100;

  const handleDismiss = () => {
    setDismissed(true);
    localStorage.setItem('onboarding_dismissed', 'true');
  };

  if (dismissed || progress === 100) {
    return null;
  }

  return (
    <Card className="relative overflow-hidden border-primary/20 bg-gradient-to-br from-primary/5 via-transparent to-transparent">
      <button 
        onClick={handleDismiss}
        className="absolute top-3 right-3 p-1 rounded-full hover:bg-muted transition-colors"
      >
        <X className="h-4 w-4 text-muted-foreground" />
      </button>
      
      <CardHeader className="pb-3">
        <div className="flex items-center gap-2">
          <Sparkles className="h-5 w-5 text-primary" />
          <CardTitle className="text-lg">{t('dashboard.onboarding.title')}</CardTitle>
          <Badge variant="secondary" className="ml-auto">
            {completedCount}/{steps.length}
          </Badge>
        </div>
        <CardDescription>{t('dashboard.onboarding.description')}</CardDescription>
      </CardHeader>
      
      <CardContent className="space-y-4">
        <Progress value={progress} className="h-2" />
        
        <div className="space-y-3">
          {steps.map((step) => (
            <div 
              key={step.id}
              className={`flex items-start gap-3 p-3 rounded-lg transition-colors ${
                step.completed 
                  ? 'bg-green-50 dark:bg-green-950/30' 
                  : 'bg-muted/50 hover:bg-muted'
              }`}
            >
              <div className={`mt-0.5 ${step.completed ? 'text-green-500' : 'text-muted-foreground'}`}>
                {step.completed ? (
                  <CheckCircle2 className="h-5 w-5" />
                ) : (
                  <Circle className="h-5 w-5" />
                )}
              </div>
              
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                  <step.icon className="h-4 w-4 text-muted-foreground" />
                  <span className={`font-medium ${step.completed ? 'line-through text-muted-foreground' : ''}`}>
                    {step.title}
                  </span>
                </div>
                <p className="text-sm text-muted-foreground mt-0.5">
                  {step.description}
                </p>
              </div>
              
              {!step.completed && step.action && (
                <Button 
                  size="sm" 
                  variant="outline"
                  onClick={step.action}
                  className="shrink-0"
                >
                  {step.actionLabel}
                  <ArrowRight className="h-3 w-3 ml-1" />
                </Button>
              )}
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}
