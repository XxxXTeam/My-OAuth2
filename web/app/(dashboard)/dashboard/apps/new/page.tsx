'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { api } from '@/lib/api';
import { useI18n } from '@/lib/i18n';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { ArrowLeft, Loader2, Plus, X } from 'lucide-react';

export default function NewAppPage() {
  const router = useRouter();
  const { t } = useI18n();
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [redirectUris, setRedirectUris] = useState<string[]>(['']);
  const [error, setError] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [grantTypes, setGrantTypes] = useState<string[]>(['authorization_code', 'refresh_token']);

  const handleAddUri = () => {
    setRedirectUris([...redirectUris, '']);
  };

  const handleRemoveUri = (index: number) => {
    if (redirectUris.length > 1) {
      setRedirectUris(redirectUris.filter((_, i) => i !== index));
    }
  };

  const handleUriChange = (index: number, value: string) => {
    const newUris = [...redirectUris];
    newUris[index] = value;
    setRedirectUris(newUris);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    const validUris = redirectUris.filter(uri => uri.trim() !== '');
    if (validUris.length === 0) {
      setError(t('apps.create.redirectUrisHelp'));
      return;
    }

    setIsLoading(true);

    const response = await api.createApp({
      name,
      description,
      redirect_uris: validUris,
      grant_types: grantTypes,
    });

    if (response.success && response.data) {
      // Store the secret temporarily for display on the detail page
      if (response.data.client_secret) {
        sessionStorage.setItem(`app_secret_${response.data.id}`, response.data.client_secret);
      }
      router.push(`/dashboard/apps/${response.data.id}?new=true`);
    } else {
      setError(response.error?.message || t('toast.error'));
    }

    setIsLoading(false);
  };

  return (
    <div className="max-w-2xl mx-auto space-y-8">
      {/* Header */}
      <div className="flex items-center gap-4">
        <Link href="/dashboard/apps">
          <Button variant="outline" size="icon">
            <ArrowLeft className="h-4 w-4" />
          </Button>
        </Link>
        <div>
          <h1 className="text-3xl font-bold">{t('apps.create.title')}</h1>
          <p className="text-muted-foreground mt-1">
            {t('apps.create.description')}
          </p>
        </div>
      </div>

      {/* Form */}
      <Card>
        <CardHeader>
          <CardTitle>{t('apps.detail.appInfo')}</CardTitle>
          <CardDescription>
            {t('apps.create.description')}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-6">
            {error && (
              <div className="p-3 text-sm text-red-500 bg-red-50 dark:bg-red-900/20 rounded-md">
                {error}
              </div>
            )}

            <div className="space-y-2">
              <Label htmlFor="name">{t('apps.create.name')} *</Label>
              <Input
                id="name"
                placeholder={t('apps.create.namePlaceholder')}
                value={name}
                onChange={(e) => setName(e.target.value)}
                required
                disabled={isLoading}
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="description">{t('apps.create.appDescription')}</Label>
              <Input
                id="description"
                placeholder={t('apps.create.descriptionPlaceholder')}
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                disabled={isLoading}
              />
            </div>

            <div className="space-y-2">
              <Label>{t('apps.create.redirectUris')} *</Label>
              <p className="text-sm text-muted-foreground">
                {t('apps.create.redirectUrisHelp')}
              </p>
              <div className="space-y-2">
                {redirectUris.map((uri, index) => (
                  <div key={index} className="flex gap-2">
                    <Input
                      placeholder="https://example.com/callback"
                      value={uri}
                      onChange={(e) => handleUriChange(index, e.target.value)}
                      disabled={isLoading}
                    />
                    {redirectUris.length > 1 && (
                      <Button
                        type="button"
                        variant="outline"
                        size="icon"
                        onClick={() => handleRemoveUri(index)}
                        disabled={isLoading}
                      >
                        <X className="h-4 w-4" />
                      </Button>
                    )}
                  </div>
                ))}
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={handleAddUri}
                  disabled={isLoading}
                >
                  <Plus className="mr-2 h-4 w-4" />
                  {t('common.add')}
                </Button>
              </div>
            </div>

            <div className="space-y-4">
              <div className="space-y-2">
                <Label>{t('apps.create.grantTypes')}</Label>
                <p className="text-sm text-muted-foreground">{t('apps.create.grantTypesHelp')}</p>
                <div className="grid sm:grid-cols-2 gap-3">
                  {[
                    { key: 'authorization_code', defaultChecked: true },
                    { key: 'refresh_token', defaultChecked: true },
                    { key: 'client_credentials' },
                    { key: 'device_code' },
                    { key: 'token_exchange' },
                  ].map(opt => (
                    <label key={opt.key} className="flex items-start gap-2 cursor-pointer select-none">
                      <input
                        type="checkbox"
                        className="mt-1 h-4 w-4"
                        defaultChecked={!!opt.defaultChecked}
                        onChange={(e) => {
                          setGrantTypes(prev => {
                            const exists = prev.includes(opt.key);
                            if (e.target.checked && !exists) return [...prev, opt.key];
                            if (!e.target.checked && exists) return prev.filter(x => x !== opt.key);
                            return prev;
                          });
                        }}
                      />
                      <div>
                        <div className="text-sm font-medium">{t(`apps.grantType.${opt.key}`)}</div>
                        <div className="text-xs text-muted-foreground">{t(`apps.grantType.${opt.key}_desc`)}</div>
                      </div>
                    </label>
                  ))}
                </div>
              </div>

              <div className="flex gap-4 pt-2">
                <Button type="submit" disabled={isLoading}>
                  {isLoading ? (
                    <>
                      <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                      {t('apps.create.submitting')}
                    </>
                  ) : (
                    t('apps.create.submit')
                  )}
                </Button>
                <Link href="/dashboard/apps">
                  <Button type="button" variant="outline" disabled={isLoading}>
                    {t('common.cancel')}
                  </Button>
                </Link>
              </div>
            </div>
          </form>
        </CardContent>
      </Card>
    </div>
  );
}
