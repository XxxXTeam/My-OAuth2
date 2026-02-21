'use client'

import { useState, useEffect, useCallback, Suspense } from 'react'
import { useSearchParams, useRouter } from 'next/navigation'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '@/components/ui/card'
import { Label } from '@/components/ui/label'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Loader2, Monitor, CheckCircle2, XCircle } from 'lucide-react'
import { api } from '@/lib/api'
import { useAuth } from '@/lib/auth-context'
import { useI18n } from '@/lib/i18n'

interface DeviceInfo {
  user_code: string
  scope: string
  app: {
    id: string
    name: string
    description: string
  }
  expires_in: number
}

function DevicePageContent() {
  const searchParams = useSearchParams()
  const router = useRouter()
  const { user, isLoading: authLoading } = useAuth()
  const { t } = useI18n()
  
  const [userCode, setUserCode] = useState(searchParams.get('user_code') || '')
  const [deviceInfo, setDeviceInfo] = useState<DeviceInfo | null>(null)
  const [loading, setLoading] = useState(false)
  const [authorizing, setAuthorizing] = useState(false)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState<'authorized' | 'denied' | null>(null)

  const fetchDeviceInfo = useCallback(async (code: string) => {
    setLoading(true)
    setError('')
    try {
      const data = await api.getDeviceInfo(code)
      setDeviceInfo(data)
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : t('device.error.notFound'))
    } finally {
      setLoading(false)
    }
  }, [t])

  useEffect(() => {
    const code = searchParams.get('user_code')
    if (code) {
      setUserCode(code)
      fetchDeviceInfo(code)
    }
  }, [searchParams, fetchDeviceInfo])

  const handleSubmitCode = (e: React.FormEvent) => {
    e.preventDefault()
    if (!userCode.trim()) return
    fetchDeviceInfo(userCode.trim().toUpperCase())
  }

  const handleAuthorize = async (consent: 'allow' | 'deny') => {
    if (!deviceInfo) return
    
    setAuthorizing(true)
    setError('')
    try {
      await api.authorizeDevice(deviceInfo.user_code, consent)
      setSuccess(consent === 'allow' ? 'authorized' : 'denied')
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : t('device.error.authFailed'))
    } finally {
      setAuthorizing(false)
    }
  }

  // Redirect to login if not authenticated
  if (!authLoading && !user && deviceInfo) {
    const returnUrl = `/device?user_code=${encodeURIComponent(userCode)}`
    router.push(`/login?return_to=${encodeURIComponent(returnUrl)}`)
    return null
  }

  // Success state
  if (success) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-gray-900 px-4">
        <Card className="w-full max-w-md">
          <CardHeader className="text-center">
            {success === 'authorized' ? (
              <>
                <CheckCircle2 className="w-16 h-16 mx-auto text-green-500 mb-4" />
                <CardTitle className="text-green-600">{t('device.success.authorized')}</CardTitle>
                <CardDescription>
                  {t('device.success.authorizedDesc')}
                </CardDescription>
              </>
            ) : (
              <>
                <XCircle className="w-16 h-16 mx-auto text-red-500 mb-4" />
                <CardTitle className="text-red-600">{t('device.success.denied')}</CardTitle>
                <CardDescription>
                  {t('device.success.deniedDesc')}
                </CardDescription>
              </>
            )}
          </CardHeader>
          <CardFooter className="justify-center">
            <p className="text-sm text-muted-foreground">
              {t('device.success.closeWindow')}
            </p>
          </CardFooter>
        </Card>
      </div>
    )
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-gray-900 px-4">
      <Card className="w-full max-w-md">
        <CardHeader className="text-center">
          <Monitor className="w-12 h-12 mx-auto text-primary mb-4" />
          <CardTitle>{t('device.title')}</CardTitle>
          <CardDescription>
            {t('device.description')}
          </CardDescription>
        </CardHeader>
        
        <CardContent>
          {error && (
            <Alert variant="destructive" className="mb-4">
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}

          {!deviceInfo ? (
            <form onSubmit={handleSubmitCode} className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="userCode">{t('device.enterCode')}</Label>
                <Input
                  id="userCode"
                  value={userCode}
                  onChange={(e) => setUserCode(e.target.value.toUpperCase())}
                  placeholder="XXXX-XXXX"
                  className="text-center text-2xl tracking-widest font-mono"
                  maxLength={9}
                  disabled={loading}
                />
              </div>
              <Button type="submit" className="w-full" disabled={loading || !userCode.trim()}>
                {loading ? (
                  <>
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    {t('common.loading')}
                  </>
                ) : (
                  t('device.continue')
                )}
              </Button>
            </form>
          ) : (
            <div className="space-y-6">
              <div className="text-center p-4 bg-muted rounded-lg">
                <p className="text-sm text-muted-foreground mb-1">{t('device.code')}</p>
                <p className="text-2xl font-mono font-bold tracking-widest">{deviceInfo.user_code}</p>
              </div>

              <div className="border rounded-lg p-4">
                <h3 className="font-semibold text-lg mb-2">{deviceInfo.app.name}</h3>
                {deviceInfo.app.description && (
                  <p className="text-sm text-muted-foreground mb-4">{deviceInfo.app.description}</p>
                )}
                
                {deviceInfo.scope && (
                  <div className="mt-4">
                    <p className="text-sm font-medium mb-2">{t('device.permissions')}</p>
                    <div className="flex flex-wrap gap-2">
                      {deviceInfo.scope.split(' ').map((scope) => (
                        <span
                          key={scope}
                          className="px-2 py-1 bg-primary/10 text-primary text-xs rounded-full"
                        >
                          {scope}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>

              {user ? (
                <div className="space-y-3">
                  <p className="text-sm text-center text-muted-foreground">
                    {t('device.authorizeAs', { username: user.username })}
                  </p>
                  <div className="flex gap-3">
                    <Button
                      variant="outline"
                      className="flex-1"
                      onClick={() => handleAuthorize('deny')}
                      disabled={authorizing}
                    >
                      {t('device.deny')}
                    </Button>
                    <Button
                      className="flex-1"
                      onClick={() => handleAuthorize('allow')}
                      disabled={authorizing}
                    >
                      {authorizing ? (
                        <>
                          <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                          {t('common.loading')}
                        </>
                      ) : (
                        t('device.authorize')
                      )}
                    </Button>
                  </div>
                </div>
              ) : (
                <div className="text-center">
                  <Loader2 className="h-6 w-6 animate-spin mx-auto" />
                  <p className="text-sm text-muted-foreground mt-2">
                    {t('device.redirectLogin')}
                  </p>
                </div>
              )}
            </div>
          )}
        </CardContent>

        <CardFooter className="justify-center">
          <p className="text-xs text-muted-foreground text-center">
            {t('device.expiresIn', { minutes: String(Math.ceil((deviceInfo?.expires_in || 1800) / 60)) })}
          </p>
        </CardFooter>
      </Card>
    </div>
  )
}

export default function DevicePage() {
  return (
    <Suspense fallback={
      <div className="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-gray-900">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
      </div>
    }>
      <DevicePageContent />
    </Suspense>
  )
}
