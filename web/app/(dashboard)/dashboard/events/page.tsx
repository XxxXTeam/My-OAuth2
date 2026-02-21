'use client';

import { useEffect, useState, useCallback, useRef } from 'react';
import { useAuth } from '@/lib/auth-context';
import { useI18n } from '@/lib/i18n';
import { api, AuthEvent } from '@/lib/api';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { 
  Activity, 
  Loader2, 
  UserPlus, 
  LogIn, 
  Shield, 
  XCircle,
  Wifi,
  WifiOff,
  Trash2
} from 'lucide-react';

const eventIcons = {
  user_registered: UserPlus,
  user_login: LogIn,
  oauth_authorized: Shield,
  oauth_revoked: XCircle,
};

const eventColors = {
  user_registered: 'text-green-500 bg-green-50',
  user_login: 'text-blue-500 bg-blue-50',
  oauth_authorized: 'text-purple-500 bg-purple-50',
  oauth_revoked: 'text-red-500 bg-red-50',
};

/* eventLabels 通过 i18n 动态获取，见组件内 getEventLabel */

export default function EventsPage() {
  const { user } = useAuth();
  const { t, dateLocale } = useI18n();
  const [events, setEvents] = useState<AuthEvent[]>([]);
  const [isConnected, setIsConnected] = useState(false);
  const [isConnecting, setIsConnecting] = useState(false);
  const eventSourceRef = useRef<EventSource | null>(null);

  const connect = useCallback(() => {
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
    }

    setIsConnecting(true);
    const url = api.getEventStreamUrl();
    const eventSource = new EventSource(url, { withCredentials: true });
    eventSourceRef.current = eventSource;

    eventSource.onopen = () => {
      setIsConnected(true);
      setIsConnecting(false);
    };

    eventSource.onerror = () => {
      setIsConnected(false);
      setIsConnecting(false);
    };

    eventSource.addEventListener('connected', () => {
      setIsConnected(true);
      setIsConnecting(false);
    });

    eventSource.addEventListener('auth', (e) => {
      try {
        const event = JSON.parse(e.data) as AuthEvent;
        setEvents(prev => [event, ...prev].slice(0, 100)); // Keep last 100 events
      } catch {
        // Ignore parse errors
      }
    });

    eventSource.addEventListener('ping', () => {
      // Keep-alive ping
    });
  }, []);

  const disconnect = useCallback(() => {
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
      eventSourceRef.current = null;
    }
    setIsConnected(false);
  }, []);

  useEffect(() => {
    // Auto-connect for admin users
    if (user?.role === 'admin') {
      connect();
    }

    return () => {
      disconnect();
    };
  }, [user, connect, disconnect]);

  const clearEvents = () => {
    setEvents([]);
  };

  const formatTime = (timestamp: string) => {
    return new Date(timestamp).toLocaleString(dateLocale);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold flex items-center gap-2">
            <Activity className="h-8 w-8" />
            {t('admin.events.title')}
          </h1>
          <p className="text-muted-foreground mt-1">
            {t('admin.events.description')}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <div className={`flex items-center gap-2 px-3 py-1 rounded-full text-sm ${
            isConnected ? 'bg-green-100 text-green-700' : 'bg-slate-100 text-slate-600'
          }`}>
            {isConnected ? (
              <>
                <Wifi className="h-4 w-4" />
                {t('admin.events.connected')}
              </>
            ) : (
              <>
                <WifiOff className="h-4 w-4" />
                {t('admin.events.disconnected')}
              </>
            )}
          </div>
          {!isConnected ? (
            <Button onClick={connect} disabled={isConnecting}>
              {isConnecting ? (
                <Loader2 className="h-4 w-4 animate-spin mr-2" />
              ) : null}
              {t('admin.events.reconnect')}
            </Button>
          ) : (
            <Button variant="outline" onClick={disconnect}>
              {t('admin.events.disconnect')}
            </Button>
          )}
          <Button variant="outline" onClick={clearEvents}>
            <Trash2 className="h-4 w-4 mr-2" />
            {t('admin.events.clearAll')}
          </Button>
        </div>
      </div>

      {/* Events List */}
      <Card>
        <CardHeader>
          <CardTitle>{t('admin.events.title')}</CardTitle>
          <CardDescription>
            {events.length > 0 ? `${events.length} ${t('admin.events.title')}` : t('admin.events.waitingForEvents')}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {events.length === 0 ? (
            <div className="text-center py-12 text-muted-foreground">
              <Activity className="h-12 w-12 mx-auto mb-4 opacity-50" />
              <p>{t('admin.events.noEvents')}</p>
              <p className="text-sm mt-1">
                {isConnected ? t('admin.events.waitingForEvents') : t('admin.events.reconnect')}
              </p>
            </div>
          ) : (
            <div className="space-y-3">
              {events.map((event, index) => {
                const Icon = eventIcons[event.type] || Activity;
                const colorClass = eventColors[event.type] || 'text-slate-500 bg-slate-50';
                const eventLabelMap: Record<string, string> = {
                  user_registered: t('admin.events.userRegistered'),
                  user_login: t('admin.events.userLogin'),
                  oauth_authorized: t('admin.events.oauthAuthorized'),
                  oauth_revoked: t('admin.events.oauthRevoked'),
                };
                const label = eventLabelMap[event.type] || event.type;

                return (
                  <div 
                    key={`${event.timestamp}-${index}`}
                    className="flex items-start gap-4 p-4 rounded-lg border bg-white dark:bg-slate-900"
                  >
                    <div className={`p-2 rounded-lg ${colorClass}`}>
                      <Icon className="h-5 w-5" />
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="font-medium">{label}</span>
                        <span className="text-xs text-muted-foreground">
                          {formatTime(event.timestamp)}
                        </span>
                      </div>
                      <div className="text-sm text-muted-foreground mt-1">
                        <span className="font-medium">{event.username}</span>
                        {event.email && <span className="ml-2">({event.email})</span>}
                      </div>
                      <div className="text-xs text-muted-foreground mt-1">
                        {t('admin.events.appLabel')}: {event.app_name}
                        {event.scope && <span className="ml-2">| {t('admin.events.scopeLabel')}: {event.scope}</span>}
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
