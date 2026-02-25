'use client';

import { useEffect, useState, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import { useAuth } from '@/lib/auth-context';
import { useI18n } from '@/lib/i18n';
import { api } from '@/lib/api';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { PageHeader } from '@/components/ui/page-header';
import {
  Users, AppWindow, Loader2, Shield, Trash2, UserCog, Activity, TrendingUp, Clock,
  CheckCircle, XCircle, Search, ChevronLeft, ChevronRight, Ban, UserCheck, KeyRound,
  Download, MoreHorizontal, X, AlertCircle, Check, UserPlus, Eye, Mail, Pencil, Unlock
} from 'lucide-react';
import type { User, AdminStats, LoginTrend } from '@/lib/types';

/* 重置密码弹窗 */
function ResetPasswordDialog({ userId, userName, onClose }: { userId: string; userName: string; onClose: () => void }) {
  const { t } = useI18n();
  const [newPassword, setNewPassword] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [result, setResult] = useState<{ success: boolean; message: string } | null>(null);

  const handleReset = async () => {
    if (newPassword.length < 8) { setResult({ success: false, message: t('profile.passwordMinLength') }); return; }
    setIsLoading(true);
    const response = await api.resetUserPassword(userId, newPassword);
    if (response.success) { setResult({ success: true, message: t('admin.users.passwordResetSuccess') }); setTimeout(onClose, 1500); }
    else { setResult({ success: false, message: response.error?.message || t('profile.passwordFailed') }); }
    setIsLoading(false);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50" onClick={onClose}>
      <div className="bg-white dark:bg-slate-900 rounded-lg shadow-xl p-6 w-full max-w-md mx-4" onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold flex items-center gap-2"><KeyRound className="h-5 w-5" />{t('admin.users.resetPassword')}</h3>
          <button onClick={onClose} className="text-muted-foreground hover:text-foreground"><X className="h-5 w-5" /></button>
        </div>
        <p className="text-sm text-muted-foreground mb-4">{t('admin.users.resetPasswordDesc')} - <strong>{userName}</strong></p>
        {result && (
          <div className={`flex items-center gap-2 p-3 rounded-lg text-sm mb-4 ${result.success ? 'bg-green-50 text-green-600 dark:bg-green-950/30 dark:text-green-400' : 'bg-red-50 text-red-600 dark:bg-red-950/30 dark:text-red-400'}`}>
            {result.success ? <Check className="h-4 w-4" /> : <AlertCircle className="h-4 w-4" />}{result.message}
          </div>
        )}
        <Input type="password" value={newPassword} onChange={e => setNewPassword(e.target.value)} placeholder={t('admin.users.passwordPlaceholder')} className="mb-4" />
        <div className="flex justify-end gap-2">
          <Button variant="outline" onClick={onClose}>{t('common.cancel')}</Button>
          <Button onClick={handleReset} disabled={isLoading}>{isLoading ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : null}{t('common.confirm')}</Button>
        </div>
      </div>
    </div>
  );
}

/* 创建用户弹窗 */
function CreateUserDialog({ onClose, onSuccess }: { onClose: () => void; onSuccess: () => void }) {
  const { t } = useI18n();
  const [form, setForm] = useState({ email: '', username: '', password: '', role: 'user', status: 'active', send_welcome: false });
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [generatedPwd, setGeneratedPwd] = useState<string | null>(null);

  const handleCreate = async () => {
    setError(null);
    if (!form.email || !form.username) { setError(t('common.required')); return; }
    setIsLoading(true);
    const response = await api.createUser({ email: form.email, username: form.username, password: form.password || undefined, role: form.role, status: form.status, send_welcome: form.send_welcome });
    if (response.success && response.data) {
      if (response.data.generated_password) { setGeneratedPwd(response.data.generated_password); }
      else { onSuccess(); onClose(); }
    } else { setError(response.error?.message || t('common.error')); }
    setIsLoading(false);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50" onClick={onClose}>
      <div className="bg-white dark:bg-slate-900 rounded-lg shadow-xl p-6 w-full max-w-lg mx-4 max-h-[90vh] overflow-y-auto" onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold flex items-center gap-2"><UserPlus className="h-5 w-5" />{t('admin.users.createUser')}</h3>
          <button onClick={onClose} className="text-muted-foreground hover:text-foreground"><X className="h-5 w-5" /></button>
        </div>
        <p className="text-sm text-muted-foreground mb-4">{t('admin.users.createUserDesc')}</p>
        {error && (<div className="flex items-center gap-2 p-3 bg-red-50 dark:bg-red-950/30 text-red-600 dark:text-red-400 rounded-lg text-sm mb-4"><AlertCircle className="h-4 w-4" />{error}</div>)}
        {generatedPwd && (
          <div className="p-4 bg-green-50 dark:bg-green-950/30 rounded-lg mb-4 space-y-2">
            <p className="text-sm text-green-600 dark:text-green-400 flex items-center gap-2"><Check className="h-4 w-4" />{t('admin.users.createSuccess')}</p>
            <p className="text-sm font-medium">{t('admin.users.generatedPassword')}:</p>
            <code className="block p-2 bg-white dark:bg-slate-800 rounded text-sm font-mono">{generatedPwd}</code>
            <Button size="sm" onClick={() => { onSuccess(); onClose(); }}>{t('common.confirm')}</Button>
          </div>
        )}
        {!generatedPwd && (
          <div className="space-y-4">
            <div className="grid gap-4 md:grid-cols-2">
              <div className="space-y-2"><Label>{t('admin.users.emailLabel')} *</Label><Input value={form.email} onChange={e => setForm(p => ({ ...p, email: e.target.value }))} type="email" /></div>
              <div className="space-y-2"><Label>{t('admin.users.usernameLabel')} *</Label><Input value={form.username} onChange={e => setForm(p => ({ ...p, username: e.target.value }))} /></div>
            </div>
            <div className="space-y-2"><Label>{t('admin.users.passwordLabel')}</Label><Input value={form.password} onChange={e => setForm(p => ({ ...p, password: e.target.value }))} type="password" placeholder={t('admin.users.passwordPlaceholder')} /></div>
            <div className="grid gap-4 md:grid-cols-2">
              <div className="space-y-2">
                <Label>{t('admin.users.roleLabel')}</Label>
              <select className="w-full h-10 px-3 rounded-md border border-input bg-background" value={form.role} onChange={e => setForm(p => ({ ...p, role: e.target.value as 'admin' | 'user' }))}>
                  <option value="user">{t('admin.users.user')}</option><option value="admin">{t('admin.users.admin')}</option>
                </select>
              </div>
              <div className="space-y-2">
                <Label>{t('admin.users.statusLabel')}</Label>
                <select className="w-full h-10 px-3 rounded-md border border-input bg-background" value={form.status} onChange={e => setForm(p => ({ ...p, status: e.target.value as 'active' | 'suspended' | 'pending' }))}>
                  <option value="active">{t('admin.users.active')}</option><option value="suspended">{t('admin.users.suspended')}</option><option value="pending">{t('admin.users.pending')}</option>
                </select>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <input type="checkbox" id="sendWelcome" checked={form.send_welcome} onChange={e => setForm(p => ({ ...p, send_welcome: e.target.checked }))} className="rounded" />
              <Label htmlFor="sendWelcome">{t('admin.users.sendWelcome')}</Label>
            </div>
            <div className="flex justify-end gap-2 pt-2">
              <Button variant="outline" onClick={onClose}>{t('common.cancel')}</Button>
              <Button onClick={handleCreate} disabled={isLoading}>{isLoading ? <><Loader2 className="h-4 w-4 animate-spin mr-2" />{t('admin.users.creating')}</> : t('common.create')}</Button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

/* 编辑用户弹窗 */
function EditUserDialog({ userData, onClose, onSuccess }: { userData: User; onClose: () => void; onSuccess: () => void }) {
  const { t } = useI18n();
  const [form, setForm] = useState({
    email: userData.email, username: userData.username, role: userData.role || 'user', status: userData.status || 'active',
    nickname: userData.nickname || '', given_name: userData.given_name || '', family_name: userData.family_name || '',
    phone_number: userData.phone_number || '', gender: userData.gender || '', company: userData.company || '',
    department: userData.department || '', job_title: userData.job_title || '', email_verified: userData.email_verified,
  });
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleUpdate = async () => {
    setError(null); setIsLoading(true);
    const response = await api.updateUser(userData.id, form);
    if (response.success) { onSuccess(); onClose(); }
    else { setError(response.error?.message || t('common.error')); }
    setIsLoading(false);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50" onClick={onClose}>
      <div className="bg-white dark:bg-slate-900 rounded-lg shadow-xl p-6 w-full max-w-lg mx-4 max-h-[90vh] overflow-y-auto" onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold flex items-center gap-2"><Pencil className="h-5 w-5" />{t('admin.users.editUser')}</h3>
          <button onClick={onClose} className="text-muted-foreground hover:text-foreground"><X className="h-5 w-5" /></button>
        </div>
        <p className="text-sm text-muted-foreground mb-4">{t('admin.users.editUserDesc')}</p>
        {error && (<div className="flex items-center gap-2 p-3 bg-red-50 dark:bg-red-950/30 text-red-600 dark:text-red-400 rounded-lg text-sm mb-4"><AlertCircle className="h-4 w-4" />{error}</div>)}
        <div className="space-y-4">
          <div className="grid gap-4 md:grid-cols-2">
            <div className="space-y-2"><Label>{t('admin.users.emailLabel')}</Label><Input value={form.email} onChange={e => setForm(p => ({ ...p, email: e.target.value }))} type="email" /></div>
            <div className="space-y-2"><Label>{t('admin.users.usernameLabel')}</Label><Input value={form.username} onChange={e => setForm(p => ({ ...p, username: e.target.value }))} /></div>
          </div>
          <div className="grid gap-4 md:grid-cols-2">
            <div className="space-y-2"><Label>{t('admin.users.nicknameLabel')}</Label><Input value={form.nickname} onChange={e => setForm(p => ({ ...p, nickname: e.target.value }))} /></div>
            <div className="space-y-2"><Label>{t('admin.users.phoneLabel')}</Label><Input value={form.phone_number} onChange={e => setForm(p => ({ ...p, phone_number: e.target.value }))} /></div>
          </div>
          <div className="grid gap-4 md:grid-cols-2">
            <div className="space-y-2"><Label>{t('admin.users.familyNameLabel')}</Label><Input value={form.family_name} onChange={e => setForm(p => ({ ...p, family_name: e.target.value }))} /></div>
            <div className="space-y-2"><Label>{t('admin.users.givenNameLabel')}</Label><Input value={form.given_name} onChange={e => setForm(p => ({ ...p, given_name: e.target.value }))} /></div>
          </div>
          <div className="grid gap-4 md:grid-cols-2">
            <div className="space-y-2"><Label>{t('admin.users.companyLabel')}</Label><Input value={form.company} onChange={e => setForm(p => ({ ...p, company: e.target.value }))} /></div>
            <div className="space-y-2"><Label>{t('admin.users.departmentLabel')}</Label><Input value={form.department} onChange={e => setForm(p => ({ ...p, department: e.target.value }))} /></div>
          </div>
          <div className="space-y-2"><Label>{t('admin.users.jobTitleLabel')}</Label><Input value={form.job_title} onChange={e => setForm(p => ({ ...p, job_title: e.target.value }))} /></div>
          <div className="grid gap-4 md:grid-cols-2">
            <div className="space-y-2">
              <Label>{t('admin.users.roleLabel')}</Label>
              <select className="w-full h-10 px-3 rounded-md border border-input bg-background" value={form.role} onChange={e => setForm(p => ({ ...p, role: e.target.value as 'admin' | 'user' }))}>
                <option value="user">{t('admin.users.user')}</option><option value="admin">{t('admin.users.admin')}</option>
              </select>
            </div>
            <div className="space-y-2">
              <Label>{t('admin.users.statusLabel')}</Label>
              <select className="w-full h-10 px-3 rounded-md border border-input bg-background" value={form.status} onChange={e => setForm(p => ({ ...p, status: e.target.value as 'active' | 'suspended' | 'pending' }))}>
                <option value="active">{t('admin.users.active')}</option><option value="suspended">{t('admin.users.suspended')}</option><option value="pending">{t('admin.users.pending')}</option>
              </select>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <input type="checkbox" id="emailVerified" checked={form.email_verified} onChange={e => setForm(p => ({ ...p, email_verified: e.target.checked }))} className="rounded" />
            <Label htmlFor="emailVerified">{t('admin.users.emailVerifiedLabel')}</Label>
          </div>
          <div className="flex justify-end gap-2 pt-2">
            <Button variant="outline" onClick={onClose}>{t('common.cancel')}</Button>
            <Button onClick={handleUpdate} disabled={isLoading}>{isLoading ? <><Loader2 className="h-4 w-4 animate-spin mr-2" />{t('admin.users.updating')}</> : t('common.save')}</Button>
          </div>
        </div>
      </div>
    </div>
  );
}

/* 用户详情弹窗 */
function UserDetailDialog({ userData, onClose }: { userData: User; onClose: () => void }) {
  const { t, dateLocale } = useI18n();
  const [sendingReset, setSendingReset] = useState(false);
  const [resetResult, setResetResult] = useState<string | null>(null);
  const [unlocking, setUnlocking] = useState(false);

  const handleSendResetEmail = async () => {
    setSendingReset(true); setResetResult(null);
    const response = await api.sendResetEmail(userData.id);
    setResetResult(response.success ? t('admin.users.sendResetEmailSuccess') : (response.error?.message || t('admin.users.sendResetEmailFailed')));
    setSendingReset(false);
  };

  /* 管理员解锁用户账户 */
  const handleUnlockUser = async () => {
    setUnlocking(true); setResetResult(null);
    const response = await api.unlockUser(userData.id);
    setResetResult(response.success ? t('admin.users.unlockSuccess') : (response.error?.message || t('admin.users.unlockFailed')));
    setUnlocking(false);
  };

  const fields = [
    { label: 'ID', value: userData.id },
    { label: t('admin.users.emailLabel'), value: userData.email },
    { label: t('admin.users.usernameLabel'), value: userData.username },
    { label: t('admin.users.nicknameLabel'), value: userData.nickname },
    { label: t('admin.users.familyNameLabel'), value: userData.family_name },
    { label: t('admin.users.givenNameLabel'), value: userData.given_name },
    { label: t('admin.users.genderLabel'), value: userData.gender },
    { label: t('admin.users.phoneLabel'), value: userData.phone_number },
    { label: t('admin.users.companyLabel'), value: userData.company },
    { label: t('admin.users.departmentLabel'), value: userData.department },
    { label: t('admin.users.jobTitleLabel'), value: userData.job_title },
    { label: t('admin.users.roleLabel'), value: userData.role },
    { label: t('common.status'), value: userData.status || 'active' },
    { label: t('admin.users.emailVerifiedLabel'), value: userData.email_verified ? t('common.yes') : t('common.no') },
    { label: t('admin.users.createdAt'), value: userData.created_at ? new Date(userData.created_at).toLocaleString(dateLocale) : '-' },
    { label: t('admin.users.lastLoginAt'), value: userData.last_login_at ? new Date(userData.last_login_at).toLocaleString(dateLocale) : t('admin.users.neverLoggedIn') },
  ];

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50" onClick={onClose}>
      <div className="bg-white dark:bg-slate-900 rounded-lg shadow-xl p-6 w-full max-w-lg mx-4 max-h-[90vh] overflow-y-auto" onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold flex items-center gap-2"><Eye className="h-5 w-5" />{t('admin.users.userDetail')}</h3>
          <button onClick={onClose} className="text-muted-foreground hover:text-foreground"><X className="h-5 w-5" /></button>
        </div>
        <div className="flex items-center gap-4 p-4 bg-slate-50 dark:bg-slate-800 rounded-lg mb-4">
          <div className="h-14 w-14 rounded-full bg-primary/10 flex items-center justify-center overflow-hidden">
            {userData.avatar ? (<img src={userData.avatar} alt="" className="h-14 w-14 rounded-full object-cover" />) : (
              <span className="text-xl font-bold text-primary">{userData.username.charAt(0).toUpperCase()}</span>
            )}
          </div>
          <div>
            <h4 className="font-semibold">{userData.nickname || userData.username}</h4>
            <p className="text-sm text-muted-foreground">{userData.email}</p>
            <div className="flex gap-2 mt-1">
              <Badge variant={userData.role === 'admin' ? 'default' : 'secondary'} className="text-xs">{userData.role}</Badge>
              <Badge variant={userData.status === 'suspended' ? 'destructive' : 'outline'} className="text-xs">{userData.status || 'active'}</Badge>
            </div>
          </div>
        </div>
        <dl className="space-y-2">
          {fields.map(f => f.value ? (
            <div key={f.label} className="flex justify-between py-1.5 border-b border-dashed text-sm">
              <dt className="text-muted-foreground">{f.label}</dt>
              <dd className="font-medium text-right max-w-[60%] truncate">{f.value}</dd>
            </div>
          ) : null)}
        </dl>
        {resetResult && (<div className="mt-4 p-3 bg-blue-50 dark:bg-blue-950/30 text-blue-600 dark:text-blue-400 rounded-lg text-sm">{resetResult}</div>)}
        <div className="flex justify-end gap-2 mt-4">
          <Button variant="outline" size="sm" onClick={handleUnlockUser} disabled={unlocking}>
            {unlocking ? <Loader2 className="h-4 w-4 animate-spin mr-1" /> : <Unlock className="h-4 w-4 mr-1" />}{t('admin.users.unlock')}
          </Button>
          <Button variant="outline" size="sm" onClick={handleSendResetEmail} disabled={sendingReset}>
            {sendingReset ? <Loader2 className="h-4 w-4 animate-spin mr-1" /> : <Mail className="h-4 w-4 mr-1" />}{t('admin.users.sendResetEmail')}
          </Button>
          <Button variant="outline" onClick={onClose}>{t('common.confirm')}</Button>
        </div>
      </div>
    </div>
  );
}

export default function AdminPage() {
  const router = useRouter();
  const { user } = useAuth();
  const { t, dateLocale } = useI18n();
  const [stats, setStats] = useState<AdminStats | null>(null);
  const [users, setUsers] = useState<User[]>([]);
  const [loginTrend, setLoginTrend] = useState<LoginTrend[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [updatingUserId, setUpdatingUserId] = useState<string | null>(null);
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);
  const [limit] = useState(15);
  const [searchQuery, setSearchQuery] = useState('');
  const [searchInput, setSearchInput] = useState('');
  const [roleFilter, setRoleFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [selectedUsers, setSelectedUsers] = useState<Set<string>>(new Set());
  const [resetPasswordUser, setResetPasswordUser] = useState<{ id: string; name: string } | null>(null);
  const [actionMenuUser, setActionMenuUser] = useState<string | null>(null);
  const [showCreateDialog, setShowCreateDialog] = useState(false);
  const [editingUser, setEditingUser] = useState<User | null>(null);
  const [viewingUser, setViewingUser] = useState<User | null>(null);

  const loadStats = useCallback(async () => {
    const [statsRes, trendRes] = await Promise.all([api.getAdminStats(), api.getLoginTrend(7)]);
    if (statsRes.success && statsRes.data) setStats(statsRes.data);
    if (trendRes.success && trendRes.data) setLoginTrend(trendRes.data.trend);
  }, []);

  const loadUsers = useCallback(async () => {
    setIsLoading(true);
    let response;
    if (searchQuery || roleFilter || statusFilter) { response = await api.searchUsers(searchQuery, { role: roleFilter, status: statusFilter }, page, limit); }
    else { response = await api.getAdminUsers(page, limit); }
    if (response.success && response.data) { setUsers(response.data.users); setTotal(response.data.total); }
    setIsLoading(false);
  }, [page, limit, searchQuery, roleFilter, statusFilter]);

  useEffect(() => { if (user && user.role !== 'admin') { router.push('/dashboard'); return; } loadStats(); }, [user, router, loadStats]);
  useEffect(() => { loadUsers(); }, [loadUsers]);

  const handleSearch = () => { setPage(1); setSearchQuery(searchInput); };
  const clearSearch = () => { setSearchInput(''); setSearchQuery(''); setRoleFilter(''); setStatusFilter(''); setPage(1); };

  const handleRoleChange = async (userId: string, newRole: 'admin' | 'user') => {
    setUpdatingUserId(userId);
    const response = await api.updateUserRole(userId, newRole);
    if (response.success) { setUsers(users.map(u => u.id === userId ? { ...u, role: newRole } : u)); }
    setUpdatingUserId(null); setActionMenuUser(null);
  };

  const handleStatusChange = async (userId: string, newStatus: 'active' | 'suspended') => {
    setUpdatingUserId(userId);
    const response = await api.updateUserStatus(userId, newStatus);
    if (response.success) { setUsers(users.map(u => u.id === userId ? { ...u, status: newStatus } : u)); }
    setUpdatingUserId(null); setActionMenuUser(null);
  };

  const handleDeleteUser = async (userId: string) => {
    if (!confirm(t('admin.users.confirmDelete'))) return;
    const response = await api.deleteUser(userId);
    if (response.success) { await loadUsers(); loadStats(); }
    setActionMenuUser(null);
  };

  const handleBatchAction = async (action: string) => {
    const userIds = Array.from(selectedUsers);
    if (userIds.length === 0) return;
    if (action === 'delete') { if (!confirm(t('admin.users.batchConfirmDelete', { count: String(userIds.length) }))) return; await api.batchDeleteUsers(userIds); }
    else if (action === 'suspend') { await api.batchUpdateUserStatus(userIds, 'suspended'); }
    else if (action === 'activate') { await api.batchUpdateUserStatus(userIds, 'active'); }
    setSelectedUsers(new Set()); await loadUsers(); loadStats();
  };

  const toggleSelectAll = () => {
    if (selectedUsers.size === users.filter(u => u.id !== user?.id).length) { setSelectedUsers(new Set()); }
    else { setSelectedUsers(new Set(users.filter(u => u.id !== user?.id).map(u => u.id))); }
  };
  const toggleSelect = (id: string) => { const next = new Set(selectedUsers); if (next.has(id)) next.delete(id); else next.add(id); setSelectedUsers(next); };
  const totalPages = Math.ceil(total / limit);

  if (user?.role !== 'admin') return null;

  return (
    <div className="space-y-6">
      <PageHeader icon={Shield} title={t('admin.title')} description={t('admin.users.description')} />

      {/* Stats Cards */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card><CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2"><CardTitle className="text-sm font-medium">{t('admin.stats.users')}</CardTitle><Users className="h-4 w-4 text-muted-foreground" /></CardHeader><CardContent><div className="text-2xl font-bold">{stats?.users || 0}</div><p className="text-xs text-muted-foreground">{stats?.active_users || 0} {t('admin.stats.activeUsers')}</p></CardContent></Card>
        <Card><CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2"><CardTitle className="text-sm font-medium">{t('admin.stats.apps')}</CardTitle><AppWindow className="h-4 w-4 text-muted-foreground" /></CardHeader><CardContent><div className="text-2xl font-bold">{stats?.applications || 0}</div><p className="text-xs text-muted-foreground">OAuth2</p></CardContent></Card>
        <Card><CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2"><CardTitle className="text-sm font-medium">{t('admin.stats.todayLogins')}</CardTitle><Activity className="h-4 w-4 text-muted-foreground" /></CardHeader><CardContent><div className="text-2xl font-bold">{stats?.today_logins || 0}</div><p className="text-xs text-muted-foreground">{t('admin.stats.last24h')}</p></CardContent></Card>
        <Card><CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2"><CardTitle className="text-sm font-medium">{t('admin.stats.loginSuccess')}</CardTitle><TrendingUp className="h-4 w-4 text-muted-foreground" /></CardHeader><CardContent><div className="text-2xl font-bold">{stats?.login_stats ? Math.round((stats.login_stats.successful_logins / Math.max(stats.login_stats.total_logins, 1)) * 100) : 0}%</div><p className="text-xs text-muted-foreground">{stats?.login_stats?.successful_logins || 0} / {stats?.login_stats?.total_logins || 0}</p></CardContent></Card>
      </div>

      {/* Login Trend */}
      {loginTrend.length > 0 && (
        <Card>
          <CardHeader><CardTitle className="flex items-center gap-2"><Clock className="h-5 w-5" />{t('admin.stats.loginTrend')}</CardTitle><CardDescription>{t('admin.stats.last7days')}</CardDescription></CardHeader>
          <CardContent>
            <div className="h-[180px] flex items-end gap-2">
              {loginTrend.map((day, i) => { const maxCount = Math.max(...loginTrend.map(d => d.total_count), 1); const height = (day.total_count / maxCount) * 100; const successRate = day.total_count > 0 ? (day.success / day.total_count) * 100 : 0; return (
                <div key={i} className="flex-1 flex flex-col items-center gap-1">
                  <div className="w-full relative" style={{ height: '140px' }}><div className="absolute bottom-0 w-full bg-primary/20 rounded-t transition-all" style={{ height: `${height}%` }}><div className="absolute bottom-0 w-full bg-primary rounded-t" style={{ height: `${successRate}%` }} /></div></div>
                  <span className="text-xs text-muted-foreground">{new Date(day.date).toLocaleDateString(dateLocale, { weekday: 'short' })}</span>
                  <span className="text-xs font-medium">{day.total_count}</span>
                </div>
              ); })}
            </div>
            <div className="flex justify-center gap-6 mt-3 text-xs">
              <div className="flex items-center gap-2"><div className="w-3 h-3 bg-primary rounded" /><span>{t('admin.stats.successful')}</span></div>
              <div className="flex items-center gap-2"><div className="w-3 h-3 bg-primary/20 rounded" /><span>{t('admin.stats.failed')}</span></div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* User Management */}
      <Card>
        <CardHeader>
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div>
              <CardTitle className="flex items-center gap-2">
                <Users className="h-5 w-5" />
                {t('admin.users.title')}
              </CardTitle>
              <CardDescription>{t('admin.users.description')}</CardDescription>
            </div>
            <div className="flex gap-2">
              <Button variant="outline" size="sm" onClick={() => window.open(api.getExportUsersUrl('csv'), '_blank')}>
                <Download className="h-4 w-4 mr-1" />{t('admin.users.exportUsers')}
              </Button>
              <Button size="sm" onClick={() => setShowCreateDialog(true)}>
                <UserPlus className="h-4 w-4 mr-1" />{t('admin.users.createUser')}
              </Button>
            </div>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* Search & Filters */}
          <div className="flex flex-col sm:flex-row gap-3">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder={t('admin.users.searchPlaceholder')}
                value={searchInput}
                onChange={e => setSearchInput(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && handleSearch()}
                className="pl-9"
              />
            </div>
            <select
              className="h-10 px-3 rounded-md border border-input bg-background text-sm"
              value={roleFilter}
              onChange={e => { setRoleFilter(e.target.value); setPage(1); }}
            >
              <option value="">{t('admin.users.allRoles')}</option>
              <option value="admin">{t('admin.users.admin')}</option>
              <option value="user">{t('admin.users.user')}</option>
            </select>
            <select
              className="h-10 px-3 rounded-md border border-input bg-background text-sm"
              value={statusFilter}
              onChange={e => { setStatusFilter(e.target.value); setPage(1); }}
            >
              <option value="">{t('admin.users.allStatus')}</option>
              <option value="active">{t('admin.users.active')}</option>
              <option value="suspended">{t('admin.users.suspended')}</option>
              <option value="pending">{t('admin.users.pending')}</option>
            </select>
            <Button variant="outline" onClick={handleSearch}>
              <Search className="h-4 w-4" />
            </Button>
            {(searchQuery || roleFilter || statusFilter) && (
              <Button variant="ghost" onClick={clearSearch}>
                <X className="h-4 w-4 mr-1" />{t('common.clear')}
              </Button>
            )}
          </div>

          {/* Batch Actions */}
          {selectedUsers.size > 0 && (
            <div className="flex items-center gap-3 p-3 bg-primary/5 rounded-lg">
              <span className="text-sm font-medium">{t('common.selected', { count: String(selectedUsers.size) })}</span>
              <div className="flex gap-2 ml-auto">
                <Button variant="outline" size="sm" onClick={() => handleBatchAction('activate')}>
                  <UserCheck className="h-4 w-4 mr-1" />{t('admin.users.batchActivate')}
                </Button>
                <Button variant="outline" size="sm" onClick={() => handleBatchAction('suspend')}>
                  <Ban className="h-4 w-4 mr-1" />{t('admin.users.batchSuspend')}
                </Button>
                <Button variant="destructive" size="sm" onClick={() => handleBatchAction('delete')}>
                  <Trash2 className="h-4 w-4 mr-1" />{t('admin.users.batchDelete')}
                </Button>
              </div>
            </div>
          )}

          {/* User Table */}
          {isLoading ? (
            <div className="flex justify-center py-8">
              <Loader2 className="h-8 w-8 animate-spin text-primary" />
            </div>
          ) : users.length === 0 ? (
            <div className="text-center py-8 text-muted-foreground">
              {t('admin.users.noResults')}
            </div>
          ) : (
            <div className="border rounded-lg overflow-hidden">
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead className="bg-muted/50">
                    <tr>
                      <th className="p-3 text-left w-10">
                        <input
                          type="checkbox"
                          checked={selectedUsers.size === users.filter(u => u.id !== user?.id).length && users.length > 0}
                          onChange={toggleSelectAll}
                          className="rounded"
                        />
                      </th>
                      <th className="p-3 text-left">{t('admin.users.usernameLabel')}</th>
                      <th className="p-3 text-left hidden md:table-cell">{t('admin.users.emailLabel')}</th>
                      <th className="p-3 text-left">{t('admin.users.roleLabel')}</th>
                      <th className="p-3 text-left">{t('common.status')}</th>
                      <th className="p-3 text-left hidden lg:table-cell">{t('admin.users.lastLoginAt')}</th>
                      <th className="p-3 text-right">{t('common.actions')}</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y">
                    {users.map(u => (
                      <tr key={u.id} className="hover:bg-muted/30 transition-colors">
                        <td className="p-3">
                          {u.id !== user?.id && (
                            <input
                              type="checkbox"
                              checked={selectedUsers.has(u.id)}
                              onChange={() => toggleSelect(u.id)}
                              className="rounded"
                            />
                          )}
                        </td>
                        <td className="p-3">
                          <div className="flex items-center gap-3">
                            <div className="h-8 w-8 rounded-full bg-primary/10 flex items-center justify-center overflow-hidden flex-shrink-0">
                              {u.avatar ? (
                                <img src={u.avatar} alt="" className="h-8 w-8 rounded-full object-cover" />
                              ) : (
                                <span className="text-xs font-medium text-primary">{u.username.charAt(0).toUpperCase()}</span>
                              )}
                            </div>
                            <div className="min-w-0">
                              <div className="font-medium truncate">{u.nickname || u.username}</div>
                              <div className="text-xs text-muted-foreground truncate md:hidden">{u.email}</div>
                            </div>
                          </div>
                        </td>
                        <td className="p-3 hidden md:table-cell">
                          <div className="flex items-center gap-1">
                            <span className="truncate max-w-[200px]">{u.email}</span>
                            {u.email_verified ? (
                              <CheckCircle className="h-3.5 w-3.5 text-green-500 flex-shrink-0" />
                            ) : (
                              <XCircle className="h-3.5 w-3.5 text-orange-400 flex-shrink-0" />
                            )}
                          </div>
                        </td>
                        <td className="p-3">
                          <Badge variant={u.role === 'admin' ? 'default' : 'secondary'} className="text-xs">
                            {u.role === 'admin' ? t('admin.users.admin') : t('admin.users.user')}
                          </Badge>
                        </td>
                        <td className="p-3">
                          <div className="flex gap-1 flex-wrap">
                            <Badge
                              variant={u.status === 'suspended' ? 'destructive' : u.status === 'pending' ? 'outline' : 'secondary'}
                              className="text-xs"
                            >
                              {u.status === 'suspended' ? t('admin.users.suspended') : u.status === 'pending' ? t('admin.users.pending') : t('admin.users.active')}
                            </Badge>
                            {u.locked_until && new Date(u.locked_until) > new Date() && (
                              <Badge variant="destructive" className="text-xs">
                                {t('admin.users.locked')}
                              </Badge>
                            )}
                          </div>
                        </td>
                        <td className="p-3 hidden lg:table-cell text-muted-foreground text-xs">
                          {u.last_login_at ? new Date(u.last_login_at).toLocaleString(dateLocale) : t('admin.users.neverLoggedIn')}
                        </td>
                        <td className="p-3 text-right">
                          <div className="relative inline-block">
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => setActionMenuUser(actionMenuUser === u.id ? null : u.id)}
                              disabled={updatingUserId === u.id}
                            >
                              {updatingUserId === u.id ? (
                                <Loader2 className="h-4 w-4 animate-spin" />
                              ) : (
                                <MoreHorizontal className="h-4 w-4" />
                              )}
                            </Button>
                            {actionMenuUser === u.id && (
                              <div className="absolute right-0 top-full mt-1 w-48 bg-white dark:bg-slate-900 rounded-lg shadow-lg border z-50 py-1">
                                <button
                                  className="w-full px-4 py-2 text-left text-sm hover:bg-muted/50 flex items-center gap-2"
                                  onClick={() => { setViewingUser(u); setActionMenuUser(null); }}
                                >
                                  <Eye className="h-4 w-4" />{t('admin.users.viewDetail')}
                                </button>
                                <button
                                  className="w-full px-4 py-2 text-left text-sm hover:bg-muted/50 flex items-center gap-2"
                                  onClick={() => { setEditingUser(u); setActionMenuUser(null); }}
                                >
                                  <Pencil className="h-4 w-4" />{t('common.edit')}
                                </button>
                                <button
                                  className="w-full px-4 py-2 text-left text-sm hover:bg-muted/50 flex items-center gap-2"
                                  onClick={() => { setResetPasswordUser({ id: u.id, name: u.username }); setActionMenuUser(null); }}
                                >
                                  <KeyRound className="h-4 w-4" />{t('admin.users.resetPassword')}
                                </button>
                                <hr className="my-1" />
                                {u.role === 'user' ? (
                                  <button
                                    className="w-full px-4 py-2 text-left text-sm hover:bg-muted/50 flex items-center gap-2"
                                    onClick={() => handleRoleChange(u.id, 'admin')}
                                  >
                                    <Shield className="h-4 w-4" />{t('admin.users.promoteAdmin')}
                                  </button>
                                ) : u.id !== user?.id && (
                                  <button
                                    className="w-full px-4 py-2 text-left text-sm hover:bg-muted/50 flex items-center gap-2"
                                    onClick={() => handleRoleChange(u.id, 'user')}
                                  >
                                    <UserCog className="h-4 w-4" />{t('admin.users.demoteUser')}
                                  </button>
                                )}
                                {u.status === 'active' ? (
                                  <button
                                    className="w-full px-4 py-2 text-left text-sm hover:bg-muted/50 flex items-center gap-2 text-orange-500"
                                    onClick={() => handleStatusChange(u.id, 'suspended')}
                                  >
                                    <Ban className="h-4 w-4" />{t('admin.users.disableAccount')}
                                  </button>
                                ) : (
                                  <button
                                    className="w-full px-4 py-2 text-left text-sm hover:bg-muted/50 flex items-center gap-2 text-green-500"
                                    onClick={() => handleStatusChange(u.id, 'active')}
                                  >
                                    <UserCheck className="h-4 w-4" />{t('admin.users.enableAccount')}
                                  </button>
                                )}
                                {u.id !== user?.id && (
                                  <button
                                    className="w-full px-4 py-2 text-left text-sm hover:bg-muted/50 flex items-center gap-2 text-red-500"
                                    onClick={() => handleDeleteUser(u.id)}
                                  >
                                    <Trash2 className="h-4 w-4" />{t('admin.users.deleteUser')}
                                  </button>
                                )}
                              </div>
                            )}
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="flex items-center justify-between pt-4">
              <span className="text-sm text-muted-foreground">
                {t('common.page', { current: String(page), total: String(totalPages) })}
              </span>
              <div className="flex gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setPage(p => Math.max(1, p - 1))}
                  disabled={page === 1}
                >
                  <ChevronLeft className="h-4 w-4" />
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setPage(p => Math.min(totalPages, p + 1))}
                  disabled={page === totalPages}
                >
                  <ChevronRight className="h-4 w-4" />
                </Button>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Dialogs */}
      {resetPasswordUser && (
        <ResetPasswordDialog
          userId={resetPasswordUser.id}
          userName={resetPasswordUser.name}
          onClose={() => setResetPasswordUser(null)}
        />
      )}
      {showCreateDialog && (
        <CreateUserDialog
          onClose={() => setShowCreateDialog(false)}
          onSuccess={() => { loadUsers(); loadStats(); }}
        />
      )}
      {editingUser && (
        <EditUserDialog
          userData={editingUser}
          onClose={() => setEditingUser(null)}
          onSuccess={() => { loadUsers(); loadStats(); }}
        />
      )}
      {viewingUser && (
        <UserDetailDialog
          userData={viewingUser}
          onClose={() => setViewingUser(null)}
        />
      )}
    </div>
  );
}
