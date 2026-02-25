'use client';

import { useState, useEffect, useRef } from 'react';
import { useAuth } from '@/lib/auth-context';
import { useI18n } from '@/lib/i18n';
import { api } from '@/lib/api';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import {
  User, Mail, Calendar, Shield, Loader2, Check, AlertCircle, Globe, Phone, Github, Twitter,
  Lock, Eye, EyeOff, BadgeCheck, Send, RefreshCw, Camera, Trash2, Briefcase, MapPin
} from 'lucide-react';
import { PasswordStrength } from '@/components/ui/password-strength';
import { Dialog, DialogPanel, DialogTitle, Transition, TransitionChild } from '@headlessui/react';
import { Fragment } from 'react';
import type { UpdateProfileRequest, AddressInfo } from '@/lib/types';

/* 头像上传组件 */
function AvatarUploadCard({ user, onRefresh }: { user: { avatar?: string; username: string; nickname?: string }; onRefresh: () => void }) {
  const { t } = useI18n();
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [isUploading, setIsUploading] = useState(false);
  const [isDeleting, setIsDeleting] = useState(false);
  const [avatarError, setAvatarError] = useState<string | null>(null);
  const [avatarSuccess, setAvatarSuccess] = useState<string | null>(null);

  const handleUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setAvatarError(null);
    setAvatarSuccess(null);
    if (file.size > 5 * 1024 * 1024) {
      setAvatarError(t('profile.avatarMaxSize'));
      return;
    }
    setIsUploading(true);
    const response = await api.uploadAvatar(file);
    if (response.success) {
      setAvatarSuccess(t('profile.avatarUploadSuccess'));
      onRefresh();
      setTimeout(() => setAvatarSuccess(null), 3000);
    } else {
      setAvatarError(response.error?.message || t('profile.avatarUploadFailed'));
    }
    setIsUploading(false);
    if (fileInputRef.current) fileInputRef.current.value = '';
  };

  const handleDelete = async () => {
    setAvatarError(null);
    setAvatarSuccess(null);
    setIsDeleting(true);
    const response = await api.deleteAvatar();
    if (response.success) {
      setAvatarSuccess(t('profile.avatarDeleteSuccess'));
      onRefresh();
      setTimeout(() => setAvatarSuccess(null), 3000);
    } else {
      setAvatarError(response.error?.message || t('profile.avatarDeleteFailed'));
    }
    setIsDeleting(false);
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2"><Camera className="h-5 w-5" />{t('profile.avatarTitle')}</CardTitle>
        <CardDescription>{t('profile.avatarDesc')}</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {avatarError && (
          <div className="flex items-center gap-2 p-3 bg-red-50 dark:bg-red-950/30 text-red-600 dark:text-red-400 rounded-lg text-sm">
            <AlertCircle className="h-4 w-4 flex-shrink-0" />{avatarError}
          </div>
        )}
        {avatarSuccess && (
          <div className="flex items-center gap-2 p-3 bg-green-50 dark:bg-green-950/30 text-green-600 dark:text-green-400 rounded-lg text-sm">
            <Check className="h-4 w-4 flex-shrink-0" />{avatarSuccess}
          </div>
        )}
        <div className="flex items-center gap-6">
          <div className="relative group">
            <div className="h-24 w-24 rounded-full bg-primary/10 flex items-center justify-center overflow-hidden ring-2 ring-primary/20">
              {user.avatar ? (
                <img src={user.avatar} alt="avatar" className="h-24 w-24 rounded-full object-cover" />
              ) : (
                <span className="text-3xl font-bold text-primary">
                  {user.nickname?.charAt(0) || user.username?.charAt(0).toUpperCase() || 'U'}
                </span>
              )}
            </div>
            <button type="button" onClick={() => fileInputRef.current?.click()}
              className="absolute inset-0 rounded-full bg-black/40 opacity-0 group-hover:opacity-100 transition-opacity flex items-center justify-center">
              <Camera className="h-6 w-6 text-white" />
            </button>
          </div>
          <div className="space-y-2">
            <input ref={fileInputRef} type="file" accept="image/jpeg,image/png,image/gif,image/webp" onChange={handleUpload} className="hidden" />
            <div className="flex gap-2">
              <Button variant="outline" size="sm" onClick={() => fileInputRef.current?.click()} disabled={isUploading}>
                {isUploading ? <Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin" /> : <Camera className="mr-1.5 h-3.5 w-3.5" />}
                {isUploading ? t('profile.avatarUploading') : t('profile.avatarUpload')}
              </Button>
              {user.avatar && (
                <Button variant="outline" size="sm" onClick={handleDelete} disabled={isDeleting} className="text-red-500 hover:text-red-600">
                  {isDeleting ? <Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin" /> : <Trash2 className="mr-1.5 h-3.5 w-3.5" />}
                  {t('profile.avatarDelete')}
                </Button>
              )}
            </div>
            <p className="text-xs text-muted-foreground">{t('profile.avatarMaxSize')}</p>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

/* 邮箱管理卡片组件 */
function EmailManagementCard({ user }: { user: { email: string; email_verified: boolean } }) {
  const { t } = useI18n();
  const [isSending, setIsSending] = useState(false);
  const [sendSuccess, setSendSuccess] = useState(false);
  const [emailError, setEmailError] = useState<string | null>(null);
  const [showChangeEmail, setShowChangeEmail] = useState(false);
  const [newEmail, setNewEmail] = useState('');
  const [isChanging, setIsChanging] = useState(false);
  const [changeSuccess, setChangeSuccess] = useState(false);

  const handleSendVerification = async () => {
    setEmailError(null); setSendSuccess(false); setIsSending(true);
    const response = await api.sendEmailVerification();
    if (response.success) { setSendSuccess(true); setTimeout(() => setSendSuccess(false), 5000); }
    else { setEmailError(response.error?.message || t('profile.email.sendFailed')); }
    setIsSending(false);
  };

  const handleChangeEmail = async () => {
    setEmailError(null); setChangeSuccess(false);
    if (!newEmail || !newEmail.includes('@')) { setEmailError(t('profile.email.invalidEmail')); return; }
    setIsChanging(true);
    const response = await api.requestEmailChange(newEmail);
    if (response.success) { setChangeSuccess(true); setNewEmail(''); setShowChangeEmail(false); setTimeout(() => setChangeSuccess(false), 5000); }
    else { setEmailError(response.error?.message || t('profile.email.changeFailed')); }
    setIsChanging(false);
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2"><Mail className="h-5 w-5" />{t('profile.email.title')}</CardTitle>
        <CardDescription>{t('profile.email.description')}</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {emailError && (<div className="flex items-center gap-2 p-3 bg-red-50 dark:bg-red-950/30 text-red-600 dark:text-red-400 rounded-lg text-sm"><AlertCircle className="h-4 w-4 flex-shrink-0" />{emailError}</div>)}
        {sendSuccess && (<div className="flex items-center gap-2 p-3 bg-green-50 dark:bg-green-950/30 text-green-600 dark:text-green-400 rounded-lg text-sm"><Check className="h-4 w-4 flex-shrink-0" />{t('profile.email.verificationSent')}</div>)}
        {changeSuccess && (<div className="flex items-center gap-2 p-3 bg-green-50 dark:bg-green-950/30 text-green-600 dark:text-green-400 rounded-lg text-sm"><Check className="h-4 w-4 flex-shrink-0" />{t('profile.email.changeSent')}</div>)}
        <div className="flex items-center justify-between p-4 bg-slate-50 dark:bg-slate-800 rounded-lg">
          <div className="flex items-center gap-3">
            <Mail className="h-5 w-5 text-muted-foreground" />
            <div>
              <p className="font-medium">{user.email}</p>
              <div className="flex items-center gap-1.5 mt-0.5">
                {user.email_verified ? (
                  <span className="inline-flex items-center gap-1 text-xs text-green-600 dark:text-green-400"><BadgeCheck className="h-3.5 w-3.5" />{t('profile.email.verified')}</span>
                ) : (
                  <span className="inline-flex items-center gap-1 text-xs text-orange-500"><AlertCircle className="h-3.5 w-3.5" />{t('profile.email.unverified')}</span>
                )}
              </div>
            </div>
          </div>
          <div className="flex gap-2">
            {!user.email_verified && (
              <Button variant="outline" size="sm" onClick={handleSendVerification} disabled={isSending}>
                {isSending ? <Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin" /> : <Send className="mr-1.5 h-3.5 w-3.5" />}
                {t('profile.email.sendVerification')}
              </Button>
            )}
            <Button variant="outline" size="sm" onClick={() => setShowChangeEmail(!showChangeEmail)}>
              <RefreshCw className="mr-1.5 h-3.5 w-3.5" />{t('profile.email.changeEmail')}
            </Button>
          </div>
        </div>
        {showChangeEmail && (
          <div className="space-y-3 p-4 border rounded-lg">
            <Label>{t('profile.email.newEmailLabel')}</Label>
            <div className="flex gap-2">
              <Input type="email" value={newEmail} onChange={(e) => setNewEmail(e.target.value)} placeholder={t('profile.email.newEmailPlaceholder')} />
              <Button onClick={handleChangeEmail} disabled={isChanging}>
                {isChanging ? <Loader2 className="mr-1.5 h-4 w-4 animate-spin" /> : null}{t('profile.email.sendVerification')}
              </Button>
            </div>
            <p className="text-xs text-muted-foreground">{t('profile.email.changeHint')}</p>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

/* 删除账号危险区域组件 — 使用 Headless UI Dialog 模态弹窗 */
function DeleteAccountCard() {
  const { t } = useI18n();
  const { logout } = useAuth();
  const [isOpen, setIsOpen] = useState(false);
  const [password, setPassword] = useState('');
  const [showPwd, setShowPwd] = useState(false);
  const [isDeleting, setIsDeleting] = useState(false);
  const [deleteError, setDeleteError] = useState<string | null>(null);
  const [confirmText, setConfirmText] = useState('');

  const closeDialog = () => { setIsOpen(false); setPassword(''); setConfirmText(''); setDeleteError(null); setShowPwd(false); };

  const handleDelete = async () => {
    setDeleteError(null);
    if (confirmText !== 'DELETE') {
      setDeleteError(t('profile.deleteConfirmMismatch') || 'Please type DELETE to confirm');
      return;
    }
    setIsDeleting(true);
    const response = await api.deleteAccount(password);
    if (response.success) {
      logout();
    } else {
      setDeleteError(response.error?.message || t('profile.deleteAccountFailed') || 'Failed to delete account');
    }
    setIsDeleting(false);
  };

  return (
    <>
      <Card className="border-red-200 dark:border-red-900">
        <CardHeader>
          <CardTitle className="text-red-600 dark:text-red-400">{t('profile.dangerZone')}</CardTitle>
          <CardDescription>{t('profile.dangerZoneDesc')}</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex items-center justify-between">
            <div>
              <h4 className="font-medium">{t('profile.deleteAccount')}</h4>
              <p className="text-sm text-muted-foreground">{t('profile.deleteAccountDesc')}</p>
            </div>
            <Button variant="outline" className="text-red-600 hover:bg-red-50 hover:text-red-700 dark:hover:bg-red-950/30" onClick={() => setIsOpen(true)}>
              <Trash2 className="mr-1.5 h-4 w-4" />{t('profile.deleteAccount')}
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Headless UI 模态确认弹窗 */}
      <Transition appear show={isOpen} as={Fragment}>
        <Dialog as="div" className="relative z-50" onClose={closeDialog}>
          <TransitionChild as={Fragment} enter="ease-out duration-200" enterFrom="opacity-0" enterTo="opacity-100" leave="ease-in duration-150" leaveFrom="opacity-100" leaveTo="opacity-0">
            <div className="fixed inset-0 bg-black/40 backdrop-blur-sm" />
          </TransitionChild>
          <div className="fixed inset-0 overflow-y-auto">
            <div className="flex min-h-full items-center justify-center p-4">
              <TransitionChild as={Fragment} enter="ease-out duration-200" enterFrom="opacity-0 scale-95" enterTo="opacity-100 scale-100" leave="ease-in duration-150" leaveFrom="opacity-100 scale-100" leaveTo="opacity-0 scale-95">
                <DialogPanel className="w-full max-w-md rounded-xl bg-white dark:bg-slate-900 p-6 shadow-2xl border border-red-200 dark:border-red-900">
                  <div className="flex items-start gap-3 mb-4">
                    <div className="flex-shrink-0 h-10 w-10 rounded-full bg-red-100 dark:bg-red-950/40 flex items-center justify-center">
                      <AlertCircle className="h-5 w-5 text-red-600" />
                    </div>
                    <div>
                      <DialogTitle className="text-lg font-semibold text-red-600 dark:text-red-400">
                        {t('profile.deleteAccountWarning') || 'This action cannot be undone'}
                      </DialogTitle>
                      <p className="text-sm text-muted-foreground mt-1">
                        {t('profile.deleteAccountWarningDesc') || 'All your data, authorizations, and tokens will be permanently deleted.'}
                      </p>
                    </div>
                  </div>

                  {deleteError && (
                    <div className="flex items-center gap-2 p-3 mb-4 bg-red-100 dark:bg-red-950/40 text-red-600 dark:text-red-400 rounded-lg text-sm">
                      <AlertCircle className="h-4 w-4 flex-shrink-0" />{deleteError}
                    </div>
                  )}

                  <div className="space-y-4">
                    <div className="space-y-2">
                      <Label>{t('profile.currentPasswordLabel') || 'Current Password'}</Label>
                      <div className="relative">
                        <Input type={showPwd ? 'text' : 'password'} value={password} onChange={(e) => setPassword(e.target.value)} placeholder={t('profile.currentPasswordPlaceholder') || 'Enter your password'} autoComplete="current-password" />
                        <button type="button" className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground" onClick={() => setShowPwd(!showPwd)}>
                          {showPwd ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                        </button>
                      </div>
                    </div>
                    <div className="space-y-2">
                      <Label>{t('profile.deleteConfirmLabel') || 'Type DELETE to confirm'}</Label>
                      <Input value={confirmText} onChange={(e) => setConfirmText(e.target.value)} placeholder="DELETE" className="font-mono" />
                    </div>
                  </div>

                  <div className="flex gap-2 justify-end mt-6">
                    <Button variant="outline" onClick={closeDialog}>
                      {t('profile.cancel') || 'Cancel'}
                    </Button>
                    <Button variant="destructive" onClick={handleDelete} disabled={isDeleting || confirmText !== 'DELETE'}>
                      {isDeleting ? <Loader2 className="mr-1.5 h-4 w-4 animate-spin" /> : <Trash2 className="mr-1.5 h-4 w-4" />}
                      {isDeleting ? (t('profile.deleting') || 'Deleting...') : (t('profile.confirmDelete') || 'Permanently Delete Account')}
                    </Button>
                  </div>
                </DialogPanel>
              </TransitionChild>
            </div>
          </div>
        </Dialog>
      </Transition>
    </>
  );
}

/* 修改密码卡片组件 */
function ChangePasswordCard() {
  const { t } = useI18n();
  const [oldPassword, setOldPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showOld, setShowOld] = useState(false);
  const [showNew, setShowNew] = useState(false);
  const [isChanging, setIsChanging] = useState(false);
  const [pwdError, setPwdError] = useState<string | null>(null);
  const [pwdSuccess, setPwdSuccess] = useState(false);

  const handleChangePassword = async () => {
    setPwdError(null); setPwdSuccess(false);
    if (newPassword.length < 8) { setPwdError(t('profile.passwordMinLength')); return; }
    if (newPassword !== confirmPassword) { setPwdError(t('profile.passwordMismatch')); return; }
    setIsChanging(true);
    const response = await api.changePassword(oldPassword, newPassword);
    if (response.success) { setPwdSuccess(true); setOldPassword(''); setNewPassword(''); setConfirmPassword(''); setTimeout(() => setPwdSuccess(false), 3000); }
    else { setPwdError(response.error?.message || t('profile.passwordFailed')); }
    setIsChanging(false);
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2"><Lock className="h-5 w-5" />{t('profile.passwordTitle')}</CardTitle>
        <CardDescription>{t('profile.passwordDesc')}</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {pwdError && (<div className="flex items-center gap-2 p-3 bg-red-50 dark:bg-red-950/30 text-red-600 dark:text-red-400 rounded-lg text-sm"><AlertCircle className="h-4 w-4 flex-shrink-0" />{pwdError}</div>)}
        {pwdSuccess && (<div className="flex items-center gap-2 p-3 bg-green-50 dark:bg-green-950/30 text-green-600 dark:text-green-400 rounded-lg text-sm"><Check className="h-4 w-4 flex-shrink-0" />{t('profile.passwordSuccess')}</div>)}
        <div className="space-y-2">
          <Label>{t('profile.currentPasswordLabel')}</Label>
          <div className="relative">
            <Input type={showOld ? 'text' : 'password'} value={oldPassword} onChange={(e) => setOldPassword(e.target.value)} placeholder={t('profile.currentPasswordPlaceholder')} autoComplete="current-password" />
            <button type="button" className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground" onClick={() => setShowOld(!showOld)}>
              {showOld ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
            </button>
          </div>
        </div>
        <div className="grid gap-4 md:grid-cols-2">
          <div className="space-y-2">
            <Label>{t('profile.newPasswordLabel')}</Label>
            <div className="relative">
              <Input type={showNew ? 'text' : 'password'} value={newPassword} onChange={(e) => setNewPassword(e.target.value)} placeholder={t('profile.newPasswordPlaceholder')} autoComplete="new-password" />
              <button type="button" className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground" onClick={() => setShowNew(!showNew)}>
                {showNew ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
              </button>
            </div>
            <PasswordStrength password={newPassword} />
          </div>
          <div className="space-y-2">
            <Label>{t('profile.confirmPasswordLabel')}</Label>
            <Input type="password" value={confirmPassword} onChange={(e) => setConfirmPassword(e.target.value)} placeholder={t('profile.confirmPasswordPlaceholder')} autoComplete="new-password" />
          </div>
        </div>
        <div className="flex justify-end">
          <Button onClick={handleChangePassword} disabled={isChanging} variant="outline">
            {isChanging ? (<><Loader2 className="mr-2 h-4 w-4 animate-spin" />{t('profile.changingPassword')}</>) : t('profile.changePasswordBtn')}
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

export default function ProfilePage() {
  const { user, refreshUser } = useAuth();
  const { t, dateLocale } = useI18n();
  const [isSaving, setIsSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [form, setForm] = useState<UpdateProfileRequest>({});
  const [address, setAddress] = useState<AddressInfo>({});

  useEffect(() => {
    if (user) {
      setForm({
        username: user.username, nickname: user.nickname || '', given_name: user.given_name || '',
        family_name: user.family_name || '', gender: user.gender || '', birthdate: user.birthdate || '',
        phone_number: user.phone_number || '', website: user.website || '', bio: user.bio || '',
        social_accounts: user.social_accounts || {}, company: user.company || '',
        department: user.department || '', job_title: user.job_title || '',
        locale: user.locale || '', zoneinfo: user.zoneinfo || '',
      });
      setAddress(user.address || {});
    }
  }, [user]);

  const handleSave = async () => {
    setIsSaving(true); setError(null);
    const payload: UpdateProfileRequest = { ...form, address: Object.values(address).some(v => v) ? address : undefined };
    const response = await api.updateProfile(payload);
    if (response.success) { setSaved(true); setTimeout(() => setSaved(false), 2000); refreshUser(); }
    else { setError(response.error?.message || t('profile.updateFailed')); }
    setIsSaving(false);
  };

  const updateForm = (field: keyof UpdateProfileRequest, value: string) => { setForm(prev => ({ ...prev, [field]: value })); };
  const updateSocialAccount = (platform: string, value: string) => { setForm(prev => ({ ...prev, social_accounts: { ...(prev.social_accounts || {}), [platform]: value } })); };
  const updateAddress = (field: keyof AddressInfo, value: string) => { setAddress(prev => ({ ...prev, [field]: value })); };

  if (!user) { return (<div className="flex items-center justify-center py-12"><Loader2 className="h-8 w-8 animate-spin text-primary" /></div>); }

  return (
    <div className="max-w-2xl mx-auto space-y-6">
      <div>
        <h1 className="text-3xl font-bold">{t('profile.title')}</h1>
        <p className="text-muted-foreground mt-1">{t('profile.description')}</p>
      </div>

      {error && (<div className="flex items-center gap-2 p-3 bg-red-50 dark:bg-red-950/30 text-red-600 dark:text-red-400 rounded-lg text-sm"><AlertCircle className="h-4 w-4" />{error}</div>)}

      {/* Avatar Upload */}
      <AvatarUploadCard user={user} onRefresh={refreshUser} />

      {/* Basic Info */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2"><User className="h-5 w-5" />{t('profile.basicInfo')}</CardTitle>
          <CardDescription>{t('profile.basicInfoDesc')}</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center gap-4 p-4 bg-slate-50 dark:bg-slate-800 rounded-lg">
            <div className="h-16 w-16 rounded-full bg-primary/10 flex items-center justify-center overflow-hidden">
              {user.avatar ? (<img src={user.avatar} alt="" className="h-16 w-16 rounded-full object-cover" />) : (
                <span className="text-2xl font-bold text-primary">{user.nickname?.charAt(0) || user.username?.charAt(0).toUpperCase() || 'U'}</span>
              )}
            </div>
            <div>
              <h3 className="font-semibold text-lg">{user.nickname || user.username}</h3>
              <p className="text-sm text-muted-foreground">{user.email}</p>
              {!user.profile_completed && (<p className="text-xs text-orange-500 mt-1">{t('profile.completeProfile')}</p>)}
            </div>
          </div>
          <div className="grid gap-4 md:grid-cols-2">
            <div className="space-y-2"><Label>{t('profile.usernameLabel')}</Label><Input value={form.username || ''} onChange={(e) => updateForm('username', e.target.value)} /></div>
            <div className="space-y-2"><Label>{t('profile.nicknameLabel')}</Label><Input value={form.nickname || ''} onChange={(e) => updateForm('nickname', e.target.value)} placeholder={t('profile.nicknamePlaceholder')} /></div>
            <div className="space-y-2"><Label>{t('profile.familyNameLabel')}</Label><Input value={form.family_name || ''} onChange={(e) => updateForm('family_name', e.target.value)} /></div>
            <div className="space-y-2"><Label>{t('profile.givenNameLabel')}</Label><Input value={form.given_name || ''} onChange={(e) => updateForm('given_name', e.target.value)} /></div>
          </div>
          <div className="grid gap-4 md:grid-cols-2">
            <div className="space-y-2">
              <Label>{t('profile.genderLabel')}</Label>
              <select className="w-full h-10 px-3 rounded-md border border-input bg-background" value={form.gender || ''} onChange={(e) => updateForm('gender', e.target.value)}>
                <option value="">{t('profile.genderPlaceholder')}</option>
                <option value="male">{t('profile.genderMale')}</option>
                <option value="female">{t('profile.genderFemale')}</option>
                <option value="other">{t('profile.genderOther')}</option>
              </select>
            </div>
            <div className="space-y-2"><Label>{t('profile.birthdateLabel')}</Label><Input type="date" value={form.birthdate || ''} onChange={(e) => updateForm('birthdate', e.target.value)} /></div>
          </div>
          <div className="space-y-2">
            <Label>{t('profile.bioLabel')}</Label>
            <textarea className="w-full min-h-[80px] px-3 py-2 rounded-md border border-input bg-background resize-none" value={form.bio || ''} onChange={(e) => updateForm('bio', e.target.value)} placeholder={t('profile.bioPlaceholder')} />
          </div>
        </CardContent>
      </Card>

      <EmailManagementCard user={user} />

      {/* Contact Info */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2"><Phone className="h-5 w-5" />{t('profile.contactTitle')}</CardTitle>
          <CardDescription>{t('profile.contactDesc')}</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid gap-4 md:grid-cols-2">
            <div className="space-y-2"><Label className="flex items-center gap-2"><Phone className="h-4 w-4" />{t('profile.phoneLabel')}</Label><Input value={form.phone_number || ''} onChange={(e) => updateForm('phone_number', e.target.value)} placeholder="+86 xxx xxxx xxxx" /></div>
            <div className="space-y-2"><Label className="flex items-center gap-2"><Globe className="h-4 w-4" />{t('profile.websiteLabel')}</Label><Input value={form.website || ''} onChange={(e) => updateForm('website', e.target.value)} placeholder="https://example.com" /></div>
            <div className="space-y-2"><Label>{t('profile.localeLabel')}</Label><Input value={form.locale || ''} onChange={(e) => updateForm('locale', e.target.value)} placeholder="zh-CN" /></div>
            <div className="space-y-2"><Label>{t('profile.timezoneLabel')}</Label><Input value={form.zoneinfo || ''} onChange={(e) => updateForm('zoneinfo', e.target.value)} placeholder="Asia/Shanghai" /></div>
          </div>
        </CardContent>
      </Card>

      {/* Work Information */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2"><Briefcase className="h-5 w-5" />{t('profile.workTitle')}</CardTitle>
          <CardDescription>{t('profile.workDesc')}</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid gap-4 md:grid-cols-2">
            <div className="space-y-2"><Label>{t('profile.companyLabel')}</Label><Input value={form.company || ''} onChange={(e) => updateForm('company', e.target.value)} placeholder={t('profile.companyPlaceholder')} /></div>
            <div className="space-y-2"><Label>{t('profile.departmentLabel')}</Label><Input value={form.department || ''} onChange={(e) => updateForm('department', e.target.value)} placeholder={t('profile.departmentPlaceholder')} /></div>
          </div>
          <div className="space-y-2"><Label>{t('profile.jobTitleLabel')}</Label><Input value={form.job_title || ''} onChange={(e) => updateForm('job_title', e.target.value)} placeholder={t('profile.jobTitlePlaceholder')} /></div>
        </CardContent>
      </Card>

      {/* Address */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2"><MapPin className="h-5 w-5" />{t('profile.addressTitle')}</CardTitle>
          <CardDescription>{t('profile.addressDesc')}</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2"><Label>{t('profile.addressStreet')}</Label><Input value={address.street_address || ''} onChange={(e) => updateAddress('street_address', e.target.value)} /></div>
          <div className="grid gap-4 md:grid-cols-2">
            <div className="space-y-2"><Label>{t('profile.addressCity')}</Label><Input value={address.locality || ''} onChange={(e) => updateAddress('locality', e.target.value)} /></div>
            <div className="space-y-2"><Label>{t('profile.addressRegion')}</Label><Input value={address.region || ''} onChange={(e) => updateAddress('region', e.target.value)} /></div>
          </div>
          <div className="grid gap-4 md:grid-cols-2">
            <div className="space-y-2"><Label>{t('profile.addressPostalCode')}</Label><Input value={address.postal_code || ''} onChange={(e) => updateAddress('postal_code', e.target.value)} /></div>
            <div className="space-y-2"><Label>{t('profile.addressCountry')}</Label><Input value={address.country || ''} onChange={(e) => updateAddress('country', e.target.value)} /></div>
          </div>
        </CardContent>
      </Card>

      {/* Social Accounts */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2"><Globe className="h-5 w-5" />{t('profile.socialTitle')}</CardTitle>
          <CardDescription>{t('profile.socialDesc')}</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid gap-4 md:grid-cols-2">
            <div className="space-y-2"><Label className="flex items-center gap-2"><Github className="h-4 w-4" /> GitHub</Label><Input value={form.social_accounts?.github || ''} onChange={(e) => updateSocialAccount('github', e.target.value)} placeholder="GitHub" /></div>
            <div className="space-y-2"><Label className="flex items-center gap-2"><Twitter className="h-4 w-4" /> Twitter</Label><Input value={form.social_accounts?.twitter || ''} onChange={(e) => updateSocialAccount('twitter', e.target.value)} placeholder="Twitter" /></div>
            <div className="space-y-2"><Label>WeChat</Label><Input value={form.social_accounts?.wechat || ''} onChange={(e) => updateSocialAccount('wechat', e.target.value)} /></div>
            <div className="space-y-2"><Label>QQ</Label><Input value={form.social_accounts?.qq || ''} onChange={(e) => updateSocialAccount('qq', e.target.value)} /></div>
          </div>
        </CardContent>
      </Card>

      {/* Save */}
      <div className="flex justify-end gap-4">
        <Button onClick={handleSave} disabled={isSaving} size="lg">
          {isSaving ? (<><Loader2 className="mr-2 h-4 w-4 animate-spin" />{t('profile.saving')}</>) : saved ? (<><Check className="mr-2 h-4 w-4" />{t('profile.saved')}</>) : t('profile.saveChanges')}
        </Button>
      </div>

      <ChangePasswordCard />

      {/* Account Info */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2"><Shield className="h-5 w-5" />{t('profile.accountInfo')}</CardTitle>
          <CardDescription>{t('profile.accountInfoDesc')}</CardDescription>
        </CardHeader>
        <CardContent>
          <dl className="grid gap-4">
            <div className="flex items-center justify-between py-2 border-b">
              <dt className="text-muted-foreground flex items-center gap-2"><Calendar className="h-4 w-4" />{t('profile.accountCreated')}</dt>
              <dd className="font-medium">{user.created_at ? new Date(user.created_at).toLocaleDateString(dateLocale) : '-'}</dd>
            </div>
            <div className="flex items-center justify-between py-2 border-b">
              <dt className="text-muted-foreground">{t('profile.userId')}</dt>
              <dd className="font-mono text-sm">{user.id}</dd>
            </div>
          </dl>
        </CardContent>
      </Card>

      {/* Danger Zone - 删除账号 */}
      <DeleteAccountCard />
    </div>
  );
}
