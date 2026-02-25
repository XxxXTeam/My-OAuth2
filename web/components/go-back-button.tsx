'use client';

import { useRouter } from 'next/navigation';
import { Button } from '@/components/ui/button';
import { ArrowLeft } from 'lucide-react';

/*
 * GoBackButton 返回上一页按钮（客户端组件）
 * 功能：封装 router.back() 调用，供服务端组件使用
 */
export function GoBackButton({ label }: { label: string }) {
  const router = useRouter();
  return (
    <Button variant="outline" onClick={() => router.back()}>
      <ArrowLeft className="mr-2 h-4 w-4" />
      {label}
    </Button>
  );
}
