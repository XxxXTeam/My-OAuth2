import AppDetailClient from './client';

// Required for static export with dynamic routes
export const dynamicParams = false;

export async function generateStaticParams(): Promise<{ id: string }[]> {
  // Return a placeholder - actual IDs are resolved client-side
  return [{ id: '_placeholder_' }];
}

export default function AppDetailPage() {
  return <AppDetailClient />;
}
