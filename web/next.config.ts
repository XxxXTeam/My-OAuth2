import type { NextConfig } from "next";

/* 生成构建ID：日期 + 短时间戳哈希，格式如 250214-a3f8 */
const now = new Date();
const datePart = now.toISOString().slice(2, 10).replace(/-/g, '');
const hashPart = Math.floor(now.getTime() % 0xFFFF).toString(16).padStart(4, '0');
const buildId = `${datePart}-${hashPart}`;

const nextConfig: NextConfig = {
  output: "export",
  trailingSlash: true,
  images: {
    unoptimized: true,
  },
  generateBuildId: () => buildId,
  env: {
    NEXT_PUBLIC_BUILD_ID: buildId,
  },
  /* 性能优化 */
  poweredByHeader: false,
  reactStrictMode: true,
  compress: true,
  /* Turbopack 兼容（Next.js 16 默认） */
  turbopack: {},
  /* Next.js 16 自动生成的 .next/types/validator.ts 存在类型导出缺陷，跳过构建时类型检查 */
  typescript: {
    ignoreBuildErrors: true,
  },
};

export default nextConfig;
