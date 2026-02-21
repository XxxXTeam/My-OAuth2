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
};

export default nextConfig;
