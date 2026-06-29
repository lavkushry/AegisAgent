import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  output: "export",
  distDir: "dist",
  // The gateway mounts the exported console at /dashboard and serves static
  // files through /dashboard/*path. Without this prefix Next emits /_next/*
  // URLs, leaving the SSR shell visible but never hydrated.
  assetPrefix: "/dashboard",
  images: {
    unoptimized: true,
  },
};

export default nextConfig;
