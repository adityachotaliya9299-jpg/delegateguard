import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Allow delegateguard CLI to be called from API routes in future
  serverExternalPackages: [],
  // Output standalone for Docker/self-host option
  output: process.env.NEXT_OUTPUT === "standalone" ? "standalone" : undefined,
};

export default nextConfig;