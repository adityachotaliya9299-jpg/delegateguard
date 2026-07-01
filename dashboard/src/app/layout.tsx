import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "DelegateGuard — EIP-7702 Security Toolkit",
  description: "Security analysis toolkit for EIP-7702 delegate contracts and post-Pectra protocol assumptions.",
  keywords: ["EIP-7702", "smart contract security", "Ethereum", "delegate contracts", "Pectra", "audit"],
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
        <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&family=Inter:wght@400;500;600&display=swap" rel="stylesheet" />
      </head>
      <body>{children}</body>
    </html>
  );
}