import type { Metadata } from "next";
import SiteHeader from "@/components/SiteHeader";
import SiteFooter from "@/components/SiteFooter";
import "./globals.css";

export const metadata: Metadata = {
  title: {
    default: "DelegateGuard — EIP-7702 Security, Investigated",
    template: "%s · DelegateGuard",
  },
  description:
    "Code-level security analysis for the EIP-7702 attack surface: delegate contract analyzer, protocol assumption scanner, Foundry harness generator, and a live on-chain delegation monitor.",
  keywords: [
    "EIP-7702",
    "Pectra",
    "smart contract security",
    "delegate contracts",
    "Ethereum audit",
    "static analysis",
  ],
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
        <link
          href="https://fonts.googleapis.com/css2?family=Fraunces:opsz,wght@9..144,400..700&family=IBM+Plex+Mono:wght@400;500;600;700&family=IBM+Plex+Sans:wght@400;500;600&display=swap"
          rel="stylesheet"
        />
        {/* If JS never runs, scroll-reveal content must still be visible. */}
        <noscript>
          <style>{`.reveal-init{opacity:1 !important;transform:none !important;filter:none !important;clip-path:none !important}`}</style>
        </noscript>
      </head>
      <body>
        <SiteHeader />
        <main>{children}</main>
        <SiteFooter />
      </body>
    </html>
  );
}
