import type { Metadata } from "next";
import { Cinzel, Plus_Jakarta_Sans, JetBrains_Mono } from "next/font/google";
import "./globals.css";

const fontDisplay = Cinzel({
  subsets: ["latin"],
  weight: ["600", "700"],
  variable: "--font-display",
  display: "swap",
});

const fontSans = Plus_Jakarta_Sans({
  subsets: ["latin"],
  weight: ["400", "500", "600", "700"],
  variable: "--font-sans",
  display: "swap",
});

const fontMono = JetBrains_Mono({
  subsets: ["latin"],
  weight: ["400", "500", "600"],
  variable: "--font-mono",
  display: "swap",
});

export const metadata: Metadata = {
  title: "ALASTOR | Forensic Code Property Graph, SAST, SCA & ASPM Studio",
  description:
    "ALASTOR — Deterministic Code Property Graph (AST, CFG, DFG, Call Graph), Zero-FP SAST, Reachable OSV SCA, STRIDE & Executive ASPM Studio.",
  icons: {
    icon: "/alastor-demon-logo.png",
  },
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html
      lang="en"
      className={`dark ${fontDisplay.variable} ${fontSans.variable} ${fontMono.variable}`}
      data-theme="alastor-infernal"
      data-theme-mode="dark"
      suppressHydrationWarning
    >
      <body className="bg-[var(--surface-void)] text-[var(--ink-primary)] font-sans min-h-screen overflow-hidden antialiased">
        {children}
      </body>
    </html>
  );
}
