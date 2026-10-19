import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "ALASTOR | Mythological Daimon CPG, SAST, SCA & IaC Security Platform",
  description:
    "ALASTOR — The Relentless Hunter of Hidden Code Flaws. Deterministic Code Property Graph (AST, CFG, DFG) & Unified Security Platform.",
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
    <html lang="en" className="dark" data-theme="alastor-infernal" data-theme-mode="dark">
      <body className="bg-zinc-950 text-zinc-100 min-h-screen overflow-hidden antialiased">
        {children}
      </body>
    </html>
  );
}
