import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Loyal Passkey Demo",
  description: "Passkey and wallet account integration demo.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
