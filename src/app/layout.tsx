import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Loyal Passkey PRF Tester",
  description: "Create and inspect passkeys with the WebAuthn PRF extension.",
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
