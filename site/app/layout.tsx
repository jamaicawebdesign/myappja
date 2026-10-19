import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Perimeter | Website Security Scanner",
  description: "Run safe, read-only security checks on public websites and their assets.",
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
