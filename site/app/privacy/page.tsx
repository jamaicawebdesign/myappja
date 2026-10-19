import type { Metadata } from "next";
import Link from "next/link";

export const metadata: Metadata = {
  title: "Privacy Notice | Perimeter",
  description: "What Perimeter collects, how scan reports are stored, and how to delete them.",
};

export default function PrivacyPage() {
  return <main className="legal-page">
    <Link className="legal-back" href="/">← Back to scanner</Link>
    <header className="legal-heading"><span>PERIMETER · LEGAL</span><h1>Privacy notice</h1><p>Effective October 19, 2026</p></header>
    <article className="legal-copy">
      <p>This notice explains what Perimeter processes when you use its read-only website security scanner.</p>
      <h2>Information in a scan report</h2>
      <p>A report may contain the submitted website URL, scan time, response status and security-header evidence, same-origin page paths, discovered asset URLs and response codes, findings, recommendations, and a heuristic score. The scanner reads target pages to perform checks but does not save their full HTML or asset response bodies in the report.</p>
      <h2>Where reports are stored</h2>
      <p>When you are signed out, reports are stored in local browser storage on that device. The browser keeps up to 50 reports; you can export or clear them in Settings. When you are signed in, reports are also stored in the service’s Supabase database and associated with your user account. Cloud reports remain until you delete them in Settings or your account is removed. Supabase may retain database backups according to its own backup and deletion schedules.</p>
      <h2>Website requests</h2>
      <p>When a scan runs, the service makes bounded GET requests to the submitted public website, its same-origin pages and assets, and its robots.txt file. The target website receives those requests from the service’s hosting infrastructure and may process request metadata under its own privacy practices.</p>
      <h2>Rate-limit metadata</h2>
      <p>The scanner uses a client address supplied by the hosting proxy to enforce per-client limits. Request timestamps are kept in a 10-minute in-memory window; active-scan counters are released when a scan finishes. The address is not added to scan reports or intentionally written to application logs. Limits are process-local and may reset when an instance restarts. Hosting providers and trusted proxies may independently process or retain network metadata under their own policies.</p>
      <h2>Service providers</h2>
      <p>Supabase provides authentication and cloud report storage for signed-in users. The application sends report data to Supabase only when a valid signed-in session is present and the database is configured. Hosting providers may process standard operational data needed to deliver the service.</p>
      <h2>Deletion and control</h2>
      <p>Use Settings to export or clear browser reports and, while signed in, delete cloud reports from your account. Clearing browser storage does not delete cloud reports, and deleting cloud reports does not clear copies stored in other browsers. You can also remove local storage through your browser’s site-data controls.</p>
      <h2>Security and limitations</h2>
      <p>Perimeter is a beta, heuristic baseline tool. Do not submit secrets in URLs. Reports may contain sensitive target paths or header values, so protect your account and exported files accordingly.</p>
      <h2>Contact and operator details</h2>
      <p>Before offering this service commercially, the operator should publish its legal name, business address, and a monitored privacy contact email here. This draft should be reviewed for applicable privacy-law requirements.</p>
    </article>
    <footer className="legal-footer"><Link href="/terms">Terms of use</Link><span>Perimeter · Website security baseline</span></footer>
  </main>;
}