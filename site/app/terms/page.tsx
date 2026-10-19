import type { Metadata } from "next";
import Link from "next/link";

export const metadata: Metadata = {
  title: "Terms of Use | Perimeter",
  description: "Terms for using the Perimeter website security baseline scanner.",
};

export default function TermsPage() {
  return <main className="legal-page">
    <Link className="legal-back" href="/">← Back to scanner</Link>
    <header className="legal-heading"><span>PERIMETER · LEGAL</span><h1>Terms of use</h1><p>Effective October 19, 2026</p></header>
    <article className="legal-copy">
      <p>These terms cover your use of Perimeter, a read-only website security baseline scanner. By using the service, you agree to these terms.</p>
      <h2>Authorization required</h2>
      <p>Only submit websites that you own or are explicitly authorized to assess. You are responsible for obtaining permission from the site owner and for complying with applicable laws, contracts, and acceptable-use rules. Do not use the service to scan systems without authorization.</p>
      <h2>What the scanner does</h2>
      <p>Perimeter makes bounded HTTP GET requests to the submitted page, follows same-origin links subject to robots.txt, and checks selected response headers, HTML resource references, same-origin scripts and stylesheets, and referenced public source maps. A crawl is limited to 20 pages, 30 seconds, and 40 asset requests. The service does not submit forms, authenticate to target sites, run exploit payloads, probe ports, or attempt to bypass access controls.</p>
      <h2>Not a security guarantee</h2>
      <p>Reports and scores are heuristic signals based on the pages and responses observed during a scan. They may be incomplete or inaccurate and are not a penetration test, compliance assessment, certification, or guarantee that a site is secure. Do not rely on Perimeter as your sole security control or for emergency decisions. Arrange a qualified assessment when you need assurance.</p>
      <h2>Rate limits and service protection</h2>
      <p>Scan requests are limited to 5 per client per 10-minute window and 60 per running instance per 10 minutes. Each instance allows at most 2 concurrent scans per client and 20 concurrent scans overall. Request bodies are limited to 8 KB. Limits are held in instance memory, may reset on restart, and are not shared across multiple instances; the service may reject requests to protect availability, follow robots.txt, or prevent misuse. Limits may change.</p>
      <h2>Acceptable use</h2>
      <p>You may not use the service to disrupt websites, access private networks, evade access controls, or infringe another party’s rights. We may suspend access when use creates security, legal, or operational risk.</p>
      <h2>Reports and data</h2>
      <p>Scan reports can contain submitted URLs, response-header evidence, discovered asset URLs, status codes, and scan timestamps. Browser-only reports remain in your browser until cleared. Signed-in reports are stored in your Supabase account until deleted by you or your account is removed. See the <Link href="/privacy">Privacy notice</Link> for details.</p>
      <h2>Availability and liability</h2>
      <p>The service is provided on an as-available basis. To the extent permitted by law, Perimeter is provided without warranties, and the operator is not liable for losses arising from incomplete scan results, service interruptions, or decisions made based on a report.</p>
      <h2>Contact and operator details</h2>
      <p>Before offering this service commercially, the operator should publish its legal name, business address, and a monitored contact email here. These draft terms should be reviewed for the jurisdictions where the service and its customers operate.</p>
    </article>
    <footer className="legal-footer"><Link href="/privacy">Privacy notice</Link><span>Perimeter · Website security baseline</span></footer>
  </main>;
}