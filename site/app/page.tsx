"use client";

import {
  Activity, ArrowUpRight, Bell, Check, ChevronDown, ChevronRight, CircleAlert, CircleHelp,
  Clock3, Cloud, Code2, Copy, CreditCard, Download, ExternalLink, FileCode2, Globe2,
  LayoutDashboard, LoaderCircle, LockKeyhole, LogOut, Menu, Plus, Search,
  Save, Settings2, Shield, ShieldAlert, ShieldCheck, Sparkles, Trash2, UserRound, X,
} from "lucide-react";
import { FormEvent, ReactNode, useEffect, useRef, useState } from "react";
import { createBrowserSupabaseClient, isSupabaseConfigured } from "@/lib/supabase";

type CheckResult = {
  id: string;
  title: string;
  detail: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  status: "pass" | "issue" | "info";
  resource?: string;
  evidence?: string;
  recommendation?: string;
};
type AssetResult = { url: string; kind: "script" | "stylesheet" | "source map"; status: number | null };
type ScanResult = { id: string; targetUrl: string; scannedAt: string; score: number; checks: CheckResult[]; assets: AssetResult[] };
type Section = "Overview" | "Scans" | "Files" | "Reports" | "Plans" | "Settings";

const navigation: { label: Section; icon: typeof LayoutDashboard }[] = [
  { label: "Overview", icon: LayoutDashboard }, { label: "Scans", icon: Activity },
  { label: "Files", icon: FileCode2 }, { label: "Reports", icon: ShieldCheck },
  { label: "Plans", icon: CreditCard }, { label: "Settings", icon: Settings2 },
];
const severityLabel: Record<CheckResult["severity"], string> = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info" };

function hostOf(value: string) {
  try { return new URL(value).hostname.replace(/^www\./, ""); } catch { return value; }
}
function dateOf(value: string) {
  return new Intl.DateTimeFormat("en", { dateStyle: "medium", timeStyle: "short" }).format(new Date(value));
}
function scoreTone(score: number) { return score >= 85 ? "good" : score >= 65 ? "watch" : "bad"; }
function scanPageCount(scan: ScanResult) {
  const detail = scan.checks.find((check) => check.id === "crawl-coverage")?.detail ?? "";
  const match = /Inspected (\d+) of (\d+) discovered/i.exec(detail);
  return match ? { inspected: Number(match[1]), discovered: Number(match[2]) } : { inspected: 1, discovered: 1 };
}

export default function Home() {
  const [section, setSection] = useState<Section>("Overview");
  const [url, setUrl] = useState("https://example.com");
  const [scans, setScans] = useState<ScanResult[]>([]);
  const [selected, setSelected] = useState<ScanResult | null>(null);
  const [search, setSearch] = useState("");
  const [fileScanId, setFileScanId] = useState("");
  const [fileSearch, setFileSearch] = useState("");
  const [fileKindFilter, setFileKindFilter] = useState("all");
  const [fileStatusFilter, setFileStatusFilter] = useState("all");
  const [copiedAsset, setCopiedAsset] = useState("");
  const [fileNotice, setFileNotice] = useState("");
  const [workspaceName, setWorkspaceName] = useState("Northstar Studio");
  const [workspaceNameDraft, setWorkspaceNameDraft] = useState("Northstar Studio");
  const [defaultTargetDraft, setDefaultTargetDraft] = useState("https://example.com");
  const [rememberLastTarget, setRememberLastTarget] = useState(true);
  const [settingsNotice, setSettingsNotice] = useState("");
  const [settingsBusy, setSettingsBusy] = useState(false);
  const [isScanning, setIsScanning] = useState(false);
  const [notice, setNotice] = useState("");
  const [syncOpen, setSyncOpen] = useState(false);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [authMode, setAuthMode] = useState<"login" | "signup">("login");
  const [signedIn, setSignedIn] = useState(false);
  const [accountEmail, setAccountEmail] = useState("");
  const [authBusy, setAuthBusy] = useState(false);
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const [accountMenuOpen, setAccountMenuOpen] = useState(false);
  const accountMenuRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const savedWorkspace = window.localStorage.getItem("perimeter-workspace-name-v1");
    const savedTarget = window.localStorage.getItem("perimeter-default-target-v1");
    const savedRemember = window.localStorage.getItem("perimeter-remember-target-v1");
    queueMicrotask(() => {
      if (savedWorkspace) {
        setWorkspaceName(savedWorkspace);
        setWorkspaceNameDraft(savedWorkspace);
      }
      if (savedTarget) {
        setDefaultTargetDraft(savedTarget);
        setUrl(savedTarget);
      }
      if (savedRemember !== null) setRememberLastTarget(savedRemember === "true");
    });
    const stored = window.localStorage.getItem("perimeter-scans-v1");
    if (stored) {
      try {
        const savedScans = JSON.parse(stored) as ScanResult[];
        queueMicrotask(() => setScans(savedScans));
      }
      catch { window.localStorage.removeItem("perimeter-scans-v1"); }
    }
    if (!isSupabaseConfigured()) return;
    const supabase = createBrowserSupabaseClient();
    if (!supabase) return;
    void supabase.auth.getSession().then(async ({ data }) => {
      if (!data.session) return;
      setSignedIn(true);
      setAccountEmail(data.session.user.email ?? "");
      try {
        const response = await fetch("/api/scans", { headers: { Authorization: `Bearer ${data.session.access_token}` } });
        if (!response.ok) return;
        const cloudScans = await response.json() as ScanResult[];
        setScans((current) => {
          const combined = [...cloudScans, ...current.filter((scan) => !cloudScans.some((saved) => saved.id === scan.id))].slice(0, 50);
          window.localStorage.setItem("perimeter-scans-v1", JSON.stringify(combined));
          return combined;
        });
      } catch { setNotice("Cloud history is unavailable. Local reports are still here."); }
    });
    const { data: listener } = supabase.auth.onAuthStateChange((_event, session) => {
      setSignedIn(Boolean(session));
      setAccountEmail(session?.user.email ?? "");
    });
    return () => listener.subscription.unsubscribe();
  }, []);

  useEffect(() => {
    if (!accountMenuOpen) return;
    const closeOnOutsideClick = (event: PointerEvent) => {
      if (!accountMenuRef.current?.contains(event.target as Node)) setAccountMenuOpen(false);
    };
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key === "Escape") setAccountMenuOpen(false);
    };
    document.addEventListener("pointerdown", closeOnOutsideClick);
    document.addEventListener("keydown", closeOnEscape);
    return () => {
      document.removeEventListener("pointerdown", closeOnOutsideClick);
      document.removeEventListener("keydown", closeOnEscape);
    };
  }, [accountMenuOpen]);

  async function handleScan(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (isScanning) return;
    setIsScanning(true); setNotice(""); setSelected(null);
    try {
      const supabase = createBrowserSupabaseClient();
      const { data } = supabase ? await supabase.auth.getSession() : { data: { session: null } };
      const response = await fetch("/api/scans", {
        method: "POST",
        headers: { "Content-Type": "application/json", ...(data.session ? { Authorization: `Bearer ${data.session.access_token}` } : {}) },
        body: JSON.stringify({ url }),
      });
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.error ?? "The scan could not be completed.");
      const scan = payload.scan as ScanResult;
      setScans((current) => {
        const next = [scan, ...current.filter((item) => item.id !== scan.id)].slice(0, 50);
        window.localStorage.setItem("perimeter-scans-v1", JSON.stringify(next));
        return next;
      });
      if (rememberLastTarget) {
        window.localStorage.setItem("perimeter-default-target-v1", url);
        setDefaultTargetDraft(url);
      }
      setSelected(scan); setSection("Overview");
      const pageCount = scanPageCount(scan);
      const crawlSummary = `Inspected ${pageCount.inspected} of ${pageCount.discovered} discovered pages.`;
      setNotice(payload.saved ? `Scan complete. ${crawlSummary} Report synced to your Supabase account.` : `${crawlSummary} ${payload.saveError ?? "Report saved in this browser only."}`);
    } catch (error) { setNotice(error instanceof Error ? error.message : "The scan could not be completed."); }
    finally { setIsScanning(false); }
  }

  async function handleAuthSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const supabase = createBrowserSupabaseClient();
    if (!supabase) return;
    setAuthBusy(true); setNotice("");
    const result = authMode === "login"
      ? await supabase.auth.signInWithPassword({ email, password })
      : await supabase.auth.signUp({ email, password, options: { emailRedirectTo: window.location.origin } });
    setAuthBusy(false);
    if (result.error) {
      setNotice(result.error.message);
      return;
    }
    if (authMode === "signup" && !result.data.session) {
      setNotice("Account created. Check your email to confirm your address, then log in.");
      return;
    }
    if (result.data.session) {
      try {
        const response = await fetch("/api/scans", { headers: { Authorization: `Bearer ${result.data.session.access_token}` } });
        if (response.ok) {
          const cloudScans = await response.json() as ScanResult[];
          setScans((current) => {
            const combined = [...cloudScans, ...current.filter((scan) => !cloudScans.some((saved) => saved.id === scan.id))].slice(0, 50);
            window.localStorage.setItem("perimeter-scans-v1", JSON.stringify(combined));
            return combined;
          });
        }
      } catch {
        setNotice("You’re signed in, but cloud history could not be loaded.");
        return;
      }
    }
    setNotice(authMode === "login" ? "You’re logged in. Your cloud history is ready." : "Your account is ready.");
    setPassword("");
    setSyncOpen(false);
  }

  async function handleSignOut() {
    const supabase = createBrowserSupabaseClient();
    if (!supabase) return;
    await supabase.auth.signOut(); setSignedIn(false); setAccountEmail("");
    setAccountMenuOpen(false);
    setNotice("Signed out. Browser-local scan history remains on this device.");
  }

  function handleSaveSettings(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const cleanName = workspaceNameDraft.trim();
    if (!cleanName) {
      setSettingsNotice("Enter a workspace name before saving.");
      return;
    }
    let target: URL;
    try { target = new URL(defaultTargetDraft.trim()); }
    catch {
      setSettingsNotice("Enter a complete default URL, including https://.");
      return;
    }
    if (target.protocol !== "http:" && target.protocol !== "https:") {
      setSettingsNotice("The default target must use HTTP or HTTPS.");
      return;
    }
    const normalizedTarget = target.href;
    window.localStorage.setItem("perimeter-workspace-name-v1", cleanName);
    window.localStorage.setItem("perimeter-default-target-v1", normalizedTarget);
    window.localStorage.setItem("perimeter-remember-target-v1", String(rememberLastTarget));
    setWorkspaceName(cleanName);
    setWorkspaceNameDraft(cleanName);
    setDefaultTargetDraft(normalizedTarget);
    setUrl(normalizedTarget);
    setSettingsNotice("Workspace settings saved on this device.");
  }

  function exportScanArchive() {
    const objectUrl = URL.createObjectURL(new Blob([JSON.stringify(scans, null, 2)], { type: "application/json" }));
    const link = document.createElement("a");
    link.href = objectUrl;
    link.download = "perimeter-scan-history.json";
    link.click();
    URL.revokeObjectURL(objectUrl);
  }

  function clearLocalHistory() {
    if (!window.confirm("Clear scan history saved in this browser? Cloud reports will not be deleted.")) return;
    window.localStorage.removeItem("perimeter-scans-v1");
    setScans([]);
    setSelected(null);
    setFileScanId("");
    setSettingsNotice("Browser history cleared. Supabase reports were not changed.");
  }

  async function deleteCloudHistory() {
    if (!window.confirm("Permanently delete all scan reports in your Supabase account? This cannot be undone.")) return;
    const supabase = createBrowserSupabaseClient();
    if (!supabase) return;
    setSettingsBusy(true);
    setSettingsNotice("");
    try {
      const { data } = await supabase.auth.getSession();
      if (!data.session) throw new Error("Log in again to delete cloud reports.");
      const response = await fetch("/api/scans", { method: "DELETE", headers: { Authorization: `Bearer ${data.session.access_token}` } });
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.error ?? "Cloud reports could not be deleted.");
      const deletedIds = new Set<string>(payload.deletedIds ?? []);
      setScans((current) => {
        const remaining = current.filter((scan) => !deletedIds.has(scan.id));
        window.localStorage.setItem("perimeter-scans-v1", JSON.stringify(remaining));
        return remaining;
      });
      setSelected((current) => current && deletedIds.has(current.id) ? null : current);
      setSettingsNotice(`${payload.deletedCount} cloud ${payload.deletedCount === 1 ? "report was" : "reports were"} deleted.`);
    } catch (error) {
      setSettingsNotice(error instanceof Error ? error.message : "Cloud reports could not be deleted.");
    } finally {
      setSettingsBusy(false);
    }
  }

  async function sendPasswordReset() {
    const supabase = createBrowserSupabaseClient();
    if (!supabase || !accountEmail) return;
    setSettingsBusy(true);
    const { error } = await supabase.auth.resetPasswordForEmail(accountEmail, { redirectTo: window.location.origin });
    setSettingsBusy(false);
    setSettingsNotice(error ? error.message : `Password reset instructions sent to ${accountEmail}.`);
  }

  const latest = selected ?? scans[0] ?? null;
  const issueCount = scans.reduce((sum, scan) => sum + scan.checks.filter((check) => check.status === "issue").length, 0);
  const averageScore = scans.length ? Math.round(scans.reduce((sum, scan) => sum + scan.score, 0) / scans.length) : null;
  const activeFindings = latest?.checks.filter((check) => check.status === "issue") ?? [];
  const filteredScans = scans.filter((scan) => `${scan.targetUrl} ${scan.score}`.toLowerCase().includes(search.toLowerCase()));
  const fileScan = scans.find((scan) => scan.id === fileScanId) ?? latest;
  const fileAssets = fileScan?.assets ?? [];
  const visibleAssets = fileAssets.filter((asset) => {
    const matchesSearch = `${asset.url} ${asset.url.split("/").pop() ?? ""}`.toLowerCase().includes(fileSearch.toLowerCase());
    const matchesKind = fileKindFilter === "all" || asset.kind === fileKindFilter;
    const isAvailable = asset.status !== null && asset.status >= 200 && asset.status < 400;
    const matchesStatus = fileStatusFilter === "all" || (fileStatusFilter === "available" ? isAvailable : !isAvailable);
    return matchesSearch && matchesKind && matchesStatus;
  });
  const unavailableAssetCount = fileAssets.filter((asset) => asset.status === null || asset.status >= 400).length;
  const heading = section === "Overview" ? "Security overview" : section === "Files" ? "Scanned files" : section === "Settings" ? "Workspace settings" : section === "Reports" ? "Scan reports" : section === "Plans" ? "Plans & pricing" : "Scan history";

  function exportAssets() {
    const escapeCell = (value: string) => `"${value.replaceAll('"', '""')}"`;
    const rows = [["URL", "Type", "HTTP status"], ...visibleAssets.map((asset) => [asset.url, asset.kind, asset.status === null ? "Not fetched" : String(asset.status)])];
    const csv = rows.map((row) => row.map(escapeCell).join(",")).join("\n");
    const objectUrl = URL.createObjectURL(new Blob([csv], { type: "text/csv;charset=utf-8" }));
    const link = document.createElement("a");
    link.href = objectUrl;
    link.download = `${hostOf(fileScan?.targetUrl ?? "website")}-assets.csv`;
    link.click();
    URL.revokeObjectURL(objectUrl);
  }

  async function copyAssetUrl(assetUrl: string) {
    try {
      await navigator.clipboard.writeText(assetUrl);
      setCopiedAsset(assetUrl);
      setFileNotice("Asset URL copied to clipboard.");
      window.setTimeout(() => setCopiedAsset((current) => current === assetUrl ? "" : current), 1600);
    } catch {
      setFileNotice("Clipboard access is unavailable in this browser.");
    }
  }

  return <div className="app-shell">
    <aside className={`sidebar ${mobileNavOpen ? "sidebar-open" : ""}`}>
      <a className="brand" href="#overview" onClick={() => setSection("Overview")}><span className="brand-mark"><Shield size={19} /></span><span>perimeter<span className="brand-period">.</span></span></a>
      <button className="workspace-switcher" onClick={() => setSection("Settings")}><span className="workspace-avatar">{workspaceName.slice(0, 1).toUpperCase()}</span><span className="workspace-copy"><strong>{workspaceName}</strong><small>Free workspace</small></span><ChevronDown size={15} /></button>
      <span className="nav-caption">WORKSPACE</span>
      <nav className="main-nav" aria-label="Main navigation">{navigation.map(({ label, icon: Icon }) => <button key={label} className={`nav-link ${section === label ? "nav-link-active" : ""}`} onClick={() => { setSection(label); setMobileNavOpen(false); }}><Icon size={17} /><span>{label}</span>{label === "Scans" && scans.length > 0 && <span className="nav-count">{scans.length}</span>}{label === "Reports" && latest && <span className="nav-dot" />}</button>)}</nav>
      <div className="sidebar-bottom"><button className="sidebar-plan" onClick={() => setSection("Plans")}><span className="plan-icon"><Sparkles size={15} /></span><span><strong>Free plan</strong><small>View plans</small></span><ChevronRight size={15} /></button><button className="account-button" aria-label={signedIn ? `Account menu for ${accountEmail}` : "Log in or sign up"} onClick={() => signedIn ? (setAccountMenuOpen(false), setSection("Settings")) : (setAuthMode("login"), setSyncOpen(true))}><span className="account-avatar">{signedIn ? accountEmail.slice(0, 1).toUpperCase() : "G"}</span><span className="account-copy"><strong>{signedIn ? accountEmail : "Guest workspace"}</strong><small>{signedIn ? "Account settings" : "Log in or sign up"}</small></span>{signedIn ? <UserRound size={15} /> : <Cloud size={15} />}</button></div>
    </aside>
    {mobileNavOpen && <button className="mobile-scrim" aria-label="Close navigation" onClick={() => setMobileNavOpen(false)} />}

    <main className="main-area" id="overview">
      <header className="topbar"><button className="mobile-menu icon-button" aria-label="Open navigation" onClick={() => setMobileNavOpen(true)}><Menu size={19} /></button><div className="breadcrumbs"><span>Workspace</span><ChevronRight size={14} /><strong>{section}</strong></div><div className="top-actions"><span className="environment-pill"><span /> MONITORING ACTIVE</span><button className="icon-button" aria-label="Help center" title="Help center"><CircleHelp size={18} /></button><button className="icon-button" aria-label="Notifications" title="Notifications"><Bell size={18} /></button><div className="account-menu-wrap" ref={accountMenuRef}><button className="top-avatar" aria-label="Open account menu" aria-haspopup="menu" aria-expanded={accountMenuOpen} onClick={() => setAccountMenuOpen((open) => !open)}>{signedIn ? accountEmail.slice(0, 1).toUpperCase() : workspaceName.slice(0, 1).toUpperCase()}</button>{accountMenuOpen && <div className="account-dropdown" role="menu"><div className="account-dropdown-head"><span className="account-avatar">{signedIn ? accountEmail.slice(0, 1).toUpperCase() : workspaceName.slice(0, 1).toUpperCase()}</span><span><strong>{signedIn ? accountEmail : workspaceName}</strong><small>{signedIn ? "Signed in" : "Guest workspace"}</small></span></div><div className="account-dropdown-divider" />{signedIn && <button role="menuitem" onClick={() => { setSection("Settings"); setAccountMenuOpen(false); }}><UserRound size={16} /> Account settings</button>}<button role="menuitem" onClick={() => { setSection("Plans"); setAccountMenuOpen(false); }}><CreditCard size={16} /> Plans & pricing</button><button role="menuitem" onClick={() => { setSection("Settings"); setAccountMenuOpen(false); }}><Settings2 size={16} /> Workspace settings</button><div className="account-dropdown-divider" />{signedIn ? <button role="menuitem" className="account-logout" onClick={() => void handleSignOut()}><LogOut size={16} /> Log out</button> : <button role="menuitem" onClick={() => { setAuthMode("login"); setSyncOpen(true); setAccountMenuOpen(false); }}><Cloud size={16} /> Log in or sign up</button>}</div>}</div></div></header>
      <div className="content-wrap">
        <div className="page-heading"><div><div className="eyebrow"><span className="eyebrow-line" /> WEBSITE SECURITY</div><h1>{heading}<span className="heading-period">.</span></h1><p>{section === "Overview" ? "A clear view of what’s exposed, what’s protected, and what needs attention." : section === "Files" ? "Public scripts and stylesheets discovered during your latest scan." : section === "Settings" ? "Manage scan defaults and report storage." : section === "Reports" ? "Review security findings and score trends across your sites." : section === "Plans" ? "Current access and proposed upgrades. Checkout is not connected yet." : "Every manual check, collected in one place."}</p></div><button className="quiet-button" onClick={() => setSyncOpen(true)}><Cloud size={16} />{signedIn ? "Cloud synced" : "Connect cloud"}</button></div>

        {section === "Overview" && <>
          <section className="metrics-row" aria-label="Security metrics">
            <article className="metric-card score-metric"><div className="metric-top"><span>BASELINE SCORE</span><span className="metric-icon mint"><ShieldCheck size={17} /></span></div><div className="score-line"><strong>{averageScore ?? "--"}</strong><span>/100</span>{averageScore !== null && <span className="score-change"><ArrowUpRight size={14} />{averageScore >= 85 ? "Strong" : "Review"}</span>}</div><div className="metric-foot">{scans.length ? `Heuristic average across ${scans.length} ${scans.length === 1 ? "scan" : "scans"}` : "Run a scan to establish your baseline"}</div><div className="metric-accent score-accent" /></article>
            <article className="metric-card"><div className="metric-top"><span>WEBSITES SCANNED</span><span className="metric-icon blue"><Globe2 size={17} /></span></div><div className="metric-value">{new Set(scans.map((scan) => hostOf(scan.targetUrl))).size}<span className="metric-suffix">sites</span></div><div className="metric-foot">{scans.length ? `${scans.length} total scan${scans.length === 1 ? "" : "s"} completed` : "No websites scanned yet"}</div></article>
            <article className="metric-card"><div className="metric-top"><span>OPEN FINDINGS</span><span className="metric-icon coral"><ShieldAlert size={17} /></span></div><div className="metric-value">{issueCount}<span className="metric-suffix">{issueCount === 1 ? "issue" : "issues"}</span></div><div className="metric-foot">{latest ? "Across your saved scan reports" : "Findings appear here after a scan"}</div></article>
            <article className="metric-card"><div className="metric-top"><span>FILES INSPECTED</span><span className="metric-icon lilac"><Code2 size={17} /></span></div><div className="metric-value">{scans.reduce((sum, scan) => sum + scan.assets.length, 0)}<span className="metric-suffix">assets</span></div><div className="metric-foot">Scripts, stylesheets & source maps</div></article>
          </section>

          <section className="scan-panel"><div className="scan-panel-copy"><div className="panel-label"><span className="pulse-dot" /> ON-DEMAND SITE CRAWL</div><h2>Check your perimeter.</h2><p>Crawl up to 20 linked pages, then inspect headers, resources, and public source maps.</p></div><form className="scan-form" onSubmit={handleScan}><label className="scan-input-wrap"><Globe2 size={17} /><input aria-label="Website URL to scan" type="url" value={url} onChange={(event) => setUrl(event.target.value)} placeholder="https://yourwebsite.com" required /><span className="input-lock"><LockKeyhole size={14} /> PUBLIC URL</span></label><button className="scan-button" type="submit" disabled={isScanning}>{isScanning ? <><LoaderCircle size={16} className="spin" /> Scanning</> : <><Plus size={17} /> Run scan</>}</button></form><div className="scan-note"><LockKeyhole size={13} /> Same-origin GET requests only. Respects robots.txt; capped at 20 pages and 30 seconds.</div></section>

          {notice && <div className="notice" role="status"><span>{notice}</span><button aria-label="Dismiss notice" onClick={() => setNotice("")}><X size={15} /></button></div>}
          <div className="section-grid"><section className="surface latest-surface"><div className="surface-heading"><div><span className="surface-kicker">LATEST ACTIVITY</span><h2>Recent scans</h2></div><button className="text-button" onClick={() => setSection("Scans")}>All scans <ChevronRight size={15} /></button></div>{scans.length ? <div className="scan-table-wrap"><table className="scan-table"><thead><tr><th>WEBSITE</th><th>LAST SCAN</th><th>RESULT</th><th /></tr></thead><tbody>{scans.slice(0, 5).map((scan) => <tr key={scan.id} onClick={() => setSelected(scan)}><td><span className="site-favicon"><Globe2 size={15} /></span><span className="site-name"><strong>{hostOf(scan.targetUrl)}</strong><small>{new URL(scan.targetUrl).protocol.replace(":", "")}</small></span></td><td className="date-cell">{dateOf(scan.scannedAt)}</td><td><span className={`score-badge ${scoreTone(scan.score)}`}>{scan.score}<small>/100</small></span></td><td><ChevronRight size={16} className="row-arrow" /></td></tr>)}</tbody></table></div> : <div className="empty-activity"><div className="empty-icon"><Globe2 size={19} /></div><div><strong>Your scan history starts here</strong><span>Enter a public website above to create your first report.</span></div><button className="text-button" onClick={() => document.querySelector<HTMLInputElement>(".scan-input-wrap input")?.focus()}>Start a scan <ChevronRight size={15} /></button></div>}</section>
            <section className="surface coverage-surface"><div className="surface-heading"><div><span className="surface-kicker">CHECK COVERAGE</span><h2>What we inspect</h2></div><span className="coverage-icon"><Shield size={18} /></span></div><div className="coverage-list"><div><span className="coverage-symbol green"><LockKeyhole size={15} /></span><span><strong>Transport & headers</strong><small>HTTPS, CSP, HSTS, clickjacking</small></span><span className="coverage-state">8 checks</span></div><div><span className="coverage-symbol blue"><Code2 size={15} /></span><span><strong>Page resources</strong><small>Mixed content, third-party scripts</small></span><span className="coverage-state">3 checks</span></div><div><span className="coverage-symbol orange"><FileCode2 size={15} /></span><span><strong>Public source files</strong><small>Source maps and asset exposure</small></span><span className="coverage-state">2 checks</span></div></div><div className="coverage-footer"><ShieldCheck size={15} /> Safe, read-only checks. No exploitation.</div></section></div>
          {latest && <section className="surface findings-surface"><div className="surface-heading"><div><span className="surface-kicker">REPORT SNAPSHOT</span><h2>Findings from {hostOf(latest.targetUrl)}</h2></div><button className="text-button" onClick={() => setSection("Reports")}>View report <ChevronRight size={15} /></button></div>{activeFindings.length ? <div className="findings-list">{activeFindings.slice(0, 4).map((item) => <FindingRow key={item.id} item={item} />)}</div> : <div className="all-clear"><span><Check size={17} /></span><strong>No issues flagged in the latest scan</strong><small>Review the full report for informational checks and coverage details.</small></div>}</section>}
        </>}

        {section === "Scans" && <section className="surface page-surface"><div className="surface-heading list-heading"><div><span className="surface-kicker">SCAN HISTORY</span><h2>{scans.length} {scans.length === 1 ? "report" : "reports"}</h2></div><label className="table-search"><Search size={16} /><input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search websites" /></label></div>{filteredScans.length ? <div className="scan-table-wrap"><table className="scan-table"><thead><tr><th>WEBSITE</th><th>SCANNED</th><th>CHECKS</th><th>FINDINGS</th><th>SCORE</th><th /></tr></thead><tbody>{filteredScans.map((scan) => <tr key={scan.id} onClick={() => { setSelected(scan); setSection("Reports"); }}><td><span className="site-favicon"><Globe2 size={15} /></span><span className="site-name"><strong>{hostOf(scan.targetUrl)}</strong><small>{scan.targetUrl}</small></span></td><td className="date-cell">{dateOf(scan.scannedAt)}</td><td>{scan.checks.length}</td><td>{scan.checks.filter((check) => check.status === "issue").length}</td><td><span className={`score-badge ${scoreTone(scan.score)}`}>{scan.score}<small>/100</small></span></td><td><ChevronRight size={16} className="row-arrow" /></td></tr>)}</tbody></table></div> : <EmptyState icon={<Activity size={20} />} title={search ? "No matching scans" : "No scans yet"} detail={search ? "Try another website name." : "Run a scan from the overview to add your first report."} action={() => { setSection("Overview"); setSearch(""); }} />}</section>}

        {section === "Files" && <section className="files-page">
          {fileScan ? <>
            <div className="asset-stats">
              <article><span>ASSETS FOUND</span><strong>{fileAssets.length}</strong></article>
              <article><span>SCRIPTS</span><strong>{fileAssets.filter((asset) => asset.kind === "script").length}</strong></article>
              <article><span>STYLESHEETS</span><strong>{fileAssets.filter((asset) => asset.kind === "stylesheet").length}</strong></article>
              <article className={unavailableAssetCount ? "asset-stat-warning" : "asset-stat-good"}><span>NEEDS ATTENTION</span><strong>{unavailableAssetCount}</strong></article>
            </div>
            <section className="surface files-surface">
              <div className="surface-heading files-heading">
                <div><span className="surface-kicker">PUBLIC ASSET INVENTORY</span><h2>{fileAssets.length} {fileAssets.length === 1 ? "asset" : "assets"}</h2></div>
                <div className="file-scan-select"><label htmlFor="file-scan-select">SCAN</label><select id="file-scan-select" value={fileScan.id} onChange={(event) => setFileScanId(event.target.value)}>{scans.map((scan) => <option key={scan.id} value={scan.id}>{hostOf(scan.targetUrl)} · {dateOf(scan.scannedAt)}</option>)}</select></div>
              </div>
              <div className="files-toolbar">
                <label className="files-search"><Search size={16} /><input aria-label="Search assets" value={fileSearch} onChange={(event) => setFileSearch(event.target.value)} placeholder="Search filenames or URLs" /></label>
                <label className="file-filter"><span>TYPE</span><select value={fileKindFilter} onChange={(event) => setFileKindFilter(event.target.value)}><option value="all">All types</option><option value="script">Scripts</option><option value="stylesheet">Stylesheets</option><option value="source map">Source maps</option></select></label>
                <label className="file-filter"><span>STATUS</span><select value={fileStatusFilter} onChange={(event) => setFileStatusFilter(event.target.value)}><option value="all">Any status</option><option value="available">Available</option><option value="attention">Needs attention</option></select></label>
                <button className="quiet-button files-export" onClick={exportAssets} disabled={!visibleAssets.length}><Download size={15} /> Export CSV</button>
              </div>
              <div className="files-host"><Globe2 size={15} /><strong>{hostOf(fileScan.targetUrl)}</strong><span>Scanned {dateOf(fileScan.scannedAt)}</span><span className="files-result-count">{visibleAssets.length} shown</span></div>
              {fileNotice && <div className="files-notice" role="status">{fileNotice}<button onClick={() => setFileNotice("")} aria-label="Dismiss notice"><X size={14} /></button></div>}
              {visibleAssets.length ? <div className="asset-list">
                <div className="asset-list-header"><span>FILE</span><span>TYPE</span><span>RESPONSE</span><span /></div>
                {visibleAssets.map((asset) => {
                  const fileName = asset.url.split("/").pop()?.split("?")[0] || asset.url;
                  const isAvailable = asset.status !== null && asset.status >= 200 && asset.status < 400;
                  return <div className="asset-row" key={`${asset.kind}:${asset.url}`}>
                    <span className={`asset-type ${asset.kind === "script" ? "asset-js" : asset.kind === "source map" ? "asset-map" : "asset-css"}`}><FileCode2 size={17} /></span>
                    <div className="asset-copy"><strong title={fileName}>{fileName}</strong><span title={asset.url}>{asset.url}</span></div>
                    <span className="asset-kind">{asset.kind}</span>
                    <span className={`asset-status ${isAvailable ? "status-ok" : "status-warn"}`}>{asset.status === null ? "Not fetched" : `HTTP ${asset.status}`}</span>
                    <div className="asset-actions"><button className="asset-action" onClick={() => void copyAssetUrl(asset.url)} aria-label={copiedAsset === asset.url ? "Copied asset URL" : "Copy asset URL"} title={copiedAsset === asset.url ? "Copied" : "Copy URL"}>{copiedAsset === asset.url ? <Check size={15} /> : <Copy size={15} />}</button><a href={asset.url} target="_blank" rel="noreferrer" className="asset-action" aria-label="Open asset in a new tab" title="Open asset"><ExternalLink size={15} /></a></div>
                  </div>;
                })}
              </div> : <div className="files-empty"><FileCode2 size={20} /><strong>{fileAssets.length ? "No assets match these filters" : "No files were discovered in this scan"}</strong><span>{fileAssets.length ? "Try a different search or clear one of the filters." : "Run another scan to inspect public scripts, stylesheets, and source maps."}</span>{fileAssets.length > 0 && <button className="text-button" onClick={() => { setFileSearch(""); setFileKindFilter("all"); setFileStatusFilter("all"); }}>Clear filters <X size={14} /></button>}</div>}
            </section>
          </> : <section className="surface page-surface"><EmptyState icon={<FileCode2 size={20} />} title="No files to show" detail="Run a scan to inspect public scripts, stylesheets, and source maps." action={() => setSection("Overview")} /></section>}
        </section>}

        {section === "Reports" && <section className="report-layout">{latest ? <><div className="report-hero surface"><div className="report-score-wrap"><div className={`report-score ${scoreTone(latest.score)}`}><strong>{latest.score}</strong><small>OUT OF 100</small></div><div><span className="surface-kicker">HEURISTIC BASELINE</span><h2>{hostOf(latest.targetUrl)}</h2><p>Scanned {dateOf(latest.scannedAt)}</p></div></div><button className="quiet-button" onClick={() => { const link = document.createElement("a"); link.href = URL.createObjectURL(new Blob([JSON.stringify(latest, null, 2)], { type: "application/json" })); link.download = `${hostOf(latest.targetUrl)}-security-report.json`; link.click(); URL.revokeObjectURL(link.href); }}><Download size={15} /> Export JSON</button></div><div className="report-summary"><div><span className="summary-mark summary-issue"><ShieldAlert size={17} /></span><strong>{latest.checks.filter((item) => item.status === "issue").length}</strong><small>Findings</small></div><div><span className="summary-mark summary-pass"><ShieldCheck size={17} /></span><strong>{latest.checks.filter((item) => item.status === "pass").length}</strong><small>Passed checks</small></div><div><span className="summary-mark summary-info"><FileCode2 size={17} /></span><strong>{latest.assets.length}</strong><small>Files checked</small></div></div><section className="surface report-checks"><div className="surface-heading"><div><span className="surface-kicker">TECHNICAL RESULTS</span><h2>Security checks</h2></div><span className="report-total">{latest.checks.length} total</span></div><div className="findings-list">{latest.checks.map((item) => <FindingRow key={item.id} item={item} detailed />)}</div></section><div className="report-disclaimer"><CircleHelp size={15} /> Passive baseline checks only. Results are heuristic, not a certification, penetration test, or guarantee of security.</div></> : <section className="surface page-surface"><EmptyState icon={<ShieldCheck size={20} />} title="Your reports will appear here" detail="Run a scan to see its score, checks, and file findings." action={() => setSection("Overview")} /></section>}</section>}

        {section === "Plans" && <section className="plans-page">
          <div className="plans-status"><CreditCard size={18} /><span><strong>Billing isn’t connected yet</strong><small>Free is available now. Paid prices and benefits below are proposed and can’t be purchased yet.</small></span></div>
          <div className="plan-grid">
            <article className="plan-card plan-card-current">
              <div className="plan-card-top"><span className="plan-name">Free</span><span className="plan-badge current-badge">CURRENT</span></div>
              <p className="plan-description">Try the passive baseline scanner.</p>
              <div className="plan-price"><strong>$0</strong><span> / forever</span></div>
              <ul><li><Check size={15} /> Same-origin crawl, up to 20 pages</li><li><Check size={15} /> Header and resource checks</li><li><Check size={15} /> Browser reports and JSON export</li><li><Check size={15} /> Supabase history when signed in</li></ul>
              <button className="plan-button plan-button-current" disabled>Current plan</button>
            </article>
            <article className="plan-card plan-card-proposed">
              <div className="plan-card-top"><span className="plan-name">Pro</span><span className="plan-badge proposed-badge">PROPOSED</span></div>
              <p className="plan-description">For independent site owners.</p>
              <div className="plan-price"><strong>$12</strong><span> / site / month</span></div>
              <ul><li><Check size={15} /> Everything in Free</li><li><Check size={15} /> Higher scan allowance <small>planned</small></li><li><Check size={15} /> Longer report history <small>planned</small></li><li><Check size={15} /> Priority support <small>planned</small></li></ul>
              <button className="plan-button" disabled title="Billing is not configured">Available when billing is connected</button>
            </article>
            <article className="plan-card">
              <div className="plan-card-top"><span className="plan-name">Agency</span><span className="plan-badge proposed-badge">PROPOSED</span></div>
              <p className="plan-description">For teams managing client sites.</p>
              <div className="plan-price"><strong>$39</strong><span> / month</span></div>
              <ul><li><Check size={15} /> Multiple client sites <small>planned</small></li><li><Check size={15} /> Shared team workspaces <small>planned</small></li><li><Check size={15} /> Client-ready exports <small>planned</small></li><li><Check size={15} /> Team access controls <small>planned</small></li></ul>
              <button className="plan-button" disabled title="Billing is not configured">Available when billing is connected</button>
            </article>
          </div>
          <p className="plans-footnote">Proposed pricing is for feedback only. Paid features, plan quotas, payment processing, and subscription management are not implemented.</p>
        </section>}

        {section === "Settings" && <div className="settings-page">
          <form className="surface settings-card" onSubmit={handleSaveSettings}>
            <div className="settings-card-heading"><span className="surface-kicker">WORKSPACE</span><h2>Workspace preferences</h2><p>Keep a familiar name and scan target on this device.</p></div>
            <label className="settings-field"><span>Workspace name</span><input value={workspaceNameDraft} onChange={(event) => setWorkspaceNameDraft(event.target.value)} maxLength={48} required /></label>
            <label className="settings-field"><span>Default website to scan</span><input type="url" value={defaultTargetDraft} onChange={(event) => setDefaultTargetDraft(event.target.value)} placeholder="https://yourwebsite.com" required /></label>
            <label className="settings-toggle"><input type="checkbox" checked={rememberLastTarget} onChange={(event) => setRememberLastTarget(event.target.checked)} /><span><strong>Remember the last scanned website</strong><small>Use it as the default next time you open the scanner.</small></span></label>
            <div className="settings-card-footer"><span>Preferences are saved in this browser.</span><button className="scan-button" type="submit"><Save size={15} /> Save settings</button></div>
          </form>

          <section className="surface settings-card">
            <div className="settings-card-heading"><span className="surface-kicker">ACCOUNT</span><h2>{signedIn ? "Account security" : "Sign in to manage your account"}</h2><p>{signedIn ? `Cloud history is connected for ${accountEmail}.` : "Sign in with your Supabase account to sync reports and manage account security."}</p></div>
            {signedIn ? <div className="settings-action-list"><div><span className="settings-action-copy"><strong>Password</strong><small>Request a secure password reset email.</small></span><button className="quiet-button" onClick={() => void sendPasswordReset()} disabled={settingsBusy}>{settingsBusy ? <LoaderCircle size={15} className="spin" /> : <LockKeyhole size={15} />} Reset password</button></div><div><span className="settings-action-copy"><strong>Session</strong><small>Sign out of this browser account.</small></span><button className="quiet-button" onClick={() => void handleSignOut()}><LogOut size={15} /> Log out</button></div></div> : <button className="scan-button" onClick={() => { setAuthMode("login"); setSyncOpen(true); }}><Cloud size={16} /> Log in or sign up</button>}
          </section>

          <section className="surface settings-card settings-data-card">
            <div className="settings-card-heading"><span className="surface-kicker">DATA & REPORTS</span><h2>Manage scan history</h2><p>{scans.length} report{scans.length === 1 ? "" : "s"} available in this browser. Browser cleanup does not delete cloud copies.</p></div>
            <div className="settings-action-list"><div><span className="settings-action-copy"><strong>Export browser history</strong><small>Download all locally available scan reports as JSON.</small></span><button className="quiet-button" onClick={exportScanArchive} disabled={!scans.length}><Download size={15} /> Export</button></div><div><span className="settings-action-copy"><strong>Clear browser history</strong><small>Remove locally saved reports from this device only.</small></span><button className="quiet-button danger-button" onClick={clearLocalHistory} disabled={!scans.length}><Trash2 size={15} /> Clear</button></div><div><span className="settings-action-copy"><strong>Cloud reports</strong><small>{signedIn ? "Permanently delete all reports in your Supabase account." : "Log in to manage reports saved to Supabase."}</small></span>{signedIn ? <button className="quiet-button danger-button" onClick={() => void deleteCloudHistory()} disabled={settingsBusy}>{settingsBusy ? <LoaderCircle size={15} className="spin" /> : <Trash2 size={15} />} Delete cloud reports</button> : <button className="quiet-button" onClick={() => { setAuthMode("login"); setSyncOpen(true); }}>Log in</button>}</div></div>
            {settingsNotice && <div className="settings-notice" role="status"><CircleAlert size={15} /> {settingsNotice}</div>}
          </section>

          <section className="surface settings-card settings-safety-card">
            <div className="settings-card-heading"><span className="surface-kicker">SCANNER SAFETY</span><h2>Read-only checks</h2><p>Scanner protections are always enabled and cannot be disabled in this workspace.</p></div>
            <div className="safety-grid"><div><span className="settings-check"><Check size={15} /></span><span><strong>Public websites only</strong><small>Localhost and private IP ranges are blocked.</small></span></div><div><span className="settings-check"><Check size={15} /></span><span><strong>Same-origin crawl</strong><small>Same-origin links only; respects robots.txt.</small></span></div><div><span className="settings-check"><Check size={15} /></span><span><strong>Bounded requests</strong><small>20 pages, 30 seconds, 40 assets per scan.</small></span></div><div><span className="settings-check"><Check size={15} /></span><span><strong>No intrusive tests</strong><small>No payloads, form submissions, or access bypass attempts.</small></span></div></div>
            <p className="settings-rate-copy">Abuse limits: 5 scans per client per 10 minutes, 60 scans per running instance per 10 minutes, and 2 concurrent scans per client. Limits reset when a server instance restarts; multi-instance deployments should use a shared rate-limit store.</p>
          </section>
        </div>}

        <footer className="page-footer"><span><span className="footer-shield"><ShieldCheck size={14} /></span> Built for safer launches.</span><span className="footer-links"><a href="/terms">Terms</a><a href="/privacy">Privacy</a><span>PERIMETER SECURITY SCANNER <span className="footer-dot">·</span> v1.0</span></span></footer>
      </div>
    </main>

    {syncOpen && <div className="modal-backdrop" onMouseDown={(event) => { if (event.target === event.currentTarget) setSyncOpen(false); }}>
      <section className="sync-modal" role="dialog" aria-modal="true" aria-labelledby="sync-title">
        <button className="modal-close icon-button" aria-label="Close" onClick={() => setSyncOpen(false)}><X size={18} /></button>
        <span className="modal-icon"><Cloud size={21} /></span>
        <span className="surface-kicker">SUPABASE ACCOUNT</span>
        <h2 id="sync-title">Your reports, in sync.</h2>
        <p>Log in to access saved scans, or create an account to sync reports across devices.</p>
        {isSupabaseConfigured() ? <>
          <div className="auth-tabs" role="group" aria-label="Account action">
            <button type="button" aria-pressed={authMode === "login"} className={authMode === "login" ? "auth-tab auth-tab-active" : "auth-tab"} onClick={() => { setAuthMode("login"); setNotice(""); }}>Log in</button>
            <button type="button" aria-pressed={authMode === "signup"} className={authMode === "signup" ? "auth-tab auth-tab-active" : "auth-tab"} onClick={() => { setAuthMode("signup"); setNotice(""); }}>Sign up</button>
          </div>
          <form className="sync-form" onSubmit={handleAuthSubmit}>
            <label htmlFor="auth-email">Email</label>
            <input id="auth-email" type="email" autoComplete="email" placeholder="you@company.com" value={email} onChange={(event) => setEmail(event.target.value)} required />
            <label htmlFor="auth-password">Password</label>
            <input id="auth-password" type="password" autoComplete={authMode === "login" ? "current-password" : "new-password"} placeholder="At least 8 characters" value={password} onChange={(event) => setPassword(event.target.value)} minLength={8} required />
            <button className="scan-button" disabled={authBusy}>{authBusy ? <><LoaderCircle size={16} className="spin" /> Please wait</> : authMode === "login" ? <>Log in <ArrowUpRight size={16} /></> : <>Create account <ArrowUpRight size={16} /></>}</button>
          </form>
        </> : <div className="setup-callout"><strong>Supabase needs setup first</strong><span>Add the project URL, anon key, and service role key to <code>.env.local</code>, then run the SQL in <code>supabase/schema.sql</code>.</span></div>}
        {signedIn && <button className="text-button modal-signout" onClick={() => { void handleSignOut(); setSyncOpen(false); }}>Log out <LogOut size={15} /></button>}
        {notice && <div className="modal-notice" role="status">{notice}</div>}
      </section>
    </div>}
  </div>;
}

function FindingRow({ item, detailed = false }: { item: CheckResult; detailed?: boolean }) {
  const passed = item.status === "pass";
  return <article className={`finding-row ${passed ? "finding-pass" : ""}`}><span className={`finding-status ${passed ? "finding-status-pass" : item.status === "info" ? "finding-status-info" : "finding-status-issue"}`}>{passed ? <Check size={15} /> : item.status === "info" ? <Clock3 size={15} /> : <ShieldAlert size={15} />}</span><div className="finding-copy"><strong>{item.title}</strong><span>{item.detail}</span>{item.resource && <code>{item.resource}</code>}{detailed && item.evidence && <span className="finding-evidence"><strong>Observed evidence:</strong> {item.evidence}</span>}{detailed && item.recommendation && <span className="finding-recommendation"><strong>Recommended action:</strong> {item.recommendation}</span>}</div><span className={`severity-pill severity-${item.severity}`}>{severityLabel[item.severity]}</span></article>;
}
function EmptyState({ icon, title, detail, action }: { icon: ReactNode; title: string; detail: string; action: () => void }) {
  return <div className="empty-state"><span className="empty-state-icon">{icon}</span><strong>{title}</strong><span>{detail}</span><button className="scan-button" onClick={action}>Go to overview <ChevronRight size={16} /></button></div>;
}
