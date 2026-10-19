import { createClient } from "@supabase/supabase-js";
import { NextRequest, NextResponse } from "next/server";
import { scanWebsite } from "@/lib/scanner";

function supabaseConfig() {
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
  const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
  return url && anonKey && serviceKey ? { url, anonKey, serviceKey } : null;
}

function scansTableMissing(error: { code?: string; message?: string }) {
  return error.code === "PGRST205" || error.code === "42P01" || /public\.scans.*(not found|does not exist)|could not find the table.*scans/i.test(error.message ?? "");
}

async function authenticatedUser(request: NextRequest) {
  const config = supabaseConfig();
  const token = request.headers.get("authorization")?.replace(/^Bearer\s+/i, "");
  if (!config || !token) return null;
  const authClient = createClient(config.url, config.anonKey, { auth: { persistSession: false, autoRefreshToken: false } });
  const { data, error } = await authClient.auth.getUser(token);
  return error ? null : data.user;
}

export async function POST(request: NextRequest) {
  let body: unknown;
  try { body = await request.json(); } catch { return NextResponse.json({ error: "Request body must be valid JSON." }, { status: 400 }); }
  const url = typeof body === "object" && body !== null && "url" in body ? body.url : null;
  if (typeof url !== "string" || url.length > 2048) return NextResponse.json({ error: "Provide a website URL under 2,048 characters." }, { status: 400 });
  try {
    const scan = await scanWebsite(url);
    const config = supabaseConfig();
    if (!config) {
      return NextResponse.json({ scan, saved: false, saveError: "Supabase server credentials are not configured. The report is saved in this browser only." });
    }
    const user = await authenticatedUser(request);
    if (!user) return NextResponse.json({ scan, saved: false, saveError: "Log in to save scan results to Supabase. The report is saved in this browser only." });
    const admin = createClient(config.url, config.serviceKey, { auth: { persistSession: false, autoRefreshToken: false } });
    const { error } = await admin.from("scans").insert({ id: scan.id, user_id: user.id, target_url: scan.targetUrl, score: scan.score, checks: scan.checks, assets: scan.assets, scanned_at: scan.scannedAt });
    if (!error) return NextResponse.json({ scan, saved: true });
    console.error("Supabase scan insert failed:", error.code);
    const saveError = scansTableMissing(error)
      ? "Supabase is connected, but its scans table is missing. Run supabase/schema.sql in your project's SQL Editor. The report is saved in this browser only."
      : "Supabase could not save this report. Check the database setup; the report is saved in this browser only.";
    return NextResponse.json({ scan, saved: false, saveError });
  } catch (error) {
    const message = error instanceof Error ? error.message : "The website could not be scanned.";
    const status = /private|reserved|redirects must|only http|credentials|standard web ports|valid website/i.test(message) ? 400 : 502;
    return NextResponse.json({ error: message }, { status });
  }
}

export async function GET(request: NextRequest) {
  const user = await authenticatedUser(request);
  const config = supabaseConfig();
  if (!user || !config) return NextResponse.json({ error: "Sign in to load cloud scan history." }, { status: 401 });
  const admin = createClient(config.url, config.serviceKey, { auth: { persistSession: false, autoRefreshToken: false } });
  const { data, error } = await admin.from("scans").select("id,target_url,score,checks,assets,scanned_at").eq("user_id", user.id).order("scanned_at", { ascending: false }).limit(50);
  if (error) {
    if (scansTableMissing(error)) return NextResponse.json({ error: "The Supabase scans table is missing. Run supabase/schema.sql in your project's SQL Editor." }, { status: 503 });
    return NextResponse.json({ error: "Cloud scan history could not be loaded." }, { status: 502 });
  }
  const scans = (data ?? []).map((row) => ({ id: row.id, targetUrl: row.target_url, score: row.score, checks: row.checks, assets: row.assets, scannedAt: row.scanned_at }));
  return NextResponse.json(scans);
}

export async function DELETE(request: NextRequest) {
  const user = await authenticatedUser(request);
  const config = supabaseConfig();
  if (!user || !config) return NextResponse.json({ error: "Sign in to delete cloud scan history." }, { status: 401 });
  const admin = createClient(config.url, config.serviceKey, { auth: { persistSession: false, autoRefreshToken: false } });
  const { data, error } = await admin.from("scans").delete().eq("user_id", user.id).select("id");
  if (error) return NextResponse.json({ error: "Cloud scan history could not be deleted." }, { status: 502 });
  const deletedIds = (data ?? []).map((row) => row.id);
  return NextResponse.json({ deletedCount: deletedIds.length, deletedIds });
}