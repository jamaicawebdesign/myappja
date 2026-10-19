create table if not exists public.scans (
  id uuid primary key,
  user_id uuid not null references auth.users (id) on delete cascade,
  target_url text not null,
  score integer not null check (score between 0 and 100),
  checks jsonb not null default '[]'::jsonb,
  assets jsonb not null default '[]'::jsonb,
  scanned_at timestamptz not null default now()
);

create index if not exists scans_user_scanned_at_idx
  on public.scans (user_id, scanned_at desc);

alter table public.scans enable row level security;

create policy "Users can read their own scans"
  on public.scans for select
  to authenticated
  using (auth.uid() = user_id);

create policy "Users can insert their own scans"
  on public.scans for insert
  to authenticated
  with check (auth.uid() = user_id);