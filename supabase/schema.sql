-- ============================================================
-- Quản lý sự cố: schema cho Supabase (chạy trong SQL Editor hoặc qua migration)
-- ============================================================
create extension if not exists pgcrypto;

-- 1. Hồ sơ người dùng ---------------------------------------
create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  email text,
  full_name text,
  department text,
  phone text,
  role text not null default 'staff' check (role in ('staff','admin')),
  settings jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create or replace function public.is_admin() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.profiles where id = auth.uid() and role = 'admin');
$$;

create or replace function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  insert into public.profiles (id, email, full_name, department, phone)
  values (new.id, new.email,
          new.raw_user_meta_data->>'full_name',
          new.raw_user_meta_data->>'department',
          new.raw_user_meta_data->>'phone')
  on conflict (id) do nothing;
  return new;
end $$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users
  for each row execute function public.handle_new_user();

-- Người dùng thường không tự nâng quyền được (SQL Editor, không có auth.uid(), vẫn đổi được)
create or replace function public.protect_role() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if new.role is distinct from old.role and auth.uid() is not null and not public.is_admin() then
    new.role := old.role;
  end if;
  return new;
end $$;
drop trigger if exists protect_role on public.profiles;
create trigger protect_role before update on public.profiles
  for each row execute function public.protect_role();

-- 2. Sự cố ---------------------------------------------------
create table if not exists public.incidents (
  id uuid primary key default gen_random_uuid(),
  code text unique not null default ('SC-' || to_char(now(),'YYMMDD') || '-' || upper(substr(md5(random()::text),1,4))),
  title text not null,
  system_name text not null,               -- thiết bị / hệ thống bị sự cố
  category text,
  severity text not null default 'medium' check (severity in ('low','medium','high','critical')),
  description text,
  root_cause text,
  resolution text,
  started_at timestamptz not null,         -- thời điểm bắt đầu hỏng
  detected_at timestamptz,                 -- thời điểm phát hiện
  resolved_at timestamptz,                 -- thời điểm khắc phục xong (null = còn tồn)
  approval text not null default 'pending' check (approval in ('pending','approved','rejected')),
  review_note text,
  reviewed_by uuid references public.profiles(id),
  reviewed_at timestamptz,
  created_by uuid not null default auth.uid() references public.profiles(id),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  check (resolved_at is null or resolved_at >= started_at)
);
create index if not exists incidents_started_idx on public.incidents (started_at desc);
create index if not exists incidents_system_idx on public.incidents (system_name);
create index if not exists incidents_creator_idx on public.incidents (created_by);
create index if not exists incidents_approval_idx on public.incidents (approval);

create or replace function public.touch_updated_at() returns trigger language plpgsql as $$
begin new.updated_at = now(); return new; end $$;
drop trigger if exists incidents_touch on public.incidents;
create trigger incidents_touch before update on public.incidents
  for each row execute function public.touch_updated_at();

-- 3. Tệp đính kèm và lịch sử thao tác -------------------------
create table if not exists public.incident_attachments (
  id uuid primary key default gen_random_uuid(),
  incident_id uuid not null references public.incidents(id) on delete cascade,
  file_path text not null,
  file_name text not null,
  file_size bigint,
  mime_type text,
  uploaded_by uuid not null default auth.uid() references public.profiles(id),
  created_at timestamptz not null default now()
);
create index if not exists attachments_incident_idx on public.incident_attachments (incident_id);

create table if not exists public.incident_events (
  id bigint generated always as identity primary key,
  incident_id uuid not null references public.incidents(id) on delete cascade,
  actor uuid default auth.uid() references public.profiles(id),
  action text not null,
  note text,
  created_at timestamptz not null default now()
);
create index if not exists events_incident_idx on public.incident_events (incident_id, created_at);

-- 4. Row Level Security -------------------------------------
alter table public.profiles enable row level security;
alter table public.incidents enable row level security;
alter table public.incident_attachments enable row level security;
alter table public.incident_events enable row level security;

-- profiles: mọi người đã đăng nhập xem được tên/phòng ban (công cụ nội bộ); chỉ tự sửa của mình
drop policy if exists profiles_select on public.profiles;
create policy profiles_select on public.profiles for select to authenticated using (true);
drop policy if exists profiles_update on public.profiles;
create policy profiles_update on public.profiles for update to authenticated
  using (id = auth.uid() or public.is_admin()) with check (id = auth.uid() or public.is_admin());

-- incidents: xem sự cố của mình + sự cố đã duyệt; admin xem tất cả
drop policy if exists incidents_select on public.incidents;
create policy incidents_select on public.incidents for select to authenticated
  using (created_by = auth.uid() or approval = 'approved' or public.is_admin());
drop policy if exists incidents_insert on public.incidents;
create policy incidents_insert on public.incidents for insert to authenticated
  with check (created_by = auth.uid() and (approval = 'pending' or public.is_admin()));
drop policy if exists incidents_update on public.incidents;
create policy incidents_update on public.incidents for update to authenticated
  using (public.is_admin() or (created_by = auth.uid() and approval in ('pending','rejected')))
  with check (public.is_admin() or (created_by = auth.uid() and approval = 'pending'));
drop policy if exists incidents_delete on public.incidents;
create policy incidents_delete on public.incidents for delete to authenticated
  using (public.is_admin() or (created_by = auth.uid() and approval in ('pending','rejected')));

-- attachments
drop policy if exists att_select on public.incident_attachments;
create policy att_select on public.incident_attachments for select to authenticated
  using (exists (select 1 from public.incidents i where i.id = incident_id));
drop policy if exists att_insert on public.incident_attachments;
create policy att_insert on public.incident_attachments for insert to authenticated
  with check (uploaded_by = auth.uid() and exists (
    select 1 from public.incidents i where i.id = incident_id and (i.created_by = auth.uid() or public.is_admin())));
drop policy if exists att_delete on public.incident_attachments;
create policy att_delete on public.incident_attachments for delete to authenticated
  using (uploaded_by = auth.uid() or public.is_admin());

-- events
drop policy if exists ev_select on public.incident_events;
create policy ev_select on public.incident_events for select to authenticated
  using (exists (select 1 from public.incidents i where i.id = incident_id));
drop policy if exists ev_insert on public.incident_events;
create policy ev_insert on public.incident_events for insert to authenticated
  with check (actor = auth.uid() and exists (select 1 from public.incidents i where i.id = incident_id));

-- 5. Storage: bucket riêng tư, đường dẫn <user_id>/<incident_id>/<tệp> ---
insert into storage.buckets (id, name, public, file_size_limit)
values ('incident-files', 'incident-files', false, 20971520)
on conflict (id) do nothing;

drop policy if exists "incident files read" on storage.objects;
create policy "incident files read" on storage.objects for select to authenticated
  using (bucket_id = 'incident-files' and (
    public.is_admin()
    or (storage.foldername(name))[1] = auth.uid()::text
    or exists (select 1 from public.incident_attachments a
               join public.incidents i on i.id = a.incident_id
               where a.file_path = name and i.approval = 'approved')));
drop policy if exists "incident files upload" on storage.objects;
create policy "incident files upload" on storage.objects for insert to authenticated
  with check (bucket_id = 'incident-files' and (storage.foldername(name))[1] = auth.uid()::text);
drop policy if exists "incident files delete" on storage.objects;
create policy "incident files delete" on storage.objects for delete to authenticated
  using (bucket_id = 'incident-files' and ((storage.foldername(name))[1] = auth.uid()::text or public.is_admin()));

-- 6. Cấp quyền admin cho tài khoản đầu tiên (sửa email rồi chạy sau khi đã đăng ký):
-- update public.profiles set role = 'admin' where email = 'ban@congty.com';
