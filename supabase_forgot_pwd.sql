-- ============================================================
-- 忘记密码功能 · 云端 Supabase 补充 SQL
-- 作用：为 profiles 表增加密保字段，并创建供「未登录查询」使用的 RPC
-- 使用：在 Supabase 后台 SQL Editor 中**粘贴全部内容** → Run
-- 前提：已执行过 supabase_schema.sql（profiles 表已存在）
-- ============================================================

-- 1) 给 profiles 增加手机 / 密保 / 恢复码字段
--    注意：原始 supabase_schema.sql 的 profiles 表只有 id/username/created_at，
--          **并不含 phone 列**，所以这里必须显式补上（if not exists 幂等，重复跑安全）
alter table public.profiles add column if not exists phone         text;
alter table public.profiles add column if not exists security_q    text;
alter table public.profiles add column if not exists security_a    text;
alter table public.profiles add column if not exists recovery_code text;

-- 2) 未登录时查询脱敏手机号 + 密保问题（security definer 绕过 RLS，仅返回非敏感字段）
--    注意：绝不在该函数中返回 security_a / recovery_code（密保答案与恢复码哈希）
create or replace function public.forgot_lookup(p_username text)
returns table (phone text, security_q text, has_recovery boolean)
language sql
security definer
set search_path = public
as $$
  select p.phone,
         p.security_q,
         (p.recovery_code is not null and p.recovery_code <> '')
  from public.profiles p
  where p.username = p_username
  limit 1;
$$;

-- 3) 授权匿名用户（未登录态）调用该查询函数
grant execute on function public.forgot_lookup(text) to anon, authenticated;

-- 4) profiles 表补充 update / delete 策略
--    原 supabase_schema.sql 只给了 select / insert 两条策略，没有 update，
--    导致前端云端「修改账号信息」写 phone / 密保 / 恢复码时被 RLS 拒绝（数据写不进库）。
--    这里补上 update / delete 策略（幂等：drop if exists 后重建）。
alter table public.profiles enable row level security;
drop policy if exists "own_profile_update" on public.profiles;
create policy "own_profile_update" on public.profiles
  for update using (auth.uid() = id) with check (auth.uid() = id);
drop policy if exists "own_profile_delete" on public.profiles;
create policy "own_profile_delete" on public.profiles
  for delete using (auth.uid() = id);
