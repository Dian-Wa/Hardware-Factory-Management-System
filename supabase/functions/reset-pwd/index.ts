// ============================================================
// Supabase Edge Function: reset-pwd
// 作用：在未登录状态下，校验密保答案 / 恢复码后，用 service_role 重置密码
// 部署：在 Supabase 后台 Functions 页面新建函数（名称 reset-pwd），粘贴本文件内容；
//       并在函数 Settings 中添加两个 Secrets：
//         SUPABASE_URL            = 你的项目 URL（如 https://xxxx.supabase.co）
//         SUPABASE_SERVICE_ROLE_KEY = 项目的 service_role key（Project Settings → API）
// ============================================================

import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
};

// 必须与前端 hashPwd 完全一致（cyrb53 变体：seed 用长度，返回 h2+h1）
function hashPwd(s: string): string {
  let h1 = 0xdeadbeef ^ s.length, h2 = 0x41c6ce57 ^ s.length;
  for (let i = 0; i < s.length; i++) {
    const ch = s.charCodeAt(i);
    h1 = Math.imul(h1 ^ ch, 2654435761); h2 = Math.imul(h2 ^ ch, 1597334677);
  }
  h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^ Math.imul(h2 ^ (h2 >>> 13), 3266489909);
  h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^ Math.imul(h1 ^ (h1 >>> 13), 3266489909);
  return (h2 >>> 0).toString(16).padStart(8, '0') + (h1 >>> 0).toString(16).padStart(8, '0');
}

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: corsHeaders });
  try {
    const { username, answer, recoveryCode, newPassword } = await req.json();
    if (!username || !newPassword) {
      return new Response(JSON.stringify({ ok: false, error: '参数不完整' }), { status: 400, headers: corsHeaders });
    }
    const supabase = createClient(
      Deno.env.get('SUPABASE_URL')!,
      Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!,
      { auth: { persistSession: false } }
    );
    const { data: prof, error: pe } = await supabase
      .from('profiles')
      .select('id, security_a, recovery_code')
      .eq('username', username)
      .maybeSingle();
    if (pe || !prof) {
      return new Response(JSON.stringify({ ok: false, error: '账号不存在' }), { status: 404, headers: corsHeaders });
    }
    let ok = false;
    if (recoveryCode && prof.recovery_code && hashPwd(recoveryCode) === prof.recovery_code) ok = true;
    if (!ok && answer && prof.security_a && hashPwd(answer) === prof.security_a) ok = true;
    if (!ok) {
      return new Response(JSON.stringify({ ok: false, error: '密保答案或恢复码错误' }), { status: 401, headers: corsHeaders });
    }
    const { error: ue } = await supabase.auth.admin.updateUserById(prof.id, { password: newPassword });
    if (ue) {
      return new Response(JSON.stringify({ ok: false, error: ue.message }), { status: 400, headers: corsHeaders });
    }
    return new Response(JSON.stringify({ ok: true }), { headers: corsHeaders });
  } catch (e) {
    return new Response(JSON.stringify({ ok: false, error: e.message || '服务器错误' }), { status: 500, headers: corsHeaders });
  }
});
