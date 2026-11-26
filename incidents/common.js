/* Dùng chung cho mọi trang: kết nối Supabase, xác thực, điều hướng, tiện ích, MTTR/MTBF */
const CFG = window.CFG;
const sb = window.supabase.createClient(CFG.SUPABASE_URL, CFG.SUPABASE_ANON_KEY);
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];

const SEV = { low: 'Thấp', medium: 'Trung bình', high: 'Cao', critical: 'Nghiêm trọng' };
const SEV_CLS = { low: 'b-info', medium: 'b-warn', high: 'b-bad', critical: 'b-crit' };
const APPR = { pending: 'Chờ duyệt', approved: 'Đã duyệt', rejected: 'Bị từ chối' };
const APPR_CLS = { pending: 'b-warn', approved: 'b-ok', rejected: 'b-bad' };

const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const fmt = d => d ? new Date(d).toLocaleString('vi-VN', { dateStyle: 'short', timeStyle: 'short' }) : '—';
const toInput = d => { if (!d) return ''; const x = new Date(d); x.setMinutes(x.getMinutes() - x.getTimezoneOffset()); return x.toISOString().slice(0, 16); };
const fromInput = v => v ? new Date(v).toISOString() : null;
const hoursBetween = (a, b) => (new Date(b) - new Date(a)) / 36e5;
const fmtDur = h => h == null || isNaN(h) ? '—' : h < 1 ? Math.round(h * 60) + ' phút' : h < 48 ? h.toFixed(1) + ' giờ' : (h / 24).toFixed(1) + ' ngày';
const badge = (cls, txt) => `<span class="badge ${cls}">${esc(txt)}</span>`;
const sevBadge = s => badge(SEV_CLS[s] || '', SEV[s] || s);
const apprBadge = a => badge(APPR_CLS[a] || '', APPR[a] || a);
const stateBadge = r => r.resolved_at ? badge('b-ok', 'Đã khắc phục') : badge('b-bad', 'Còn tồn');
const fmtSize = n => n > 1048576 ? (n / 1048576).toFixed(1) + ' MB' : Math.max(1, Math.round(n / 1024)) + ' KB';
const qs = k => new URLSearchParams(location.search).get(k);
const never = () => new Promise(() => {});

function toast(msg) {
  let t = $('#toast');
  if (!t) { t = document.createElement('div'); t.id = 'toast'; t.setAttribute('role', 'status'); document.body.appendChild(t); }
  t.textContent = msg; t.classList.add('show');
  clearTimeout(t._h); t._h = setTimeout(() => t.classList.remove('show'), 2800);
}

function applyTheme(t) {
  if (t === 'dark' || t === 'light') document.documentElement.dataset.theme = t;
  else delete document.documentElement.dataset.theme;
}

function configBanner() {
  if (/YOUR-/.test(CFG.SUPABASE_URL)) {
    const d = document.createElement('div');
    d.className = 'notice';
    d.textContent = 'Chưa cấu hình Supabase. Mở incidents/config.js và điền SUPABASE_URL, SUPABASE_ANON_KEY.';
    (document.querySelector('main') || document.body).prepend(d);
    return true;
  }
  return false;
}

function renderNav(profile, active) {
  const items = [
    ['index.html', 'Tổng quan', 'index'],
    ['incidents.html', 'Danh sách sự cố', 'list'],
    ['incident-form.html', 'Báo cáo sự cố mới', 'new'],
    ...(profile.role === 'admin' ? [['approvals.html', 'Duyệt và tồn đọng', 'approvals']] : []),
    ['profile.html', 'Hồ sơ của tôi', 'profile']
  ];
  const el = document.createElement('nav');
  el.className = 'side';
  el.setAttribute('aria-label', 'Điều hướng chính');
  el.innerHTML = `<div class="brand">Quản lý sự cố</div>` +
    items.map(([h, t, k]) => `<a href="${h}" class="${k === active ? 'on' : ''}">${t}</a>`).join('') +
    `<a href="../">Về trang Manages</a>
     <div class="who"><b>${esc(profile.full_name || profile.email || 'Người dùng')}</b>${profile.role === 'admin' ? 'Quản trị viên' : 'Nhân viên'}
     <button id="signout" type="button">Đăng xuất</button></div>`;
  const shell = $('.shell');
  shell.prepend(el);
  $('#signout').onclick = async () => { await sb.auth.signOut(); location.href = 'signin.html'; };
}

async function requireAuth(opts = {}) {
  if (configBanner()) return never();
  const { data: { session } } = await sb.auth.getSession();
  if (!session) {
    location.href = 'signin.html?next=' + encodeURIComponent(location.pathname.split('/').pop() + location.search);
    return never();
  }
  const { data } = await sb.from('profiles').select('*').eq('id', session.user.id).maybeSingle();
  const profile = data || { id: session.user.id, email: session.user.email, role: 'staff', settings: {} };
  if (opts.admin && profile.role !== 'admin') { location.href = 'index.html'; return never(); }
  profile.settings = profile.settings || {};
  applyTheme(profile.settings.theme);
  renderNav(profile, opts.active);
  return { user: session.user, profile };
}

async function logEvent(incident_id, action, note) {
  const { data: { user } } = await sb.auth.getUser();
  await sb.from('incident_events').insert({ incident_id, actor: user.id, action, note: note || null });
}

/* MTTR = trung bình (khắc phục - bắt đầu hỏng) của sự cố đã khắc phục.
   MTBF = trung bình khoảng chạy ổn định giữa hai sự cố liên tiếp của cùng hệ thống
          (bắt đầu hỏng lần sau - khắc phục lần trước). Cần ít nhất 2 sự cố/hệ thống. */
const avg = a => a.length ? a.reduce((x, y) => x + y, 0) / a.length : null;
function computeMetrics(rows) {
  const done = rows.filter(r => r.resolved_at && r.started_at);
  const by = {};
  done.forEach(r => (by[r.system_name] = by[r.system_name] || []).push(r));
  const allGaps = [];
  const systems = Object.entries(by).map(([name, list]) => {
    list.sort((a, b) => new Date(a.started_at) - new Date(b.started_at));
    const gaps = [];
    for (let i = 0; i < list.length - 1; i++) {
      const g = hoursBetween(list[i].resolved_at, list[i + 1].started_at);
      if (g > 0) gaps.push(g);
    }
    allGaps.push(...gaps);
    return { name, count: list.length, mttr: avg(list.map(r => hoursBetween(r.started_at, r.resolved_at))), mtbf: avg(gaps) };
  }).sort((a, b) => b.count - a.count);
  return { mttr: avg(done.map(r => hoursBetween(r.started_at, r.resolved_at))), mtbf: avg(allGaps), systems, resolvedCount: done.length };
}

async function signedUrl(path) {
  const { data, error } = await sb.storage.from(CFG.BUCKET).createSignedUrl(path, 600);
  return error ? null : data.signedUrl;
}
