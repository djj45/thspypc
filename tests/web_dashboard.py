#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
同花顺风格行情看板（数据校验用 Web 展示）。

用 Python 内置 http.server，不引入额外依赖。登录 THSClient 后提供：
  GET /            → 行情看板 HTML 页面
  GET /api/quotes  → 自选股实时行情（list_quotes，全 10 列原始字段透传）
  GET /api/hot     → 热门股排序（stock_list_hot，含名称）
  GET /api/dxjl    → 短线精灵最新异动（dxjl_latest，含名称）

定位：**数据校验**——把每个 API 的原始返回字段摊开，便于和同花顺客户端/抓包对照。
前端每 5 秒轮询刷新，同花顺风格（深色底、红涨绿跌）。

用法：
    uv run python tests/web_dashboard.py
    uv run python tests/web_dashboard.py --codes 600000,000001,600519
    uv run python tests/web_dashboard.py --port 8888
"""
import argparse
import json
import logging
import os
import sys
import threading
import time
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from thspypc.client import THSClient, market_from_code
from thspypc.protocol import SORT_BY_VALUES

logger = logging.getLogger(__name__)

# 默认自选股（沪市 17 / 深市 33）
DEFAULT_CODES = {
    17: ["600000", "601398", "601288", "601939", "600519", "600036",
         "601318", "600276", "601012", "600900"],
    33: ["000001", "000002", "000333", "000651", "002594", "300750",
         "000858", "002475", "300059", "000725"],
}

# list_quotes 全字段集（= client 默认集 LIST_QUOTE_DATATYPE_DEFAULT）。
# ⚠ 不自行增删 datatype 编号：实测往默认集里加 dt5(代码) 会导致服务器返回无法解析的
# 帧/超时（dt5 是响应里隐含的代码字段，请求 datatype 不应显式带它）。直接用默认集最稳。
# 字段含义（README「DataType 字段含义」表）：
#   dt7=今开 dt49=竞价笔 dt13=全天量 dt48=4分涨 dt10=现价 dt17=竞价量
#   dt6=昨收 dt66=涨幅 dt87=日期；code 由 hd 记录隐含返回（非 datatype 字段）
QUOTE_DATATYPE_FULL = [7, 49, 13, 48, 10, 17, 6, 66, 1111]

# ── HTML 页面（同花顺风格：深色底、红涨绿跌）──
HTML_PAGE = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>行情校验看板 · thspypc</title>
<style>
* { margin:0; padding:0; box-sizing:border-box; }
body { background:#0d1117; color:#c9d1d9; font-family:'Microsoft YaHei',sans-serif; font-size:13px; }
.header { background:#161b22; padding:10px 20px; border-bottom:1px solid #30363d; display:flex; align-items:center; gap:16px; flex-wrap:wrap; }
.header h1 { font-size:16px; color:#58a6ff; }
.header .ts { color:#8b949e; font-size:12px; }
.header .status { font-size:12px; }
.header .diag { color:#8b949e; font-size:12px; margin-left:auto; }
.status .dot { display:inline-block; width:8px; height:8px; border-radius:50%; margin-right:4px; vertical-align:middle; }
.dot-ok { background:#3fb950; } .dot-err { background:#f85149; } .dot-warn { background:#d29922; }
.container { display:grid; grid-template-columns:1fr 420px; gap:1px; background:#30363d; height:calc(100vh - 64px); }
.main { background:#0d1117; overflow-y:auto; }
.sidebar { background:#0d1117; overflow-y:auto; }
table { width:100%; border-collapse:collapse; }
th { background:#161b22; color:#8b949e; font-weight:normal; padding:8px 6px; text-align:right;
     border-bottom:1px solid #30363d; position:sticky; top:0; z-index:1; font-size:12px; white-space:nowrap; }
th:first-child, td:first-child { text-align:left; }
th.json-col, td.json-col { text-align:center; width:50px; }
td { padding:7px 6px; text-align:right; border-bottom:1px solid #21262d; font-variant-numeric:tabular-nums; }
tr:hover td { background:#161b22; }
.up { color:#f85149; }     /* 涨=红（中国习惯）*/
.down { color:#3fb950; }   /* 跌=绿 */
.flat { color:#8b949e; }
.derived { color:#d29922; }      /* 派生列（本地计算）标注橙色 */
.derived-tag { font-size:10px; color:#6e7681; }
.section-title { background:#161b22; padding:8px 12px; color:#58a6ff; font-size:13px;
                 border-bottom:1px solid #30363d; position:sticky; top:0; display:flex; align-items:center; gap:8px; }
.section-title .count { color:#8b949e; font-size:11px; font-weight:normal; }
.code { font-family:Consolas,monospace; }
.name { color:#8b949e; font-size:12px; margin-left:6px; }
.empty { color:#484f58; text-align:center; padding:40px; }
.err-row td { color:#f85149; text-align:left; padding:12px; }
#dxjl-list { list-style:none; }
#dxjl-list li { padding:6px 12px; border-bottom:1px solid #21262d; }
#dxjl-list .dxjl-line { display:flex; gap:8px; align-items:baseline; }
.dxjl-time { color:#8b949e; font-size:11px; width:56px; flex-shrink:0; }
.dxjl-code { font-family:Consolas,monospace; width:60px; flex-shrink:0; }
.dxjl-type { flex:1; font-size:12px; }
.dxjl-amt { font-family:Consolas,monospace; width:80px; text-align:right; flex-shrink:0; }
.dxjl-raw { margin-top:4px; padding:6px 8px; background:#161b22; border-radius:4px;
            font-family:Consolas,monospace; font-size:11px; color:#8b949e; white-space:pre-wrap; word-break:break-all; }
.json-link { color:#58a6ff; cursor:pointer; font-size:11px; text-decoration:underline; user-select:none; }
details summary { list-style:none; cursor:pointer; }
details summary::-webkit-details-marker { display:none; }
.raw-block { padding:6px 8px; background:#161b22; border-radius:4px; font-family:Consolas,monospace;
             font-size:11px; color:#8b949e; white-space:pre-wrap; word-break:break-all; }
.raw-block .k { color:#79c0ff; }
.raw-block .n { color:#f0883e; }
.sort-bar { padding:6px 12px; background:#161b22; border-bottom:1px solid #21262d; display:flex; gap:4px; flex-wrap:wrap; align-items:center; }
.sort-bar .label { color:#8b949e; font-size:11px; margin-right:4px; }
.sort-btn { background:#21262d; color:#c9d1d9; border:1px solid #30363d; padding:3px 10px;
            border-radius:3px; cursor:pointer; font-size:12px; font-family:inherit; }
.sort-btn:hover { background:#30363d; }
.sort-btn.active { background:#1f6feb; color:#fff; border-color:#1f6feb; }
.sort-btn .unverified { font-size:9px; color:#d29922; margin-left:2px; }
</style>
</head>
<body>
<div class="header">
  <h1>📊 行情校验看板</h1>
  <span class="ts" id="update-time">--</span>
  <span class="status"><span class="dot dot-err" id="dot"></span><span id="status-text">连接中...</span></span>
  <span class="diag" id="diag"></span>
</div>
<div class="container">
  <div class="main">
    <div class="section-title">自选行情 <span class="count" id="quotes-count"></span></div>
    <table>
      <thead><tr>
        <th>代码 / 名称</th><th>现价<br><span class="derived-tag">dt10</span></th>
        <th>涨跌幅<br><span class="derived-tag">dt66</span></th><th>4分涨<br><span class="derived-tag">dt48</span></th>
        <th>昨收<br><span class="derived-tag">dt6</span></th><th>今开<br><span class="derived-tag">dt7</span></th>
        <th>全天量<br><span class="derived-tag">dt13</span></th><th>竞价量<br><span class="derived-tag">dt17</span></th>
        <th>竞价笔<br><span class="derived-tag">dt49</span></th>
        <th class="derived">成交额<br><span class="derived-tag">dt13×dt10</span></th>
        <th class="derived">竞价金额<br><span class="derived-tag">dt17×dt7</span></th>
        <th class="json-col">原始</th>
      </tr></thead>
      <tbody id="quotes-body"><tr><td colspan="12" class="empty">加载中...</td></tr></tbody>
    </table>
    <div class="section-title" style="margin-top:8px">📈 排序榜单 <span class="count" id="hot-count"></span></div>
    <div class="sort-bar" id="sort-bar">
      <span class="label">榜单：</span>
      <button class="sort-btn active" data-sort-by="199112">涨幅</button>
      <button class="sort-btn" data-sort-by="48">涨速</button>
      <button class="sort-btn" data-sort-by="592890">主力净流入</button>
      <button class="sort-btn" data-sort-by="13">成交量<span class="unverified">未验证</span></button>
      <button class="sort-btn" data-sort-by="19">成交额<span class="unverified">未验证</span></button>
      <button class="sort-btn" data-sort-by="1968584">换手率<span class="unverified">未验证</span></button>
      <button class="sort-btn" data-sort-by="1771976">量比<span class="unverified">未验证</span></button>
    </div>
    <table>
      <thead><tr><th>#</th><th>代码</th><th>名称</th><th class="json-col">原始</th></tr></thead>
      <tbody id="hot-body"><tr><td colspan="4" class="empty">加载中...</td></tr></tbody>
    </table>
  </div>
  <div class="sidebar">
    <div class="section-title">⚡ 短线精灵异动 <span class="count" id="dxjl-count"></span></div>
    <ul id="dxjl-list"><li class="empty">加载中...</li></ul>
  </div>
</div>
<script>
const UP='up',DOWN='down',FLAT='flat';
function cls(v){ return v>0?UP:v<0?DOWN:FLAT; }
function fmt(v,d){ d=d==null?2:d; return v==null||v===''?'--':Number(v).toFixed(d); }
function pct(v){ return v==null||v===''?'--':(v>=0?'+':'')+Number(v).toFixed(2)+'%'; }
function pctTag(v,tag){ if(v==null||v===''||tag==null)return pct(v); return pct(v)+'<span class="derived-tag">('+tag+')</span>'; }
function amt(v){
  if(v==null||v===0||v==='')return '--';
  v=Number(v);
  if(Math.abs(v)>=1e8)return (v/1e8).toFixed(2)+'亿';
  if(Math.abs(v)>=1e4)return (v/1e4).toFixed(0)+'万';
  return Math.round(v);
}
function esc(s){ return String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
// 把对象渲染成带高亮的 JSON 文本（键蓝、数字橙）
function prettyJSON(obj){
  return esc(JSON.stringify(obj,null,2))
    .replace(/&quot;([^&]+)&quot;:/g,'<span class="k">"$1"</span>:')
    .replace(/: (-?\d+\.?\d*)/g,': <span class="n">$1</span>');
}
async function fetchJSON(url){
  try{ const r=await fetch(url); return await r.json(); }
  catch(e){ return null; }
}
function setDiag(text){ document.getElementById('diag').textContent=text||''; }
async function refreshQuotes(){
  const d=await fetchJSON('/api/quotes');
  const tb=document.getElementById('quotes-body');
  const dot=document.getElementById('dot'),st=document.getElementById('status-text');
  if(!d||d.error){
    tb.innerHTML='<tr class="err-row"><td colspan="12">自选行情错误: '+(d&&d.error||'连接失败')+'</td></tr>';
    dot.className='dot dot-err'; st.textContent='断开'; setDiag(''); return;
  }
  dot.className='dot '+(d.reused?'dot-warn':'dot-ok');
  st.textContent='已连接 '+(d.server||'');
  document.getElementById('update-time').textContent=d.time;
  document.getElementById('quotes-count').textContent=
    (d.count!=null?('返回 '+d.count+' 条'):'')+(d.errors&&d.errors.length?(' · '+d.errors.length+' 个市场失败'):'');
  const errs=d.errors||[];
  let diagParts=['自选 '+(d.count||0)+'/'+(d.expected||0)];
  if(errs.length)diagParts.push('错误: '+errs.join('; '));
  setDiag(diagParts.join(' · '));
  if(!d.quotes||!d.quotes.length){ tb.innerHTML='<tr><td colspan="12" class="empty">无数据'+(errs.length?'（见右上角诊断）':'')+'</td></tr>'; return; }
  tb.innerHTML=d.quotes.map(q=>{
    const chg=q.chg_value, chgTag=q.chg_source;
    const amount=(q.dt13&&q.dt10)?q.dt13*q.dt10:null;
    const bidAmt=(q.dt17&&q.dt7)?q.dt17*q.dt7:null;
    return '<tr>'
      +'<td><span class="code">'+esc(q.code)+'</span><span class="name">'+esc(q.name||'')+'</span></td>'
      +'<td class="'+cls(q.dt10)+'">'+fmt(q.dt10)+'</td>'
      +'<td class="'+cls(chg)+'">'+pctTag(chg,chgTag)+'</td>'
      +'<td class="'+cls(q.dt48)+'">'+pct(q.dt48)+'</td>'
      +'<td class="flat">'+fmt(q.dt6)+'</td>'
      +'<td class="'+cls(q.dt7)+'">'+fmt(q.dt7)+'</td>'
      +'<td class="flat">'+amt(q.dt13)+'</td>'
      +'<td class="flat">'+amt(q.dt17)+'</td>'
      +'<td class="flat">'+(q.dt49!=null?q.dt49:'--')+'</td>'
      +'<td class="derived">'+amt(amount)+'</td>'
      +'<td class="derived">'+amt(bidAmt)+'</td>'
      +'<td class="json-col"><details><summary class="json-link">JSON</summary>'
        +'<div class="raw-block">'+prettyJSON(q.raw||q)+'</div></details></td>'
      +'</tr>';
  }).join('');
}
// 当前选中的榜单 sort_by（默认 199112=涨幅）
let currentSortBy='199112';
async function refreshHot(){
  const d=await fetchJSON('/api/hot?sort_by='+currentSortBy);
  const tb=document.getElementById('hot-body');
  const hc=document.getElementById('hot-count');
  if(!d||d.error){ tb.innerHTML='<tr class="err-row"><td colspan="4">榜单错误: '+(d&&d.error||'连接失败')+'</td></tr>'; hc.textContent=''; return; }
  hc.textContent=d.sort_total!=null?('sort_total='+d.sort_total):'';
  if(!d.hot||!d.hot.length){ tb.innerHTML='<tr><td colspan="4" class="empty">无数据（sort_total='+(d.sort_total||0)+'，非交易时段可能无排序数据）</td></tr>'; return; }
  tb.innerHTML=d.hot.map((h,i)=>'<tr><td class="flat">'+(i+1)+'</td>'
    +'<td class="code">'+esc(h.code)+'</td>'
    +'<td class="flat">'+esc(h.name||'')+'</td>'
    +'<td class="json-col"><details><summary class="json-link">JSON</summary>'
      +'<div class="raw-block">'+prettyJSON(h.raw||h)+'</div></details></td></tr>').join('');
}
// 榜单切换按钮
document.getElementById('sort-bar').addEventListener('click',function(e){
  const btn=e.target.closest('.sort-btn');
  if(!btn) return;
  document.querySelectorAll('.sort-btn').forEach(b=>b.classList.remove('active'));
  btn.classList.add('active');
  currentSortBy=btn.dataset.sortBy;
  refreshHot();
});
async function refreshDxjl(){
  const d=await fetchJSON('/api/dxjl');
  const ul=document.getElementById('dxjl-list');
  document.getElementById('dxjl-count').textContent=d&&d.count!=null?('返回 '+d.count+' 条'):'';
  if(!d||d.error){ ul.innerHTML='<li class="empty">短线精灵错误: '+(d&&d.error||'连接失败')+'</li>'; return; }
  if(!d.dxjl||!d.dxjl.length){ ul.innerHTML='<li class="empty">暂无异动（非交易时段？）</li>'; return; }
  ul.innerHTML=d.dxjl.slice(0,50).map(r=>{
    const t=new Date(r.时间/1000);
    const ts=String(t.getHours()).padStart(2,'0')+':'+String(t.getMinutes()).padStart(2,'0')+':'+String(t.getSeconds()).padStart(2,'0');
    const c=cls(r.涨跌幅);
    return '<li><div class="dxjl-line">'
      +'<span class="dxjl-time">'+ts+'</span>'
      +'<span class="dxjl-code '+c+'">'+esc(r.代码)+'</span>'
      +'<span class="name">'+esc(r.name||'')+'</span>'
      +'<span class="dxjl-type">'+esc(r.异动类型)+'</span>'
      +'<span class="dxjl-amt '+c+'">'+amt(r.金额)+'</span>'
      +'</div><details><summary class="json-link">原始字段</summary>'
      +'<div class="dxjl-raw">'+prettyJSON(r.raw||r)+'</div></details></li>';
  }).join('');
}
// 初始加载串行（后端 _query_lock 会串行化查询，前端顺序发避免三请求同时排队等待）
async function refreshAll(){ await refreshQuotes(); await refreshHot(); await refreshDxjl(); }
refreshAll();
setInterval(refreshQuotes,5000);
setInterval(refreshHot,30000);
setInterval(refreshDxjl,5000);
</script>
</body>
</html>
"""


class DashboardHandler(BaseHTTPRequestHandler):
    """HTTP 请求处理器。"""
    client: THSClient | None = None
    codes_by_market: dict = DEFAULT_CODES
    _name_map: dict[str, str] = {}     # code → 中文名（启动时预加载）
    # 串行化所有对 8901 主连接的查询。list_quotes 的 _sock_lock 只保护 send 不保护
    # read（client.py 的已知缺陷），ThreadingHTTPServer 多线程并行轮询 /api/quotes
    # /api/hot /api/dxjl 会并发 read_frame 同一 socket → 帧错位/互吞响应 → 超时。
    # 本锁把所有查询排队执行，从源头杜绝并发读。
    _query_lock = threading.Lock()

    def log_message(self, *args):
        pass  # 静默默认日志

    def _json(self, data, status=200):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        try:
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", len(body))
            self.end_headers()
            self.wfile.write(body)
        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
            # 浏览器等不及超时取消了 fetch（前端刷新/切走标签页），写响应时连接已断。
            # 属正常情况，静默忽略，不影响后续请求处理。
            pass

    def _html(self):
        body = HTML_PAGE.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", len(body))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)
        if parsed.path == "/":
            self._html()
        elif parsed.path == "/api/quotes":
            self._api_quotes()
        elif parsed.path == "/api/hot":
            self._api_hot(qs)
        elif parsed.path == "/api/dxjl":
            self._api_dxjl()
        else:
            self._json({"error": "not found"}, 404)

    # ── 自选股行情（list_quotes 全字段透传，校验用）──
    def _api_quotes(self):
        c = self.client
        if not c or c._sock is None:
            self._json({"error": "未连接"}); return
        quotes = []
        errors = []
        expected = sum(len(v) for v in self.codes_by_market.values())
        # 串行化：list_quotes 的 read 不持 _sock_lock，并发读会帧错位（见类注释）
        with self._query_lock:
            for market, codes in self.codes_by_market.items():
                try:
                    # timeout 调短到 6s：非交易时段服务器对个股行情请求常不响应，
                    # 用 client 默认 15s 会让前端干等到 abort。6s 足够交易时段拿数据。
                    recs = c.list_quotes(codes, market=market,
                                         datatype=QUOTE_DATATYPE_FULL, timeout=6)
                except Exception as e:
                    msg = f"market={market}: {type(e).__name__}: {e}"
                    logger.warning("list_quotes(%s) 失败: %s", market, e)
                    errors.append(msg)
                    continue
                for r in recs:
                    price = r.get("dt10")
                    prev = r.get("dt6")
                    dt66 = r.get("dt66")
                    # 涨跌幅：优先服务器 dt66；缺失时本地 (dt10-dt6)/dt6 回退
                    chg_value = None
                    chg_source = None
                    if dt66 not in (None, "", 0):
                        chg_value, chg_source = dt66, "dt66"
                    elif price and prev:
                        chg_value, chg_source = (price - prev) / prev * 100, "本地"
                    quotes.append({
                        "code": r.get("code", ""),
                        "name": self._name_map.get(r.get("code", ""), ""),
                        # 原始字段透传（前端按 dt 编号展示，便于对照抓包）
                        "dt6": prev,
                        "dt7": r.get("dt7"),
                        "dt10": price,
                        "dt13": r.get("dt13"),
                        "dt17": r.get("dt17"),
                        "dt48": r.get("dt48"),
                        "dt49": r.get("dt49"),
                        "dt66": dt66,
                        "chg_value": round(chg_value, 2) if chg_value is not None else None,
                        "chg_source": chg_source,
                        "raw": r,   # 完整原始 dict（含所有 dt<N> 键）
                    })
        self._json({
            "quotes": quotes,
            "count": len(quotes),
            "expected": expected,
            "errors": errors,
            "time": time.strftime("%H:%M:%S"),
            "server": getattr(c, "_server_addr", None) or self._server_diag(c),
            "reused": getattr(c, "_last_connect_ts", 0) > 0
                      and c.is_connected
                      and (time.time() - c._last_connect_ts < c._CONNECT_COOLDOWN),
        })

    # ── 排序榜单（stock_list_hot，含名称 + 原始字段，支持榜单切换）──
    def _api_hot(self, qs=None):
        c = self.client
        if not c or c._sock is None:
            self._json({"error": "未连接"}); return
        # 解析榜单参数：?sort_by=<编号>，默认 199112（涨幅）
        sort_by = 199112
        if qs and qs.get("sort_by"):
            try:
                sort_by = int(qs["sort_by"][0])
            except (ValueError, IndexError):
                pass
        result = {"hot": [], "sort_total": 0, "sort_by": sort_by, "error": None}
        # 串行化：与其他查询排队，避免并发读主连接 socket（见类注释）
        with self._query_lock:
            try:
                stocks = c.stock_list_hot(count=50, sort_by=sort_by)
                for s in stocks:
                    # raw = 服务器原始字段快照（填 name 前的 dict 副本）
                    s["raw"] = dict(s)
                    s["name"] = self._name_map.get(s.get("code", ""), "")
                result["hot"] = stocks
            except Exception as e:
                result["error"] = f"{type(e).__name__}: {e}"
                logger.warning("stock_list_hot(sort_by=%d) 失败: %s", sort_by, e)
        self._json(result)

    # ── 短线精灵异动（dxjl_latest，含名称 + 原始字段）──
    def _api_dxjl(self):
        c = self.client
        if not c or c._sock is None:
            self._json({"error": "未连接"}); return
        result = {"dxjl": [], "count": 0, "error": None}
        # dxjl 走 9601 独立连接（_realorder_sock），与 8901 主连接的 _sock_lock 不同，
        # 但仍串行化以避免与心跳线程/dxjl_history 的读竞争
        with self._query_lock:
            try:
                recs = c.dxjl_latest()
                for r in recs:
                    r["name"] = self._name_map.get(r.get("代码", ""), "")
                    r["raw"] = {k: v for k, v in r.items() if k != "raw"}
                result["dxjl"] = recs
                result["count"] = len(recs)
            except Exception as e:
                result["error"] = f"{type(e).__name__}: {e}"
                logger.warning("dxjl_latest 失败: %s", e)
        self._json(result)

    @staticmethod
    def _server_diag(c: THSClient) -> str:
        """从 client 对象推导当前连接的服务器描述（诊断用）。"""
        if c._sock is None:
            return "(未连接)"
        try:
            peer = c._sock.getpeername()
            return f"{peer[0]}:{peer[1]}" if peer else "(未知)"
        except OSError:
            return "(socket 已关)"


def load_env():
    """加载 .env 到 os.environ。"""
    env_path = os.path.join(os.path.dirname(__file__), "..", ".env")
    if not os.path.exists(env_path):
        return
    for line in open(env_path, encoding="utf-8"):
        line = line.strip()
        if "=" in line and not line.startswith("#"):
            k, _, v = line.partition("=")
            k = k.strip()
            if k and k not in os.environ:
                os.environ[k] = v.strip().strip('"').strip("'")


def preload_names() -> dict[str, str]:
    """启动时预加载股票名称映射（code→中文名）。

    **只用 load_hexin_names**（读同花顺本地 stockname 文件，全品种 ~5.8万条：
    含 A 股/新三板/北交所/可转债/ETF/国债期货等，覆盖最全）。

    ⚠ **不调 stock_list_cached**：它首次缓存未命中时会走 stock_list() 重放
    subreal 订阅序列，重放后订阅无法取消，服务器持续往主连接推送帧，
    会淹没后续 list_quotes / stock_list_hot 导致超时。load_hexin_names 纯读
    本地文件、零网络、零副作用，且覆盖更全（58527 vs stock_list 的 ~7400）。
    """
    name_map: dict[str, str] = {}
    try:
        name_map = THSClient.load_hexin_names()
        logger.info("load_hexin_names: %d 条", len(name_map))
    except Exception as e:
        logger.warning("load_hexin_names 失败（名称将为空）: %s", e)

    # 分项统计：A 股（list_quotes 能查）vs 其他品种（查不到，仅备名称）
    a_stock = sum(1 for code in name_map if market_from_code(code) is not None)
    others = len(name_map) - a_stock
    logger.info("名称映射就绪: 沪深A股 %d + 其他品种 %d = %d 条",
                a_stock, others, len(name_map))
    return name_map


def main():
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    load_env()

    ap = argparse.ArgumentParser(description="同花顺风格行情校验看板")
    ap.add_argument("--port", type=int, default=8888)
    ap.add_argument("--codes", default=None,
                    help="自选股代码（逗号分隔，沪市开头6/深市开头0/3）")
    args = ap.parse_args()

    if args.codes:
        sh = [c.strip() for c in args.codes.split(",") if c.strip().startswith(("6",))]
        sz = [c.strip() for c in args.codes.split(",") if c.strip().startswith(("0", "3"))]
        DashboardHandler.codes_by_market = {17: sh, 33: sz}

    username = os.environ.get("THS_USERNAME", "")
    password = os.environ.get("THS_PASSWORD", "")
    if not username or not password:
        print("✗ 缺账号/密码，请在 .env 配 THS_USERNAME/THS_PASSWORD")
        sys.exit(1)

    print("登录中...")
    client = THSClient(username, password)
    result = client.connect()
    if not result.success:
        print(f"✗ 登录失败: {result.error}")
        sys.exit(1)
    DashboardHandler.client = client
    print(f"✓ 登录成功: {result.server}")

    # 预加载股票名称（纯读同花顺本地文件，零网络、不破坏主连接）
    print("预加载股票名称...")
    DashboardHandler._name_map = preload_names()

    server = ThreadingHTTPServer(("127.0.0.1", args.port), DashboardHandler)
    print(f"\n📊 行情校验看板已启动: http://127.0.0.1:{args.port}")
    print("   按 Ctrl+C 退出\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n退出...")
        client.disconnect()


if __name__ == "__main__":
    main()
