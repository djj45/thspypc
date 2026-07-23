#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
同花顺风格行情看板（简单 Web 展示）。

用 Python 内置 http.server，不引入额外依赖。登录 THSClient 后提供：
  GET /            → 行情看板 HTML 页面
  GET /api/quotes  → 自选股实时行情（list_quotes）
  GET /api/hot     → 热门股排序（stock_list_hot）
  GET /api/dxjl    → 短线精灵最新异动（dxjl_latest）

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

from thspypc.client import THSClient

logger = logging.getLogger(__name__)

# 默认自选股（沪市 17 / 深市 33）
DEFAULT_CODES = {
    17: ["600000", "601398", "601288", "601939", "600519", "600036",
         "601318", "600276", "601012", "600900"],
    33: ["000001", "000002", "000333", "000651", "002594", "300750",
         "000858", "002475", "300059", "000725"],
}

# ── HTML 页面（同花顺风格：深色底、红涨绿跌）──
HTML_PAGE = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>行情看板 · thspypc</title>
<style>
* { margin:0; padding:0; box-sizing:border-box; }
body { background:#0d1117; color:#c9d1d9; font-family:'Microsoft YaHei',sans-serif; font-size:13px; }
.header { background:#161b22; padding:10px 20px; border-bottom:1px solid #30363d; display:flex; align-items:center; gap:16px; }
.header h1 { font-size:16px; color:#58a6ff; }
.header .ts { color:#8b949e; font-size:12px; }
.header .status { margin-left:auto; font-size:12px; }
.status .dot { display:inline-block; width:8px; height:8px; border-radius:50%; margin-right:4px; }
.dot-ok { background:#3fb950; } .dot-err { background:#f85149; }
.container { display:grid; grid-template-columns:1fr 380px; gap:1px; background:#30363d; height:calc(100vh - 42px); }
.main { background:#0d1117; overflow-y:auto; }
.sidebar { background:#0d1117; overflow-y:auto; }
table { width:100%; border-collapse:collapse; }
th { background:#161b22; color:#8b949e; font-weight:normal; padding:8px 6px; text-align:right;
     border-bottom:1px solid #30363d; position:sticky; top:0; z-index:1; font-size:12px; }
th:first-child, td:first-child { text-align:left; }
td { padding:7px 6px; text-align:right; border-bottom:1px solid #21262d; font-variant-numeric:tabular-nums; }
tr:hover td { background:#161b22; }
.up { color:#f85149; }     /* 涨=红（中国习惯）*/
.down { color:#3fb950; }   /* 跌=绿 */
.flat { color:#8b949e; }
.section-title { background:#161b22; padding:8px 12px; color:#58a6ff; font-size:13px;
                 border-bottom:1px solid #30363d; position:sticky; top:0; }
.code { font-family:Consolas,monospace; }
.name { color:#8b949e; font-size:12px; margin-left:4px; }
.empty { color:#484f58; text-align:center; padding:40px; }
#dxjl-list { list-style:none; }
#dxjl-list li { padding:6px 12px; border-bottom:1px solid #21262d; display:flex; gap:8px; align-items:baseline; }
.dxjl-time { color:#8b949e; font-size:11px; width:56px; flex-shrink:0; }
.dxjl-code { font-family:Consolas,monospace; width:60px; flex-shrink:0; }
.dxjl-type { flex:1; font-size:12px; }
.dxjl-amt { font-family:Consolas,monospace; width:80px; text-align:right; flex-shrink:0; }
</style>
</head>
<body>
<div class="header">
  <h1>📊 行情看板</h1>
  <span class="ts" id="update-time">--</span>
  <span class="status"><span class="dot dot-err" id="dot"></span><span id="status-text">连接中...</span></span>
</div>
<div class="container">
  <div class="main">
    <div class="section-title">自选行情</div>
    <table>
      <thead><tr>
        <th>代码 / 名称</th><th>现价</th><th>涨跌幅</th><th>昨收</th><th>开盘</th>
      </tr></thead>
      <tbody id="quotes-body"><tr><td colspan="5" class="empty">加载中...</td></tr></tbody>
    </table>
    <div class="section-title" style="margin-top:8px">热门股（199112 排序）</div>
    <table>
      <thead><tr><th>#</th><th>代码</th><th>市场</th></tr></thead>
      <tbody id="hot-body"><tr><td colspan="3" class="empty">加载中...</td></tr></tbody>
    </table>
  </div>
  <div class="sidebar">
    <div class="section-title">⚡ 短线精灵异动</div>
    <ul id="dxjl-list"><li class="empty">加载中...</li></ul>
  </div>
</div>
<script>
const UP='up',DOWN='down',FLAT='flat';
function cls(v){ return v>0?UP:v<0?DOWN:FLAT; }
function fmt(v,d){ d=d||2; return v==null?'--':Number(v).toFixed(d); }
function pct(v){ return v==null?'--':(v>=0?'+':'')+v.toFixed(2)+'%'; }
function amt(v){
  if(v==null||v===0)return '--';
  if(Math.abs(v)>=1e8)return (v/1e8).toFixed(2)+'亿';
  if(Math.abs(v)>=1e4)return (v/1e4).toFixed(0)+'万';
  return Math.round(v);
}
async function fetchJSON(url){
  try{ const r=await fetch(url); return await r.json(); }
  catch(e){ return null; }
}
async function refreshQuotes(){
  const d=await fetchJSON('/api/quotes');
  const tb=document.getElementById('quotes-body');
  const dot=document.getElementById('dot'),st=document.getElementById('status-text');
  if(!d||d.error){ tb.innerHTML='<tr><td colspan="5" class="empty">'+(d&&d.error||'连接失败')+'</td></tr>';
    dot.className='dot dot-err'; st.textContent='断开'; return; }
  dot.className='dot dot-ok'; st.textContent='已连接 '+d.server;
  document.getElementById('update-time').textContent=d.time;
  if(!d.quotes||!d.quotes.length){ tb.innerHTML='<tr><td colspan="5" class="empty">无数据</td></tr>'; return; }
  tb.innerHTML=d.quotes.map(q=>{
    const chg=q.涨幅;
    return '<tr><td class="code">'+q.code+'<span class="name">'+(q.name||'')+'</span></td>'
      +'<td class="'+cls(chg)+'">'+fmt(q.现价)+'</td>'
      +'<td class="'+cls(chg)+'">'+pct(chg)+'</td>'
      +'<td class="flat">'+fmt(q.昨收)+'</td>'
      +'<td class="flat">'+fmt(q.开盘)+'</td></tr>';
  }).join('');
}
async function refreshHot(){
  const d=await fetchJSON('/api/hot');
  const tb=document.getElementById('hot-body');
  if(!d||!d.hot||!d.hot.length){ tb.innerHTML='<tr><td colspan="3" class="empty">无数据</td></tr>'; return; }
  tb.innerHTML=d.hot.map((h,i)=>'<tr><td class="flat">'+(i+1)+'</td>'
    +'<td class="code">'+h.code+'</td>'
    +'<td class="flat">'+(h.market||'')+'</td></tr>').join('');
}
async function refreshDxjl(){
  const d=await fetchJSON('/api/dxjl');
  const ul=document.getElementById('dxjl-list');
  if(!d||!d.dxjl||!d.dxjl.length){ ul.innerHTML='<li class="empty">暂无异动（非交易时段？）</li>'; return; }
  ul.innerHTML=d.dxjl.slice(0,50).map(r=>{
    const t=new Date(r.时间/1000); const ts=String(t.getHours()).padStart(2,'0')+':'+String(t.getMinutes()).padStart(2,'0')+':'+String(t.getSeconds()).padStart(2,'0');
    const c=cls(r.涨跌幅);
    return '<li><span class="dxjl-time">'+ts+'</span>'
      +'<span class="dxjl-code '+c+'">'+r.代码+'</span>'
      +'<span class="dxjl-type">'+r.异动类型+'</span>'
      +'<span class="dxjl-amt '+c+'">'+amt(r.金额)+'</span></li>';
  }).join('');
}
async function refreshAll(){ await Promise.all([refreshQuotes(),refreshHot(),refreshDxjl()]); }
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

    def log_message(self, *args):
        pass  # 静默默认日志

    def _json(self, data, status=200):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", len(body))
        self.end_headers()
        self.wfile.write(body)

    def _html(self):
        body = HTML_PAGE.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", len(body))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/":
            self._html()
        elif self.path == "/api/quotes":
            self._api_quotes()
        elif self.path == "/api/hot":
            self._api_hot()
        elif self.path == "/api/dxjl":
            self._api_dxjl()
        else:
            self._json({"error": "not found"}, 404)

    def _api_quotes(self):
        c = self.client
        if not c or c._sock is None:
            self._json({"error": "未连接"}); return
        quotes = []
        for market, codes in self.codes_by_market.items():
            try:
                recs = c.list_quotes(codes, market=market)
            except Exception as e:
                logger.warning("list_quotes(market=%d) 失败: %s", market, e)
                continue
            for r in recs:
                price = r.get("dt10")
                prev = r.get("dt6")
                open_p = r.get("dt7")
                chg = (price - prev) / prev * 100 if price and prev else None
                quotes.append({
                    "code": r.get("code", ""),
                    "name": "",  # list_quotes 不返回名称
                    "现价": price,
                    "昨收": prev,
                    "开盘": open_p,
                    "涨幅": round(chg, 2) if chg is not None else None,
                })
        self._json({
            "quotes": quotes,
            "time": time.strftime("%H:%M:%S"),
            "server": getattr(c, "_server_addr", ""),
        })

    def _api_hot(self):
        c = self.client
        if not c or c._sock is None:
            self._json({"hot": []}); return
        # stock_list_hot 在 list_quotes 用过的连接上可能冲突，
        # 用线程+超时保护，超时返回空（前端显示"无数据"）
        result = {"hot": []}
        def _run():
            try:
                result["hot"] = c.stock_list_hot(count=20)
            except Exception as e:
                logger.warning("stock_list_hot 失败: %s", e)
        t = threading.Thread(target=_run, daemon=True)
        t.start()
        t.join(timeout=10)
        self._json(result)

    def _api_dxjl(self):
        c = self.client
        if not c or c._sock is None:
            self._json({"dxjl": []}); return
        result = {"dxjl": []}
        def _run():
            try:
                result["dxjl"] = c.dxjl_latest()
            except Exception as e:
                logger.warning("dxjl_latest 失败: %s", e)
        t = threading.Thread(target=_run, daemon=True)
        t.start()
        t.join(timeout=10)
        self._json(result)


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


def main():
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    load_env()

    ap = argparse.ArgumentParser(description="同花顺风格行情看板")
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

    server = ThreadingHTTPServer(("127.0.0.1", args.port), DashboardHandler)
    print(f"\n📊 行情看板已启动: http://127.0.0.1:{args.port}")
    print("   按 Ctrl+C 退出\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n退出...")
        client.disconnect()


if __name__ == "__main__":
    main()
