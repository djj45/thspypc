#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
沪深全市场股票列表（复刻同花顺 A 股列表界面）。

纯 Python 实现（内置 http.server，不引入框架依赖）：
  - 启动：connect() → stock_list_cached() 秒拿 7400 条 code+name
  - 首屏：立即展示全量代码/名称（数值列空）
  - 后台：分批 list_quotes 回填行情（每批 30 只，按市场分组），渐进填充
  - 前端：虚拟滚动（7400 行不卡）+ 表头点击本地排序 + 同花顺深色风格

表头列（只列服务器直接返回的字段；涨跌幅/振幅/换手率等留待抓包补）：
  代码 · 名称 · 最新价 · 今开 · 最高 · 最低 · 昨收 · 成交量(手) · 成交额(元)

用法：
    uv run python tests/web_stocklist.py
    uv run python tests/web_stocklist.py --port 8888
    uv run python tests/web_stocklist.py --batch 50      # 加大批量加速回填
"""
import argparse
import logging
import os
import sys
import threading
import time
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from thspypc.client import THSClient, market_from_code

logger = logging.getLogger(__name__)

# list_quotes 请求的 DataType 字段集（2026-07-23 实测确认含义）：
#   dt5=代码 dt6=昨收 dt7=今开 dt8=最高 dt9=最低 dt10=最新价
#   dt13=成交股数(÷100=手) dt19=成交额(元)
LIST_DATATYPE = [5, 6, 7, 8, 9, 10, 13, 19]
# batch_size：list_quotes 一次查的代码数。30 是实测稳定上限（>30 服务器可能超时）。
DEFAULT_BATCH = 30


def _normalize_quote(rec: dict, base: dict) -> dict:
    """把 list_quotes 原始 dt<N> 记录合并进 base（含 code/name/market）。

    用 list_quotes 实际返回的 dt<N> 原始键取值（不能用 "price" 等具名键，
    list_quotes 不返回具名键）。

    Args:
        rec: list_quotes 返回的原始记录 {code, dt6, dt7, ...}
        base: 来自 stock_list 的 {code, name, market}，行情字段就地填充
    """
    base.update({
        "price": rec.get("dt10"),       # 最新价
        "prev_close": rec.get("dt6"),   # 昨收
        "open": rec.get("dt7"),         # 今开
        "high": rec.get("dt8"),         # 最高
        "low": rec.get("dt9"),          # 最低
        "amount": rec.get("dt19"),      # 成交额(元)
        "volume": rec.get("dt13"),      # 成交股数(÷100=手)
    })
    return base


class StockListState:
    """全局共享状态：股票列表 + 行情回填进度（线程安全）。"""

    def __init__(self):
        self.lock = threading.Lock()
        self.stocks: list[dict] = []           # 全量 [{code,name,market,price,...}]
        self.by_code: dict[str, dict] = {}     # code → stocks 内同一 dict（O(1) 回填）
        self.total = 0                         # 全量代码数
        self.loaded = 0                        # 已回填行情的数量
        self.loading = False                   # 后台是否在拉取
        self.last_error: str | None = None
        self.updated_at: float = 0.0           # 最后一批完成时间戳

    def set_stocks(self, stocks: list[dict]) -> None:
        with self.lock:
            self.stocks = stocks
            self.by_code = {s["code"]: s for s in stocks}
            self.total = len(stocks)
            # 重置行情进度（但保留已加载的——刷新场景）
            self.loaded = sum(1 for s in stocks if s.get("price") is not None)

    def update_quote(self, code: str, rec: dict) -> None:
        with self.lock:
            base = self.by_code.get(code)
            if base is not None:
                was_empty = base.get("price") is None
                _normalize_quote(rec, base)
                if was_empty:
                    self.loaded += 1
                self.updated_at = time.time()

    def snapshot(self) -> dict:
        """返回前端可序列化的快照（拷贝，避免序列化期间被改）。"""
        with self.lock:
            # stocks 内 dict 仍可能被后台改，但 update 是原子的（GIL），
            # json 序列化逐项读，读到的是一致快照，安全。
            return {
                "stocks": self.stocks,
                "total": self.total,
                "loaded": self.loaded,
                "loading": self.loading,
                "error": self.last_error,
                "updated_at": self.updated_at,
            }


STATE = StockListState()
CLIENT: THSClient | None = None  # 全局 client（主线程登录后赋值）


def load_env() -> None:
    """加载 .env 到 os.environ（不覆盖已有）。"""
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


def _fetch_loop(batch_size: int) -> None:
    """后台线程：分批 list_quotes 回填全市场行情。

    按市场分组（沪 17/深 33 各自批次），list_quotes 不支持的市场（market=None，
    如北交所/基金）跳过。每批失败不影响整体。
    """
    assert CLIENT is not None
    STATE.loading = True
    try:
        with STATE.lock:
            all_codes = [s["code"] for s in STATE.stocks]
        # 按市场码分组，避免一批里混不同市场（list_quotes 一次只能查一个市场码）
        groups: dict[int, list[str]] = {}
        skipped = 0
        for code in all_codes:
            mkt = market_from_code(code)
            if mkt is None:
                skipped += 1
                continue  # 北交所/基金等 list_quotes 不支持
            groups.setdefault(mkt, []).append(code)
        logger.info("行情回填开始: %d 只可查, %d 只跳过(不支持的市场), 分 %d 组",
                    len(all_codes) - skipped, skipped, len(groups))
        for mkt, codes in groups.items():
            for i in range(0, len(codes), batch_size):
                batch = codes[i:i + batch_size]
                try:
                    recs = CLIENT.list_quotes(batch, market=mkt,
                                              datatype=LIST_DATATYPE, timeout=15)
                except Exception as e:
                    logger.warning("list_quotes(market=%d, %s...) 失败: %s",
                                   mkt, batch[:3], e)
                    continue
                for r in recs:
                    code = r.get("code", "")
                    if code:
                        STATE.update_quote(code, r)
                STATE.loaded  # 触发（无副作用），保持计数准确
    except Exception as e:
        logger.exception("行情回填线程异常: %s", e)
        STATE.last_error = str(e)
    finally:
        STATE.loading = False
        logger.info("行情回填结束: 已加载 %d/%d", STATE.loaded, STATE.total)


# ── HTML/JS 页面（内嵌，复刻同花顺深色风格）──
HTML_PAGE = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>沪深A股 · 全市场列表</title>
<style>
*{margin:0;padding:0;box-sizing:border-box;}
body{background:#0d1117;color:#c9d1d9;font-family:'Microsoft YaHei',sans-serif;font-size:13px;}
.header{background:#161b22;padding:8px 16px;border-bottom:1px solid #30363d;display:flex;align-items:center;gap:14px;}
.header h1{font-size:15px;color:#58a6ff;}
.header .meta{color:#8b949e;font-size:12px;}
.header .meta b{color:#c9d1d9;}
.header .ctrl{margin-left:auto;display:flex;align-items:center;gap:10px;}
.progress{display:inline-block;width:160px;height:8px;background:#21262d;border-radius:4px;overflow:hidden;vertical-align:middle;}
.progress>span{display:block;height:100%;width:0;background:#58a6ff;transition:width .3s;}
.btn{background:#21262d;color:#c9d1d9;border:1px solid #30363d;padding:4px 12px;border-radius:4px;cursor:pointer;font-size:12px;}
.btn:hover{background:#30363d;}
.btn:disabled{opacity:.5;cursor:default;}
.table-wrap{height:calc(100vh - 44px);overflow:auto;}
table{width:100%;border-collapse:collapse;table-layout:fixed;}
thead th{background:#161b22;color:#8b949e;font-weight:normal;padding:8px 6px;text-align:right;
  border-bottom:1px solid #30363d;position:sticky;top:0;z-index:1;font-size:12px;cursor:pointer;
  user-select:none;white-space:nowrap;}
thead th:hover{color:#c9d1d9;}
thead th .arrow{font-size:10px;color:#58a6ff;margin-left:2px;}
thead th.l{text-align:left;}
/* 占位行：撑出虚拟滚动的总高度 */
#spacer-top,#spacer-bottom{height:0;}
td{padding:6px 6px;text-align:right;border-bottom:1px solid #21262d;font-variant-numeric:tabular-nums;}
td.l{text-align:left;}
.code{font-family:Consolas,monospace;}
.name{color:#c9d1d9;}
.muted{color:#484f58;}
tbody tr:hover td{background:#161b22;}
.muted-txt{color:#484f58;}
</style>
</head>
<body>
<div class="header">
  <h1>📊 沪深A股全市场</h1>
  <span class="meta" id="info">加载中...</span>
  <span class="ctrl">
    <span class="progress"><span id="bar"></span></span>
    <button class="btn" id="refresh-btn">刷新行情</button>
  </span>
</div>
<div class="table-wrap" id="wrap">
  <table>
    <thead><tr id="thead"></tr></thead>
    <tbody id="body"><tr id="spacer-top"></tr><tr id="spacer-bottom"></tr></tbody>
  </table>
</div>
<script>
// 列定义：key=字段名, label=表头, type=数值/文本, w=列宽(px)
const COLS=[
  {key:'code',label:'代码',type:'str',w:80,l:1},
  {key:'name',label:'名称',type:'str',w:96,l:1},
  {key:'price',label:'最新价',type:'num',w:78},
  {key:'open',label:'今开',type:'num',w:72},
  {key:'high',label:'最高',type:'num',w:72},
  {key:'low',label:'最低',type:'num',w:72},
  {key:'prev_close',label:'昨收',type:'num',w:72},
  {key:'volume',label:'成交量(手)',type:'num',w:90},
  {key:'amount',label:'成交额',type:'num',w:96},
];
// 排序状态：默认按成交额降序（最常用排序列）
let sortKey='amount', sortDir=-1;   // dir: -1=降序 1=升序
let allStocks=[];                   // 全量数据
let viewStart=-1, viewEnd=-1;       // 当前渲染范围（-1 = 尚未渲染/强制刷新）
const ROW_H=29;                     // 行高(px)，与 td padding 对齐
const BUFFER=15;                    // 视窗上下缓冲行数

function fmtNum(v){return v==null||v===undefined?'<span class="muted">--</span>':Number(v).toFixed(2);}
function fmtVol(v){
  if(v==null)return '<span class="muted">--</span>';
  const shou=Math.round(v/100);     // 股→手（dt13 单位是股，÷100）
  if(shou>=10000)return (shou/10000).toFixed(2)+'万手';
  return shou+'手';
}
function fmtAmt(v){
  if(v==null||v===0)return '<span class="muted">--</span>';
  if(Math.abs(v)>=1e8)return (v/1e8).toFixed(2)+'亿';
  if(Math.abs(v)>=1e4)return (v/1e4).toFixed(1)+'万';
  return Math.round(v);
}
function cellHtml(key,row){
  if(key==='code')return '<span class="code">'+row.code+'</span>';
  if(key==='name')return '<span class="name">'+(row.name||'')+'</span>';
  if(key==='volume')return fmtVol(row.volume);
  if(key==='amount')return fmtAmt(row.amount);
  return fmtNum(row[key]);
}

function renderHead(){
  const tr=document.getElementById('thead');
  tr.innerHTML=COLS.map(c=>{
    const isSort=c.key===sortKey;
    const arrow=isSort?(sortDir<0?' ▼':' ▲'):'';
    const cls='th'+(c.l?' l':'')+(isSort?' sorted':'');
    const style='width:'+c.w+'px;';
    return '<th class="'+(c.l?'l':'')+'" data-key="'+c.key+'" style="'+style+'">'
      +c.label+(isSort?'<span class="arrow">'+(sortDir<0?'▼':'▲')+'</span>':'')+'</th>';
  }).join('');
  tr.querySelectorAll('th').forEach(th=>{
    th.onclick=()=>{ const k=th.dataset.key;
      if(sortKey===k){sortDir=-sortDir;} else {sortKey=k; sortDir=-1;}
      renderHead(); sortData(); render();
    };
  });
}

function sortData(){
  const c=COLS.find(x=>x.key===sortKey);
  const dir=sortDir;
  allStocks.sort((a,b)=>{
    let va=a[sortKey], vb=b[sortKey];
    if(va==null&&vb==null)return 0;
    if(va==null)return 1;    // null 排到末尾（无论升降序）
    if(vb==null)return -1;
    if(c.type==='str'){
      return dir*String(va).localeCompare(String(vb));
    }
    return dir*((va>vb)?1:(va<vb)?-1:0);
  });
}

function render(){
  const wrap=document.getElementById('wrap');
  const total=allStocks.length;
  if(total===0)return;
  const topH=wrap.scrollTop;
  const visH=wrap.clientHeight;
  let start=Math.floor(topH/ROW_H)-BUFFER;
  if(start<0)start=0;
  let end=Math.ceil((topH+visH)/ROW_H)+BUFFER;
  if(end>total)end=total;
  if(start===viewStart&&end===viewEnd)return;   // 范围未变，跳过
  viewStart=start; viewEnd=end;
  const top=start*ROW_H, bottom=(total-end)*ROW_H;
  let html='';
  for(let i=start;i<end;i++){
    const row=allStocks[i];
    html+='<tr style="height:'+ROW_H+'px">';
    for(const c of COLS){
      const style=c.w?(' style="width:'+c.w+'px"':'');
      html+='<td'+style+(c.l?' class="l"':'')+'>'+cellHtml(c.key,row)+'</td>';
    }
    html+='</tr>';
  }
  const body=document.getElementById('body');
  body.innerHTML='<tr id="spacer-top" style="height:'+top+'px"></tr>'+html
    +'<tr id="spacer-bottom" style="height:'+bottom+'px"></tr>';
}

function updateInfo(s){
  const info=document.getElementById('info');
  const bar=document.getElementById('bar');
  const pct=s.total?Math.round(s.loaded/s.total*100):0;
  bar.style.width=pct+'%';
  const loadTxt=s.loading?'拉取中':'';
  const t=s.updated_at?new Date(s.updated_at*1000).toLocaleTimeString('zh-CN',{hour12:false}):'';
  info.innerHTML='共 <b>'+s.total+'</b> 只 · 行情 <b>'+s.loaded+'</b>/<b>'+s.total+'</b> ('+pct+'%)'+loadTxt
    +(s.error?' · <span style="color:#f85149">错误:'+s.error+'</span>':'')
    +(t?' · 更新 '+t:'');
}

let scrollPending=false;   // 滚动渲染节流标志（requestAnimationFrame）
async function pull(){
  try{
    const r=await fetch('/api/stocks');
    const s=await r.json();
    const changed = s.stocks && s.stocks.length!==allStocks.length;
    allStocks=s.stocks||[];
    sortData();
    // 数据变了就强制重渲染当前视窗（否则 render 的范围跳过逻辑会阻止数值更新）
    if(changed){ viewStart=-1; viewEnd=-1; }
    render(); updateInfo(s);
    // 加载中：短间隔渐进刷新；加载完：降频保活
    const next = s.loading ? 1500 : 5000;
    setTimeout(pull, next);
  }catch(e){ setTimeout(pull,3000); }
}

document.getElementById('wrap').addEventListener('scroll',()=>{
  if(!scrollPending){ scrollPending=true; requestAnimationFrame(()=>{ scrollPending=false; render(); }); }
}, {passive:true});

document.getElementById('refresh-btn').onclick=async function(){
  this.disabled=true; this.textContent='刷新中...';
  try{ await fetch('/api/refresh'); }catch(e){}
  // 重置渲染范围，强制下一帧重绘
  viewStart=-1; viewEnd=-1; setTimeout(()=>{this.disabled=false;this.textContent='刷新行情';},2000);
};

// 列宽撑满：等比例放大使总宽 ≥ 容器
function adjustWidths(){
  const totalW=COLS.reduce((a,c)=>a+c.w,0);
  const wrapW=document.getElementById('wrap').clientWidth-18;  // 留滚动条宽
  if(totalW<wrapW){
    const scale=wrapW/totalW;
    COLS.forEach(c=>c.w=Math.round(c.w*scale));
  }
  renderHead();
}

adjustWidths();
window.addEventListener('resize',()=>{adjustWidths(); viewStart=-1;viewEnd=-1; render();});
pull();
</script>
</body>
</html>"""


class StockListHandler(BaseHTTPRequestHandler):
    """HTTP 请求处理器（全静态，共享全局 STATE/CLIENT）。"""

    def log_message(self, *args):
        pass  # 静默默认访问日志

    def _json(self, data, status=200):
        import json
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", len(body))
        self.send_header("Cache-Control", "no-store")
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
        if self.path == "/" or self.path == "/index.html":
            self._html()
        elif self.path == "/api/stocks":
            self._json(STATE.snapshot())
        elif self.path == "/api/refresh":
            # 手动刷新：清空行情字段，重新触发后台回填
            _trigger_refresh()
            self._json({"ok": True})
        else:
            self._json({"error": "not found"}, 404)


_refresh_lock = threading.Lock()
_refresh_thread: threading.Thread | None = None


def _trigger_refresh(batch_size: int = DEFAULT_BATCH) -> None:
    """触发一次后台行情回填（刷新场景：清空行情字段后重新拉取）。

    同一时间只允许一个回填线程运行（_refresh_lock 保证）。
    """
    global _refresh_thread
    if CLIENT is None:
        return
    if STATE.loading:
        return  # 已在拉取，不重复触发
    # 清空行情字段（保留 code/name/market），重新回填
    with STATE.lock:
        for s in STATE.stocks:
            for k in ("price", "prev_close", "open", "high", "low",
                      "amount", "volume"):
                s.pop(k, None)
        STATE.loaded = 0
        STATE.last_error = None
    _refresh_thread = threading.Thread(
        target=_fetch_loop, args=(batch_size,), daemon=True)
    _refresh_thread.start()


def main():
    global CLIENT, _refresh_thread
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    load_env()

    ap = argparse.ArgumentParser(description="沪深全市场股票列表（复刻同花顺）")
    ap.add_argument("--port", type=int, default=8888, help="监听端口")
    ap.add_argument("--batch", type=int, default=DEFAULT_BATCH,
                    help="list_quotes 每批代码数（默认30，>30 可能超时）")
    args = ap.parse_args()

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
    CLIENT = client
    print(f"✓ 登录成功: {result.server}")

    print("加载沪深 A 股代码表（读同花顺本地名称缓存，瞬时零网络）...")
    # 用 hexin 本地名称缓存作 code+name 数据源（5556 条沪深 A 股，稳定可靠）。
    # 这里需要稳定的 code+name A 股集合；本地缓存无需占用 MAIN 连接，
    # 且名称覆盖更全。stock_list 已改为无订阅副作用的单请求。
    # 本地缓存含沪深北+基金+指数，过滤后得到 5500+ 沪深 A 股。
    names = client.fetch_stock_names_full()["names"]
    a_codes = []
    for code, name in names.items():
        mkt = market_from_code(code)
        if mkt is None:
            continue  # 非 A 股（新三板/基金/指数等），过滤掉
        a_codes.append({"code": code, "name": name, "market": mkt})
    # 按代码排序，便于首屏稳定
    a_codes.sort(key=lambda s: s["code"])
    STATE.set_stocks(a_codes)
    print(f"✓ 沪深 A 股: {len(a_codes)} 只（沪{sum(1 for s in a_codes if s['market']==17)}"
          f" + 深{sum(1 for s in a_codes if s['market']==33)})")

    # 启动后台行情回填
    _refresh_thread = threading.Thread(
        target=_fetch_loop, args=(args.batch,), daemon=True)
    _refresh_thread.start()

    server = ThreadingHTTPServer(("127.0.0.1", args.port), StockListHandler)
    print(f"\n📊 沪深A股全市场列表已启动: http://127.0.0.1:{args.port}")
    print("   按 Ctrl+C 退出\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n退出...")
        client.disconnect()


if __name__ == "__main__":
    main()
