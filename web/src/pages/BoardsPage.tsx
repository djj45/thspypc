import { useEffect, useMemo, useRef, useState } from 'react'
import { api } from '../api/endpoints'
import { useData } from '../data/useData'
import { useStockNames } from '../data/useStockNames'
import { useStock } from '../state/StockContext'
import type { Board, Kline, Quote, TimelinePoint } from '../types'
import { BoardKlineChart } from '../components/boards/BoardKlineChart'
import { BoardTimelineChart } from '../components/boards/BoardTimelineChart'
import { KlineChart } from '../components/center/KlineChart'
import { TimelineChart } from '../components/center/TimelineChart'
import {
  BoardTable,
  sortRows,
  StateBox,
  StockTable,
  usePersistedWidth,
  useQuoteExt,
  type BoardRowData,
  type ColSort,
  type StockRowData,
} from '../components/left/shared'
import { KLINE_MA_WARMUP, KLINE_VIEW_COUNT } from '../state/StockContext'

// 94板块页（热点板块 pageid=12480）：2 行 × 3 列。
// (1,1) 板块列表（热点板块全量，本地表头排序）
// (1,2) 板块分时  (1,3) 板块日K
// (2,1) 板块成分股（点击选中个股 → 全局 code；表头排序跨板块保留）
// (2,2) 个股分时  (2,3) 个股日K（均复用看盘页的全局股票上下文组件）

function readBoardParam(): string | null {
  const value = new URLSearchParams(window.location.search).get('board')
  return /^\d{6}$/.test(value ?? '') ? (value as string) : null
}

// 成分股表头排序持久化：切换板块/离开再进 94板块页都保留上次排序。
const CONS_SORT_KEY = 'ths.boards.consSort'

function readConsSort(): ColSort {
  try {
    const raw = localStorage.getItem(CONS_SORT_KEY)
    if (raw) {
      const parsed = JSON.parse(raw) as ColSort
      if (
        parsed &&
        typeof parsed.key === 'string' &&
        typeof parsed.desc === 'boolean'
      ) {
        return parsed
      }
    }
  } catch {
    /* 损坏的缓存忽略 */
  }
  return { key: 'chgPct', desc: true }
}

export function BoardsPage() {
  const [boardCode, setBoardCode] = useState<string | null>(readBoardParam)
  const [consSort, setConsSort] = useState<ColSort>(readConsSort)
  const { code, setCode } = useStock()
  const names = useStockNames()
  const stockLabel = `${names.get(code) ?? ''} ${code}`.trim()

  // 三列宽度可拖拽（与看盘页左栏同款分隔条），localStorage 持久化。
  // 列1=板块/成分股列表，列2=分时，列3=日K（吸收剩余宽度）。
  const col1 = usePersistedWidth('ths.layout.boardsCol1', 360, 240, 720)
  const col1W = Math.min(col1.w, Math.max(240, window.innerWidth - 660))
  const col2 = usePersistedWidth(
    'ths.layout.boardsCol2',
    560,
    320,
    Math.max(400, window.innerWidth - col1W - 320),
  )
  // 读取持久化值时按另一列宽度再夹一次（两列都持久化，可能后来超界）
  const col2W = Math.min(
    col2.w,
    Math.max(320, window.innerWidth - col1W - 320),
  )

  const boards = useData<Board[]>(() => api.hotBoards(), [], 'poll', 0, 8000)

  // 板块选择写入 URL（?board=886099），RoutedShell 重写 view/code 时会保留
  const selectBoard = (next: string) => {
    if (next === boardCode) return
    setBoardCode(next)
    const query = new URLSearchParams(window.location.search)
    query.set('board', next)
    window.history.replaceState(null, '', `/?${query.toString()}`)
  }

  // 无选择（或 URL 板块不在列表中）时默认选中涨幅榜首
  useEffect(() => {
    if (!boards.data?.length) return
    if (boardCode && boards.data.some((b) => b.code === boardCode)) return
    const top = [...boards.data].sort(
      (a, b) => (b.chg_pct ?? -Infinity) - (a.chg_pct ?? -Infinity),
    )[0]
    if (top) setBoardCode(top.code)
  }, [boards.data, boardCode])

  const board = boards.data?.find((b) => b.code === boardCode)
  const boardLabel = board ? `${board.name ?? ''} ${board.code}`.trim() : (boardCode ?? '')

  const boardRows: BoardRowData[] = useMemo(
    () =>
      (boards.data ?? []).map((b) => ({
        code: b.code,
        name: b.name ?? b.code,
        chgPct: b.chg_pct,
        speed1m: b.speed_1m,
        speed4m: b.speed_4m,
        mainInflow: b.main_inflow,
        upCount: b.up_count,
        downCount: b.down_count,
        limitUp: b.limit_up,
      })),
    [boards.data],
  )

  // 板块分时（盘中轮询）/ 日K（60s：收盘后不变，盘中仅尾根微动）。
  // 日K 多拉 MA_WARMUP 根用于均线预热（与个股日K同款：MA 最长 120，
  // 不预热时可视区左侧均线缺一段），展示侧由图表裁回可视数量。
  const timeline = useData<TimelinePoint[]>(
    () => (boardCode ? api.boardTimeline(boardCode) : Promise.resolve([])),
    [boardCode],
    'poll',
    0,
    5000,
  )
  const kline = useData<Kline[]>(
    () =>
      boardCode
        ? api.boardKline(boardCode, KLINE_VIEW_COUNT + KLINE_MA_WARMUP)
        : Promise.resolve([]),
    [boardCode],
    'poll',
    0,
    60_000,
  )

  // 成分股（fu4 批量行情；dt66 涨幅/dt19 成交额/dt48 涨速）。板块通道查询
  // 较重（L2 按沪/深整板块提交），15s 轮询 + 可视窗口 quotes_ext 补快字段。
  // fetcher 给数据打上板块标记：切板块后旧数据仍在屏时不会误触发首股选中。
  const constituents = useData<{ board: string; rows: Quote[] }>(
    () =>
      boardCode
        ? api.boardConstituents(boardCode).then((rows) => ({
            board: boardCode,
            rows,
          }))
        : Promise.resolve({ board: '', rows: [] as Quote[] }),
    [boardCode],
    'poll',
    0,
    15_000,
  )
  const consRows =
    constituents.data && constituents.data.board === boardCode
      ? constituents.data.rows
      : null

  const consMap = useMemo(
    () => new Map((consRows ?? []).map((r) => [r.code, r])),
    [consRows],
  )
  const consCodes = useMemo(
    () => [...consMap.keys()],
    [consMap],
  )

  const onConsSortChange = (next: ColSort) => {
    setConsSort(next)
    try {
      localStorage.setItem(CONS_SORT_KEY, JSON.stringify(next))
    } catch {
      /* 存储失败忽略 */
    }
  }
  const [visibleCodes, setVisibleCodes] = useState<string[]>([])
  // 小板块整组刷新（涨幅排序能把视口外的强弱股移进来）；大板块只拉可视窗口
  const quoteCodes = consCodes.length <= 100 ? consCodes : visibleCodes
  const quotes = useQuoteExt(quoteCodes)

  const stockRows: StockRowData[] = useMemo(
    () =>
      consCodes.map((c) => {
        const row = consMap.get(c)
        const q = quotes.get(c)
        return {
          code: c,
          name: names.get(c) ?? '',
          // 涨幅首选成分股查询自带的 chg_pct（后端按 dt10/dt6 补算，
          // 通道 dt66 收盘后为 0 不可用）：列表到达即完整可排序/选中，
          // quotes_ext 仅作为盘中更新鲜的覆盖值（与 RankPanel 同款语义）。
          chgPct:
            q?.chg_pct ??
            (typeof row?.chg_pct === 'number' ? row.chg_pct : undefined) ??
            (typeof row?.dt66 === 'number' ? row.dt66 : undefined),
          auctionChgPct: q?.auction_chg_pct ?? undefined,
          auctionAmount: q?.auction_amount ?? undefined,
          amount: row?.dt19 ?? q?.amount ?? undefined,
          speed4m: row?.dt48 ?? q?.speed_4m ?? undefined,
          mainInflow: q?.main_inflow ?? undefined,
          sealAmount: q?.seal_amount || undefined,
        }
      }),
    [consCodes, consMap, quotes, names],
  )

  // 受控排序：排序状态由本页持有（跨板块保留），行数据本地排好后传入。
  const displayRows = useMemo(
    () => sortRows(stockRows, consSort),
    [stockRows, consSort],
  )

  // ── 成分股首行跟踪 ──
  // 点击/切换板块后默认选中成分股列表第一只，并**跟随**列表加载过程中的
  // 排序变化：quotes_ext 涨幅合并、缺行回填都会让首行变动，跟踪保证选中
  // 始终是当前首行。窗口只有 4s（覆盖 quotes 合并+缺行回填）：盘中行情
  // 实时轮询会持续改变首行，跟随太久会造成选中反复横跳，加载稳定即停。
  // 用户手动点选/键盘切换后立即停止；深链 ?code= 是板块成员时保留不跟随。
  const TRACK_WINDOW_MS = 4_000
  const appliedBoardRef = useRef<string | null>(null)
  const trackUntilRef = useRef(0)
  const userPickedRef = useRef<string | null>(null)
  const lastAutoSetRef = useRef<string | null>(null)
  const activeCodesRef = useRef<string[]>([])
  activeCodesRef.current = consRows ? consCodes : []
  const boardCodeRef = useRef<string | null>(boardCode)
  boardCodeRef.current = boardCode

  // 用户手动换股（本列表点击/键盘或其它页面选中）且新代码属于当前板块时
  // 视为手动选择，停止首行跟随；我们自己 setCode 的值不触发。
  useEffect(() => {
    if (code === lastAutoSetRef.current) return
    if (activeCodesRef.current.includes(code)) {
      userPickedRef.current = boardCodeRef.current
    }
  }, [code])

  useEffect(() => {
    if (!boardCode || !displayRows.length) return
    if (appliedBoardRef.current !== boardCode) {
      appliedBoardRef.current = boardCode
      trackUntilRef.current = Date.now() + TRACK_WINDOW_MS
      userPickedRef.current = null
      // 深链/刷新恢复：URL 的 code 是该板块成员则保留（不跟随首行）
      if (activeCodesRef.current.includes(code)) {
        userPickedRef.current = boardCode
        return
      }
    }
    if (userPickedRef.current === boardCode) return
    if (Date.now() > trackUntilRef.current) return
    const first = displayRows[0].code
    if (first === code) return
    lastAutoSetRef.current = first
    setCode(first)
    // displayRows 随 quotes 合并/回填持续变化，是跟踪的驱动源
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [displayRows, boardCode, code, setCode])

  return (
    <div
      className="subpage boards-page"
      style={{
        gridTemplateColumns: `${col1W}px 5px ${col2W}px 5px minmax(280px, 1fr)`,
      }}
    >
      <div className="panel board-list-cell" style={{ gridColumn: 1, gridRow: 1 }}>
        <div className="panel-title">
          94板块 · 同花顺板块（{boards.data?.length ?? 0}）
        </div>
        <StateBox
          loading={boards.loading}
          error={boards.error}
          empty={boardRows.length === 0}
        >
          <BoardTable
            rows={boardRows}
            initialSort={{ key: 'chgPct', desc: true }}
            selectedCode={boardCode ?? undefined}
            onRowClick={selectBoard}
          />
        </StateBox>
      </div>
      <div
        className="vsplit"
        style={{ gridColumn: 2, gridRow: '1 / span 2' }}
        onPointerDown={col1.onPointerDown}
      />
      <div className="panel" style={{ gridColumn: 3, gridRow: 1, position: 'relative' }}>
        <div className="panel-title">板块分时 · {boardLabel}</div>
        <div className="chart-host">
          <BoardTimelineChart
            points={timeline.data ?? []}
            prevClose={board?.pre_close}
          />
        </div>
        {timeline.loading && (
          <div className="dim" style={{ position: 'absolute', padding: 8 }}>
            加载板块分时…
          </div>
        )}
        {timeline.error && (
          <div className="down" style={{ position: 'absolute', padding: 8 }}>
            {timeline.error.slice(0, 60)}
          </div>
        )}
      </div>
      <div
        className="vsplit"
        style={{ gridColumn: 4, gridRow: '1 / span 2' }}
        onPointerDown={col2.onPointerDown}
      />
      <div className="panel" style={{ gridColumn: 5, gridRow: 1, position: 'relative' }}>
        <div className="panel-title">板块日K · {boardLabel}</div>
        <BoardKlineChart rows={kline.data ?? []} />
        {kline.loading && (
          <div className="dim" style={{ position: 'absolute', padding: 8 }}>
            加载板块日K…
          </div>
        )}
        {kline.error && (
          <div className="down" style={{ position: 'absolute', padding: 8 }}>
            {kline.error.slice(0, 60)}
          </div>
        )}
      </div>
      <div className="panel board-list-cell" style={{ gridColumn: 1, gridRow: 2 }}>
        <div className="panel-title">
          成分股 · {boardLabel}（{consCodes.length}）
        </div>
        <StateBox
          loading={constituents.loading}
          error={constituents.error}
          empty={!boardCode || stockRows.length === 0}
        >
          <StockTable
            rows={displayRows}
            onVisible={setVisibleCodes}
            sort={consSort}
            onSortChange={onConsSortChange}
          />
        </StateBox>
      </div>
      <div className="panel" style={{ gridColumn: 3, gridRow: 2 }}>
        <div className="panel-title">分时 · {stockLabel}</div>
        <div className="chart-host">
          <TimelineChart />
        </div>
      </div>
      <div className="panel" style={{ gridColumn: 5, gridRow: 2, minHeight: 0 }}>
        <KlineChart />
      </div>
    </div>
  )
}
