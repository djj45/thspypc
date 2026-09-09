import {
  useEffect,
  useLayoutEffect,
  useRef,
  useState,
  type PointerEvent as RPointerEvent,
  type ReactNode,
} from 'react'
import { api } from '../../api/endpoints'
import { IDLE_POLL_MS, useMarketPhase } from '../../data/marketSession'
import type { QuoteExt } from '../../types'
import { useStock } from '../../state/StockContext'
import { clsOf, fmtAmt, fmtPct } from './format'

export function Cell({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div className="cell">
      <div className="cell-title">{title}</div>
      <div className="cell-body">{children}</div>
    </div>
  )
}

export function StateBox({
  loading,
  error,
  empty,
  children,
}: {
  loading: boolean
  error: string
  empty: boolean
  children: ReactNode
}) {
  if (loading) return <div className="dim" style={{ padding: 8 }}>加载中…</div>
  if (error) return <div className="down" style={{ padding: 8 }}>{error.slice(0, 60)}</div>
  if (empty) return <div className="dim" style={{ padding: 8 }}>暂无数据</div>
  return <>{children}</>
}

export interface StockRowData {
  code: string
  name?: string
  // 统一列（/api/quotes_ext 派生 + 面板自有排序值补主力/封单）
  chgPct?: number
  auctionChgPct?: number
  auctionAmount?: number
  amount?: number
  speed4m?: number
  mainInflow?: number
  sealAmount?: number
}

// 批量统一字段：滚动的可视窗口代码传进来，返回 code→QuoteExt 映射。
// 防抖吸收快速滚动的窗口抖动；新结果合并进旧 map（回滚时已看过的行
// 立即显示缓存值，不闪 "-"）。窗口静止后盘中每 4 秒受控刷新一次（休市
// 降为 10 分钟心跳）；以上一轮完成为起点调度，不会叠加并发请求。空列表
// 不发。后端单批偶发缺行（冷启动争抢）时自动补拉缺失代码（最多 3 轮），
// 保证初始可见区一定有数据。
export function useQuoteExt(
  codes: string[],
  debounceMs = 200,
): Map<string, QuoteExt> {
  const [map, setMap] = useState<Map<string, QuoteExt>>(new Map())
  const key = codes.join(',')
  const phase = useMarketPhase()
  useEffect(() => {
    if (!key) return
    let alive = true
    let timer = 0
    const run = async (): Promise<void> => {
      let pending = key.split(',')
      for (let attempt = 0; attempt < 3 && alive && pending.length; attempt++) {
        try {
          const rows = await api.quotesExt(pending)
          if (!alive) return
          const got = new Set(rows.map((r) => r.code))
          setMap((prev) => {
            const merged = new Map(prev)
            for (const r of rows) merged.set(r.code, r)
            return merged
          })
          pending = pending.filter((c) => !got.has(c))
          if (!pending.length) break
        } catch {
          /* 整批失败：本轮内重试 */
        }
        if (pending.length) {
          await new Promise((resolve) => setTimeout(resolve, 500))
        }
      }
      if (!alive) return
      // 成功拿齐 → 按时段节奏（盘中 4s / 休市 10 分钟心跳）；
      // 失败或缺行 → 30 秒恢复重试：后端冷启动/换挡期掉一批不能让
      // 盘后页面空白到下一次心跳（此前要等 10 分钟或手动刷新）
      const complete = pending.length === 0
      const delay = complete
        ? phase === 'live'
          ? 4_000
          : IDLE_POLL_MS
        : 30_000
      timer = window.setTimeout(run, delay)
    }
    timer = window.setTimeout(run, debounceMs)
    return () => {
      alive = false
      window.clearTimeout(timer)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key, debounceMs, phase])
  return map
}

// ── 表头排序状态 ──

export interface ColSort {
  key: string
  desc: boolean
}

export function sortRows<T>(rows: T[], sort: ColSort | null): T[] {
  if (!sort) return rows
  const key = sort.key as keyof T & string
  const out = [...rows]
  out.sort((a, b) => {
    // 空值恒排末尾（与排序方向无关）
    const va = a[key]
    const vb = b[key]
    if (va == null && vb == null) return 0
    if (va == null) return 1
    if (vb == null) return -1
    const c = compareValues(va, vb)
    return sort.desc ? -c : c
  })
  return out
}

function compareValues(va: unknown, vb: unknown): number {
  if (typeof va === 'number' && typeof vb === 'number') return va - vb
  return String(va).localeCompare(String(vb))
}

// ── 列宽拖拽（localStorage 持久化，模板尾部 1fr 弹性列吸收余量）──

const COL_WIDTH_MIN = 30

function useColumnWidths(storageKey: string, defaults: number[]) {
  const [widths, setWidths] = useState<number[]>(() => {
    try {
      const saved = localStorage.getItem(storageKey)
      if (saved) {
        const arr: unknown = JSON.parse(saved)
        if (
          Array.isArray(arr) &&
          arr.length === defaults.length &&
          arr.every((n) => typeof n === 'number' && n >= COL_WIDTH_MIN)
        ) {
          return arr as number[]
        }
      }
    } catch {
      /* 损坏的缓存忽略 */
    }
    return defaults
  })
  const widthsRef = useRef(widths)
  widthsRef.current = widths

  const startResize = (index: number) => (e: RPointerEvent) => {
    e.preventDefault()
    e.stopPropagation()
    const startX = e.clientX
    const startW = widthsRef.current[index]
    document.body.style.userSelect = 'none'
    // 同步追踪最新宽度：pointerup 时 React 状态可能尚未渲染回 ref
    let latest = widthsRef.current
    const move = (ev: PointerEvent) => {
      const w = Math.max(COL_WIDTH_MIN, Math.round(startW + ev.clientX - startX))
      latest = widthsRef.current.map((v, i) => (i === index ? w : v))
      setWidths(latest)
    }
    const up = () => {
      window.removeEventListener('pointermove', move)
      window.removeEventListener('pointerup', up)
      document.body.style.userSelect = ''
      try {
        localStorage.setItem(storageKey, JSON.stringify(latest))
      } catch {
        /* 存储失败忽略 */
      }
    }
    window.addEventListener('pointermove', move)
    window.addEventListener('pointerup', up)
  }

  return { widths, startResize }
}

// 面板变窄时自动隐藏放不下的列（右侧尾列先隐藏，前 keep 列恒显），
// 与同花顺一致：窄列表少显示几列，而不是出横向滚动。
const COL_GAP = 4
const COL_PAD = 14

function useVisibleColumns(
  containerRef: { current: HTMLDivElement | null },
  count: number,
  widths: number[],
  keep = 2,
) {
  const [boxW, setBoxW] = useState(0)
  useEffect(() => {
    const el = containerRef.current
    if (!el) return
    const ro = new ResizeObserver((entries) => {
      for (const e of entries) setBoxW(Math.round(e.contentRect.width))
    })
    ro.observe(el)
    return () => ro.disconnect()
  }, [containerRef])
  const avail = boxW > 0 ? boxW - COL_PAD : Number.POSITIVE_INFINITY
  const vis: number[] = []
  let used = 0
  for (let i = 0; i < count; i++) {
    used += widths[i] + COL_GAP
    if (vis.length >= keep && used > avail) break
    vis.push(i)
  }
  const template = `${vis.map((i) => `${widths[i]}px`).join(' ')} 1fr`
  return { vis, template }
}

// 面板分隔条：拖动改宽度并持久化（同花顺式子窗口边界调整）。
// min/max 在拖动时钳制；读取时若超界（如另一侧宽度后来变了）由调用方再夹一次。
export function usePersistedWidth(
  storageKey: string,
  initial: number,
  min = 100,
  max = 4000,
) {
  const [w, setW] = useState(() => {
    const saved = Number(localStorage.getItem(storageKey))
    return Number.isFinite(saved) && saved >= min ? saved : initial
  })
  const ref = useRef(w)
  ref.current = w
  const onPointerDown = (e: RPointerEvent) => {
    e.preventDefault()
    const startX = e.clientX
    const startW = ref.current
    document.body.style.userSelect = 'none'
    let latest = startW
    const move = (ev: PointerEvent) => {
      latest = Math.round(
        Math.min(max, Math.max(min, startW + ev.clientX - startX)),
      )
      setW(latest)
    }
    const up = () => {
      window.removeEventListener('pointermove', move)
      window.removeEventListener('pointerup', up)
      document.body.style.userSelect = ''
      try {
        localStorage.setItem(storageKey, String(latest))
      } catch {
        /* 存储失败忽略 */
      }
    }
    window.addEventListener('pointermove', move)
    window.addEventListener('pointerup', up)
  }
  return { w, onPointerDown }
}

// 表头单元格：可点击排序（▼/▲ 指示）+ 右缘拖拽调宽
function HeadCell({
  label,
  sortKey,
  sort,
  onSort,
  onResize,
}: {
  label: string
  sortKey?: string
  sort: ColSort | null
  onSort: (key: string) => void
  onResize?: (e: RPointerEvent) => void
}) {
  const active = !!sortKey && sort?.key === sortKey
  const cls = active
    ? 'hcell sorted'
    : sortKey
      ? 'hcell sortable'
      : 'hcell'
  return (
    <span
      className={cls}
      onClick={sortKey ? () => onSort(sortKey) : undefined}
    >
      {label}
      {active && <i className="sort-mark">{sort!.desc ? '▼' : '▲'}</i>}
      {onResize && <i className="col-grip" onPointerDown={onResize} />}
    </span>
  )
}

// ── 虚拟滚动股票列表（表头点击排序 + 列宽拖拽）──

const OVERSCAN = 8
const FALLBACK_ROW_H = 21

const STOCK_COLS: { label: string; sortKey?: string }[] = [
  { label: '代码', sortKey: 'code' },
  { label: '名称' },
  { label: '涨幅', sortKey: 'chgPct' },
  { label: '竞价涨幅', sortKey: 'auctionChgPct' },
  { label: '竞价金额', sortKey: 'auctionAmount' },
  { label: '成交额', sortKey: 'amount' },
  { label: '涨速', sortKey: 'speed4m' },
  { label: '主力净额', sortKey: 'mainInflow' },
  { label: '封单额', sortKey: 'sealAmount' },
]

const STOCK_COL_WIDTHS = [44, 76, 54, 54, 50, 50, 50, 54, 50]

export function StockTable({
  rows,
  onVisible,
  sort,
  onSortChange,
  disabledSortKeys = [],
  initialSort = null,
}: {
  rows: StockRowData[]
  onVisible?: (codes: string[]) => void
  /** 受控排序（提供 onSortChange 时由父级负责排序数据，如全市场服务端排序） */
  sort?: ColSort | null
  onSortChange?: (s: ColSort) => void
  /** 该列表无服务端排序键、本地排序又会误导的列（如全市场·成交额） */
  disabledSortKeys?: string[]
  initialSort?: ColSort | null
}) {
  const { code, setCode } = useStock()
  const listRef = useRef<HTMLDivElement>(null)
  const measureRef = useRef<HTMLDivElement | null>(null)
  const [rowH, setRowH] = useState(0)
  const [range, setRange] = useState({ start: 0, end: 40 })
  const [localSort, setLocalSort] = useState<ColSort | null>(initialSort)
  const { widths, startResize } = useColumnWidths(
    'ths.cols.stock',
    STOCK_COL_WIDTHS,
  )
  const { vis, template } = useVisibleColumns(
    listRef,
    STOCK_COLS.length,
    widths,
  )

  const controlled = onSortChange !== undefined
  const effectiveSort = controlled ? (sort ?? null) : localSort
  const display = controlled ? rows : sortRows(rows, effectiveSort)
  // 点击行时注册为键盘/滚轮切换的顺序源；用 ref 保证之后改排序也跟随最新顺序
  const displayRef = useRef(display)
  displayRef.current = display

  const onSort = (key: string) => {
    const cur = effectiveSort
    const next =
      cur && cur.key === key ? { key, desc: !cur.desc } : { key, desc: true }
    if (controlled) onSortChange(next)
    else setLocalSort(next)
  }

  useLayoutEffect(() => {
    if (measureRef.current) {
      const h = measureRef.current.getBoundingClientRect().height
      if (h >= 12) setRowH(h)
    }
  }, [])

  const h = rowH || FALLBACK_ROW_H

  // 虚拟列表只渲染当前滚动窗口。键盘/图表滚轮切股时，除了更新 code，
  // 还必须先把目标索引滚进窗口，随后 onScroll 才会渲染并高亮对应行。
  const revealCode = (nextCode: string) => {
    const el = listRef.current
    if (!el) return
    const index = displayRef.current.findIndex((row) => row.code === nextCode)
    if (index < 0) return

    const headerH =
      el.querySelector<HTMLElement>(':scope > .row-head')?.offsetHeight ?? 0
    // 内容层紧跟表头；不能使用它的 offsetTop，因为 offsetParent 可能是
    // 左栏外层网格，得到的是页面坐标而不是 vlist 内部的滚动坐标。
    const rowTop = headerH + index * h
    const rowBottom = rowTop + h
    const visibleTop = el.scrollTop + headerH
    const visibleBottom = el.scrollTop + el.clientHeight

    if (rowTop < visibleTop) {
      el.scrollTop = Math.max(0, rowTop - headerH)
    } else if (rowBottom > visibleBottom) {
      el.scrollTop = rowBottom - el.clientHeight
    }
  }

  const updateRange = () => {
    const el = listRef.current
    if (!el) return
    const first = Math.max(0, Math.floor(el.scrollTop / h) - OVERSCAN)
    const last = Math.min(
      display.length,
      first + Math.ceil(el.clientHeight / h) + OVERSCAN * 2,
    )
    setRange((prev) =>
      prev.start === first && prev.end === last ? prev : { start: first, end: last },
    )
  }

  useEffect(() => {
    updateRange()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [rowH, display.length])

  const lastReported = useRef('')
  useEffect(() => {
    if (!onVisible) return
    const codes = display.slice(range.start, range.end).map((r) => r.code)
    const key = codes.join(',')
    if (key === lastReported.current) return
    lastReported.current = key
    onVisible(codes)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [range, display, onVisible])

  const slice = display.slice(range.start, range.end)

  const cellOf = (row: StockRowData, i: number) => {
    switch (i) {
      case 0:
        return <span key={i} className="sc">{row.code}</span>
      case 1:
        return (
          <span key={i} className="sn" title={row.name ?? ''}>
            {row.name ?? ''}
          </span>
        )
      case 2:
        return <span key={i} className={clsOf(row.chgPct)}>{fmtPct(row.chgPct)}</span>
      case 3:
        return <span key={i} className={clsOf(row.auctionChgPct)}>{fmtPct(row.auctionChgPct)}</span>
      case 4:
        return <span key={i} className={clsOf(row.auctionAmount)}>{fmtAmt(row.auctionAmount)}</span>
      case 5:
        return <span key={i} className="flat">{fmtAmt(row.amount)}</span>
      case 6:
        return <span key={i} className={clsOf(row.speed4m)}>{fmtPct(row.speed4m)}</span>
      case 7:
        return <span key={i} className={clsOf(row.mainInflow)}>{fmtAmt(row.mainInflow)}</span>
      default:
        return <span key={i} className={clsOf(row.sealAmount)}>{fmtAmt(row.sealAmount)}</span>
    }
  }

  return (
    <div
      className="vlist"
      ref={listRef}
      onScroll={updateRange}
      style={{ '--cols': template } as React.CSSProperties}
    >
      <div className="row-head cols-stock">
        {STOCK_COLS.map((col, i) =>
          vis.includes(i) ? (
            <HeadCell
              key={col.label}
              label={col.label}
              sortKey={
                col.sortKey && !disabledSortKeys.includes(col.sortKey)
                  ? col.sortKey
                  : undefined
              }
              sort={effectiveSort}
              onSort={onSort}
              onResize={startResize(i)}
            />
          ) : null,
        )}
      </div>
      <div style={{ position: 'relative', height: display.length * h }}>
        {slice.map((row, i) => (
          <div
            key={row.code}
            ref={i === 0 && rowH === 0 ? measureRef : undefined}
            className={row.code === code ? 'stock-row selected' : 'stock-row'}
            style={{
              position: 'absolute',
              top: (range.start + i) * h,
              left: 0,
              right: 0,
            }}
            onClick={() =>
              setCode(row.code, {
                getCodes: () => displayRef.current.map((r) => r.code),
                revealCode,
              })
            }
          >
            {vis.map((ci) => cellOf(row, ci))}
          </div>
        ))}
      </div>
    </div>
  )
}

// ── 板块列表（同样支持表头排序 + 列宽拖拽）──

export interface BoardRowData {
  code: string
  name: string
  chgPct?: number
  speed1m?: number
  speed4m?: number
  mainInflow?: number
  upCount?: number
  downCount?: number
  limitUp?: number
}

const BOARD_COLS: { label: string; sortKey?: string }[] = [
  { label: '板块' },
  { label: '涨幅', sortKey: 'chgPct' },
  { label: '1分', sortKey: 'speed1m' },
  { label: '4分', sortKey: 'speed4m' },
  { label: '主力', sortKey: 'mainInflow' },
  { label: '涨家', sortKey: 'upCount' },
  { label: '跌家', sortKey: 'downCount' },
  { label: '涨停', sortKey: 'limitUp' },
]

const BOARD_COL_WIDTHS = [90, 46, 40, 40, 50, 34, 34, 34]

export function BoardTable({
  rows,
  initialSort = null,
  selectedCode,
  onRowClick,
}: {
  rows: BoardRowData[]
  initialSort?: ColSort | null
  /** 选中板块代码（94板块页联动板块分时/日K） */
  selectedCode?: string
  onRowClick?: (code: string) => void
}) {
  const [sort, setSort] = useState<ColSort | null>(initialSort)
  const listRef = useRef<HTMLDivElement>(null)
  const { widths, startResize } = useColumnWidths(
    'ths.cols.board',
    BOARD_COL_WIDTHS,
  )
  const { vis, template } = useVisibleColumns(
    listRef,
    BOARD_COLS.length,
    widths,
  )
  const display = sortRows(rows, sort)
  const onSort = (key: string) => {
    setSort((cur) =>
      cur && cur.key === key ? { key, desc: !cur.desc } : { key, desc: true },
    )
  }
  const cellOf = (b: BoardRowData, i: number) => {
    switch (i) {
      case 0:
        return (
          <span key={i} className="bn" title={`${b.code} ${b.name}`}>
            {b.name}
          </span>
        )
      case 1:
        return <span key={i} className={clsOf(b.chgPct)}>{fmtPct(b.chgPct)}</span>
      case 2:
        return <span key={i} className={clsOf(b.speed1m)}>{fmtPct(b.speed1m)}</span>
      case 3:
        return <span key={i} className={clsOf(b.speed4m)}>{fmtPct(b.speed4m)}</span>
      case 4:
        return <span key={i} className={clsOf(b.mainInflow)}>{fmtAmt(b.mainInflow)}</span>
      case 5:
        return <span key={i} className="up">{b.upCount != null ? String(Math.round(b.upCount)) : '-'}</span>
      case 6:
        return <span key={i} className="down">{b.downCount != null ? String(Math.round(b.downCount)) : '-'}</span>
      default:
        return <span key={i} className="up">{b.limitUp != null ? String(Math.round(b.limitUp)) : '-'}</span>
    }
  }
  return (
    <div
      className="vlist"
      ref={listRef}
      style={{ '--cols': template } as React.CSSProperties}
    >
      <div className="row-head cols-board">
        {BOARD_COLS.map((col, i) =>
          vis.includes(i) ? (
            <HeadCell
              key={col.label}
              label={col.label}
              sortKey={col.sortKey}
              sort={sort}
              onSort={onSort}
              onResize={startResize(i)}
            />
          ) : null,
        )}
      </div>
      <div className="stock-list">
        {display.map((b) => (
          <div
            key={b.code}
            className={b.code === selectedCode ? 'board-row selected' : 'board-row'}
            onClick={onRowClick ? () => onRowClick(b.code) : undefined}
          >
            {vis.map((ci) => cellOf(b, ci))}
          </div>
        ))}
      </div>
    </div>
  )
}
