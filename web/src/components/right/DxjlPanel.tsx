import { memo, useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { api } from '../../api/endpoints'
import { useStock } from '../../state/StockContext'
import type { Dxjl } from '../../types'

function fmtTime(us: number) {
  const d = new Date(us / 1000)
  const hh = String(d.getHours()).padStart(2, '0')
  const mm = String(d.getMinutes()).padStart(2, '0')
  const ss = String(d.getSeconds()).padStart(2, '0')
  const now = new Date()
  const sameDay =
    d.getFullYear() === now.getFullYear() &&
    d.getMonth() === now.getMonth() &&
    d.getDate() === now.getDate()
  if (sameDay) return `${hh}:${mm}:${ss}`
  // 翻历史会跨日，非当日记录带月日前缀
  const MM = String(d.getMonth() + 1).padStart(2, '0')
  const DD = String(d.getDate()).padStart(2, '0')
  return `${MM}-${DD} ${hh}:${mm}`
}
function fmtAmt(n: number) {
  if (n >= 1e8) return (n / 1e8).toFixed(2) + '亿'
  if (n >= 1e4) return (n / 1e4).toFixed(1) + '万'
  return n.toFixed(0)
}
const keyOf = (d: Dxjl) => `${d.时间}|${d.代码}|${d.异动编码}|${d.金额}`

/** 异动方向：买入/上涨压力=up(红)，卖出/下跌压力=down(绿)。
 *  特判两对与字面相反的：打开跌停板是上涨事件(红)、打开涨停板是下跌事件(绿)；
 *  撤单与封单大减按压力减弱方向（撤买/涨停封单大减=绿，撤卖/跌停封单大减=红）。 */
function dirOf(t: string): '' | 'up' | 'down' {
  if (!t || t.startsWith('未知') || t === '区间放量平') return ''
  if (t.startsWith('打开')) return t.includes('跌停') ? 'up' : 'down'
  if (t.startsWith('撤')) return t.includes('卖') ? 'up' : 'down'
  if (t.endsWith('大减')) return t.includes('涨停') ? 'down' : 'up'
  if (t.includes('卖') || t.includes('跌') || t.includes('压')) return 'down'
  return 'up'
}

/** 表格 memo 化：快速切股时（code 每秒变化数十次）避免 500+ 行全量
 *  reconcile；selectedKey 只在当前股命中本表行时变化。 */
const DxjlTable = memo(function DxjlTable({
  rows,
  selectedKey,
  onSelect,
}: {
  rows: Dxjl[]
  selectedKey: string
  onSelect: (code: string) => void
}) {
  return (
    <table>
      <thead>
        <tr>
          <th className="left">时间</th>
          <th className="left">名称</th>
          <th className="left">异动</th>
          <th>金额</th>
          <th>涨跌</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((d) => {
          const dir = dirOf(d.异动类型)
          return (
            <tr
              key={keyOf(d)}
              className={keyOf(d) === selectedKey ? 'selected' : ''}
              onClick={() => onSelect(d.代码)}
            >
              <td className="left dim">{fmtTime(d.时间)}</td>
              <td className={`left ${dir}`} title={d.代码}>
                {d.名称 || d.代码}
              </td>
              <td className={`left ${dir}`}>{d.异动类型}</td>
              <td className={dir}>{d.金额 ? fmtAmt(d.金额) : '-'}</td>
              <td className={d.涨跌幅 > 0 ? 'up' : d.涨跌幅 < 0 ? 'down' : ''}>
                {d.涨跌幅 != null
                  ? (d.涨跌幅 >= 0 ? '+' : '') + d.涨跌幅.toFixed(2) + '%'
                  : '-'}
              </td>
            </tr>
          )
        })}
      </tbody>
    </table>
  )
})

/** 短线精灵：最新在底部（初始贴底），向上滚动用 endtime 游标自动翻历史。 */
export function DxjlPanel() {
  const { code, setCode } = useStock()
  // 升序（旧→新）：底部永远是最新一条，与聊天窗口同构
  const [rows, setRows] = useState<Dxjl[]>([])
  const rowsRef = useRef<Dxjl[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [loadingMore, setLoadingMore] = useState(false)
  const [hasMore, setHasMore] = useState(true)
  const hasMoreRef = useRef(true)
  const loadingMoreRef = useRef(false)
  const cursorRef = useRef<number | null>(null) // 已加载最早一条的时间
  const pinnedRef = useRef(false) // 初次数据就绪后贴底一次
  const scrollRef = useRef<HTMLDivElement>(null)
  // 前插历史页后补偿滚动量，保持视口停留原位
  const pendingAdjustRef = useRef<{ prevHeight: number; prevTop: number } | null>(
    null,
  )

  useEffect(() => {
    let alive = true
    api
      .dxjlLatest()
      .then((data) => {
        if (!alive) return
        const sorted = [...data].sort((a, b) => a.时间 - b.时间)
        rowsRef.current = sorted
        setRows(sorted)
        if (sorted.length) cursorRef.current = sorted[0].时间
        setError('')
      })
      .catch((e) => {
        if (alive) setError(e instanceof Error ? e.message : String(e))
      })
      .finally(() => {
        if (alive) setLoading(false)
      })
    return () => {
      alive = false
    }
  }, [])

  // 初次就绪贴底；之后每次 rows 变化做前插补偿
  useEffect(() => {
    const el = scrollRef.current
    if (!el || loading || !rows.length) return
    if (!pinnedRef.current) {
      pinnedRef.current = true
      el.scrollTop = el.scrollHeight
    }
    if (pendingAdjustRef.current) {
      const { prevHeight, prevTop } = pendingAdjustRef.current
      pendingAdjustRef.current = null
      el.scrollTop = el.scrollHeight - prevHeight + prevTop
    }
  }, [loading, rows])

  const loadMore = useCallback(() => {
    const cursor = cursorRef.current
    if (loadingMoreRef.current || !hasMoreRef.current || cursor == null) return
    loadingMoreRef.current = true
    setLoadingMore(true)
    const el = scrollRef.current
    const prevHeight = el?.scrollHeight ?? 0
    const prevTop = el?.scrollTop ?? 0
    api
      .dxjlHistory(1, cursor)
      .then((older) => {
        const olderAsc = older
          .filter((d) => d.时间 <= cursor)
          .sort((a, b) => a.时间 - b.时间)
        const seen = new Set(rowsRef.current.map(keyOf))
        const fresh = olderAsc.filter((d) => !seen.has(keyOf(d)))
        if (!fresh.length) {
          hasMoreRef.current = false
          setHasMore(false)
          return
        }
        cursorRef.current = fresh[0].时间
        pendingAdjustRef.current = { prevHeight, prevTop }
        const next = [...fresh, ...rowsRef.current]
        rowsRef.current = next
        setRows(next)
      })
      .catch(() => {
        // 单页失败不打断列表，下次滚到顶部自动重试
      })
      .finally(() => {
        loadingMoreRef.current = false
        setLoadingMore(false)
      })
  }, [])

  const onScroll = () => {
    const el = scrollRef.current
    if (el && el.scrollTop <= 48) loadMore()
  }

  // 当前股命中本表某行时才有值；切到表外股票时保持 ''，memo 跳过重渲染
  const selectedKey = useMemo(() => {
    const hit = rows.find((d) => d.代码 === code)
    return hit ? keyOf(hit) : ''
  }, [rows, code])

  let body: React.ReactNode
  if (loading) {
    body = <div className="dim" style={{ padding: 8 }}>加载短线精灵…</div>
  } else if (error) {
    body = <div className="down" style={{ padding: 8 }}>{error}</div>
  } else if (!rows.length) {
    body = <div className="dim" style={{ padding: 8 }}>无短线精灵数据</div>
  } else {
    body = <DxjlTable rows={rows} selectedKey={selectedKey} onSelect={setCode} />
  }

  return (
    <div className="dxjl-scroll" ref={scrollRef} onScroll={onScroll}>
      {loadingMore && (
        <div className="dim" style={{ padding: 4, textAlign: 'center' }}>
          加载历史…
        </div>
      )}
      {!hasMore && !loading && rows.length > 0 && (
        <div className="dim" style={{ padding: 4, textAlign: 'center' }}>
          已到最早
        </div>
      )}
      {body}
    </div>
  )
}
