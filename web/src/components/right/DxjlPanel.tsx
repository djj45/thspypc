import { memo, useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { api } from '../../api/endpoints'
import {
  isRecoverableRequestError,
  recoverableRetryDelay,
} from '../../api/client'
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

// 实时轮询节奏：WS 实时流断开时的回退通道（与 useData poll 默认一致）
const DXJL_POLL_MS = 5_000
// WS 实时 + 历史前插共用的行数上限（聊天窗口语义，超出裁最旧）
const DXJL_MAX_ROWS = 1_000
// 只展示这几类异动，其余推送/历史行一律不显示
const DXJL_VISIBLE_TYPES = new Set([
  '大笔买入',
  '大笔卖出',
  '打开涨停板',
  '打开跌停板',
])
const isVisibleDxjl = (d: Dxjl) => DXJL_VISIBLE_TYPES.has(d.异动类型)
// 历史页整页都被过滤掉时连续向前翻的页数上限（防止死循环）
const DXJL_PAGE_SCAN_LIMIT = 10

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
  const followRef = useRef(false) // 新行到达时是否贴底跟随
  const scrollRef = useRef<HTMLDivElement>(null)
  // 前插历史页后补偿滚动量，保持视口停留原位
  const pendingAdjustRef = useRef<{ prevHeight: number; prevTop: number } | null>(
    null,
  )
  const [wsLive, setWsLive] = useState(false)

  // 合并新行（过滤、去重、升序、限量）；贴底跟随语义与轮询路径一致
  const mergeRows = useCallback((incoming: Dxjl[]) => {
    const seen = new Set(rowsRef.current.map(keyOf))
    const fresh = incoming.filter(
      (d) => isVisibleDxjl(d) && !seen.has(keyOf(d)),
    )
    if (!fresh.length) return
    const el = scrollRef.current
    followRef.current =
      el == null || el.scrollHeight - el.scrollTop - el.clientHeight <= 48
    const next = [...rowsRef.current, ...fresh]
      .sort((a, b) => a.时间 - b.时间)
      .slice(-DXJL_MAX_ROWS)
    rowsRef.current = next
    setRows(next)
    if (next.length) cursorRef.current = next[0].时间
  }, [])

  // 实时推送通道：9601 subrealorder 服务端推送（同花顺客户端同款语义，
  // 盘中约 1500 条异动/分钟，轮询 160 条窗口在活跃时段必漏）。断线自动
  // 重连，断开期间由下方轮询 effect 兜底。
  useEffect(() => {
    let alive = true
    let socket: WebSocket | null = null
    let retryTimer = 0
    let attempt = 0
    const open = () => {
      if (!alive) return
      socket = new WebSocket(api.dxjlStreamUrl())
      socket.onopen = () => {
        attempt = 0
        setWsLive(true)
      }
      socket.onmessage = (message) => {
        if (!alive) return
        try {
          const data = JSON.parse(String(message.data))
          if (data.event === 'snapshot' && Array.isArray(data.rows)) {
            mergeRows(data.rows as Dxjl[])
            // 本地后端上 WS 握手可能快于首次轮询完成：轮询 effect 会因
            // wsLive=true 提前返回，其 finally 的 alive 守卫也随之失效，
            // loading 只能由 WS 首批数据清除，否则永远停在"加载中"。
            setLoading(false)
          } else if (data.event === 'dxjl') {
            const { event: _event, ...row } = data
            mergeRows([row as Dxjl])
            setLoading(false)
          }
        } catch {
          /* 坏帧忽略，后续帧继续 */
        }
      }
      socket.onclose = () => {
        if (!alive) return
        setWsLive(false)
        const delay = Math.min(1000 * 2 ** attempt, 10_000)
        attempt += 1
        retryTimer = window.setTimeout(open, delay)
      }
    }
    open()
    return () => {
      alive = false
      window.clearTimeout(retryTimer)
      socket?.close()
    }
  }, [mergeRows])

  // 轮询兜底：实时通道在线时休眠，断开期间按 5s 拉最新页补齐
  useEffect(() => {
    if (wsLive) return
    let alive = true
    let timer: ReturnType<typeof setTimeout> | undefined
    let failureCount = 0
    const schedule = (delay: number) => {
      timer = setTimeout(loadLatest, delay)
    }
    const loadLatest = () => {
      api
        .dxjlLatest()
        .then((data) => {
          if (!alive) return
          failureCount = 0
          const sorted = [...data].filter(isVisibleDxjl).sort(
            (a, b) => a.时间 - b.时间,
          )
          // 贴底跟随：视口在底部附近才随新行滚到底；用户翻历史时不打断
          const el = scrollRef.current
          followRef.current =
            el == null ||
            el.scrollHeight - el.scrollTop - el.clientHeight <= 48
          rowsRef.current = sorted
          setRows(sorted)
          if (sorted.length) cursorRef.current = sorted[0].时间
          setError('')
          // 以上一次完成为起点轮询，慢请求不叠加并发（与 useData poll 一致）
          schedule(DXJL_POLL_MS)
        })
        .catch((e) => {
          if (!alive) return
          setError(e instanceof Error ? e.message : String(e))
          if (isRecoverableRequestError(e)) {
            failureCount += 1
            schedule(recoverableRetryDelay(failureCount))
          } else {
            // 兜底轮询不能因一次失败永久冻结，按正常节奏重试
            schedule(DXJL_POLL_MS)
          }
        })
        .finally(() => {
          if (alive) setLoading(false)
        })
    }
    loadLatest()
    return () => {
      alive = false
      if (timer !== undefined) clearTimeout(timer)
    }
  }, [wsLive])

  // 初次就绪贴底；轮询新行仅在贴底跟随时滚底；前插历史页做滚动量补偿
  useEffect(() => {
    const el = scrollRef.current
    if (!el || loading || !rows.length) return
    if (!pinnedRef.current) {
      pinnedRef.current = true
      el.scrollTop = el.scrollHeight
      return
    }
    if (pendingAdjustRef.current) {
      const { prevHeight, prevTop } = pendingAdjustRef.current
      pendingAdjustRef.current = null
      el.scrollTop = el.scrollHeight - prevHeight + prevTop
      return
    }
    if (followRef.current) {
      followRef.current = false
      el.scrollTop = el.scrollHeight
    }
  }, [loading, rows])

  const loadMore = useCallback(() => {
    const initialCursor = cursorRef.current
    if (
      loadingMoreRef.current ||
      !hasMoreRef.current ||
      initialCursor == null
    )
      return
    loadingMoreRef.current = true
    setLoadingMore(true)
    const el = scrollRef.current
    const prevHeight = el?.scrollHeight ?? 0
    const prevTop = el?.scrollTop ?? 0
    const run = async () => {
      let cursor = initialCursor
      // 一页历史可能整页都是被过滤掉的异动类型：连续向前翻，直到拿到
      // 至少一条可见新行、页面为空（到头）或翻页上限。
      for (let page = 0; page < DXJL_PAGE_SCAN_LIMIT; page++) {
        const older = await api.dxjlHistory(1, cursor)
        const pageRows = older
          .filter((d) => d.时间 <= cursor)
          .sort((a, b) => a.时间 - b.时间)
        if (!pageRows.length) {
          hasMoreRef.current = false
          setHasMore(false)
          return
        }
        cursor = pageRows[0].时间
        const seen = new Set(rowsRef.current.map(keyOf))
        const fresh = pageRows.filter(
          (d) => isVisibleDxjl(d) && !seen.has(keyOf(d)),
        )
        if (!fresh.length) continue
        cursorRef.current = fresh[0].时间
        pendingAdjustRef.current = { prevHeight, prevTop }
        const next = [...fresh, ...rowsRef.current]
        rowsRef.current = next
        setRows(next)
        return
      }
      // 限额内没等到可见行：前移游标，下次滚动到顶继续翻
      cursorRef.current = cursor
    }
    run()
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
