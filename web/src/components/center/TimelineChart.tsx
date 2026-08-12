import { useEffect, useRef, useState } from 'react'
import * as echarts from 'echarts'
import type { ECharts } from 'echarts'
import { api } from '../../api/endpoints'
import { useData } from '../../data/useData'
import { useStock } from '../../state/StockContext'
import type { AuctionPoint, TimelinePoint } from '../../types'

// auction（早盘竞价）盘后要 ~12s（client 等实时竞价超时），当日数据固定，
// 用「代码+日期」缓存避免切回重复等待。
const auctionCache = new Map<string, AuctionPoint[]>()
function todayStr() {
  return new Date().toISOString().slice(0, 10)
}

// 真实时刻 → 交易分钟 x（午休压缩）：
//   早盘竞价 9:15-9:25 → -15..-5；上午 9:30-11:29 → 0..119；
//   午休压缩；下午 13:00-14:56 → 120..236；尾盘竞价 14:57-15:00 → 237..240
function timeToX(iso?: string): number | null {
  if (!iso) return null
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return null
  const mins = d.getHours() * 60 + d.getMinutes() + d.getSeconds() / 60
  if (mins < 570) return mins - 570
  if (mins <= 690) return mins - 570
  if (mins < 780) return 120
  return mins - 660
}
function xToLabel(v: number): string {
  const mins = v < 120 ? 570 + v : 660 + v
  return `${String(Math.floor(mins / 60)).padStart(2, '0')}:${String(
    Math.floor(mins % 60),
  ).padStart(2, '0')}`
}

export function TimelineChart() {
  const hostRef = useRef<HTMLDivElement>(null)
  const chartRef = useRef<ECharts | null>(null)
  const { code } = useStock()

  // 盘中 + 尾盘竞价：都快（<0.13s），立即拉
  const continuous = useData<TimelinePoint[]>(() => api.timeline(code), [code])
  const closing = useData<AuctionPoint[]>(
    () => api.closingAuction(code),
    [code],
  )

  // 早盘竞价：慢（~12s），延后到盘中就绪后再后台拉，且当日缓存。
  // 这样切换股票时盘中分时立即显示，竞价段异步补，不阻塞。
  const [opening, setOpening] = useState<AuctionPoint[]>([])
  useEffect(() => {
    if (!continuous.data) return // 等盘中先就绪
    let alive = true
    const key = `${code}@${todayStr()}`
    const cached = auctionCache.get(key)
    if (cached) {
      setOpening(cached)
      return
    }
    setOpening([])
    api
      .auction(code)
      .then((d) => {
        if (!alive) return
        auctionCache.set(key, d)
        setOpening(d)
      })
      .catch(() => {})
    return () => {
      alive = false
    }
  }, [continuous.data, code])

  useEffect(() => {
    const el = hostRef.current
    if (!el) return
    const chart = echarts.init(el, undefined, { renderer: 'canvas' })
    chartRef.current = chart
    const ro = new ResizeObserver(() => chart.resize())
    ro.observe(el)
    return () => {
      ro.disconnect()
      chart.dispose()
      chartRef.current = null
    }
  }, [])

  useEffect(() => {
    const chart = chartRef.current
    if (!chart) return
    const cont = continuous.data ?? []
    const contData: [number, number][] = []
    const avgData: [number, number][] = []
    cont.forEach((p, i) => {
      if (p.dt10 != null) contData.push([i, p.dt10])
      if (p.lead_price != null) avgData.push([i, p.lead_price])
    })
    const openData: [number, number][] = []
    opening.forEach((p) => {
      const x = timeToX(p.time)
      if (x != null && p.dt10 != null) openData.push([x, p.dt10])
    })
    const closeData: [number, number][] = []
    ;(closing.data ?? []).forEach((p) => {
      const x = timeToX(p.time)
      if (x != null && p.dt10 != null) closeData.push([x, p.dt10])
    })

    chart.setOption({
      backgroundColor: '#141414',
      animation: false,
      grid: { left: 54, right: 10, top: 10, bottom: 26 },
      xAxis: {
        type: 'value',
        min: -17,
        max: 243,
        axisLabel: {
          color: '#888',
          fontSize: 10,
          formatter: (v: number) => xToLabel(v),
          hideOverlap: true,
        },
        axisLine: { lineStyle: { color: '#2a2a2a' } },
        splitLine: { show: true, lineStyle: { color: '#1c1c1c' } },
      },
      yAxis: {
        scale: true,
        axisLabel: { color: '#888', fontSize: 10 },
        axisLine: { lineStyle: { color: '#2a2a2a' } },
        splitLine: { lineStyle: { color: '#1c1c1c' } },
      },
      series: [
        {
          name: '盘中',
          type: 'line',
          data: contData,
          showSymbol: false,
          lineStyle: { color: '#2a9df4', width: 1 },
          areaStyle: { color: 'rgba(42,157,244,0.15)' },
        },
        {
          name: '均价',
          type: 'line',
          data: avgData,
          showSymbol: false,
          lineStyle: { color: '#e8c36a', width: 1 },
        },
        {
          name: '早盘竞价',
          type: 'line',
          data: openData,
          showSymbol: false,
          lineStyle: { color: '#e8a13a', width: 1 },
        },
        {
          name: '尾盘竞价',
          type: 'line',
          data: closeData,
          showSymbol: false,
          lineStyle: { color: '#e8a13a', width: 1 },
        },
      ],
    })
  }, [continuous.data, closing.data, opening])

  return (
    <>
      <div ref={hostRef} style={{ width: '100%', height: '100%' }} />
      {continuous.loading && (
        <div className="dim" style={{ position: 'absolute', padding: 8 }}>
          加载盘中…
        </div>
      )}
      {continuous.error && (
        <div className="down" style={{ position: 'absolute', padding: 8 }}>
          {continuous.error}
        </div>
      )}
    </>
  )
}
