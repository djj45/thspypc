import { useEffect, useRef } from 'react'
import * as echarts from 'echarts'
import type { ECharts } from 'echarts'
import { useStock } from '../../state/StockContext'
import type { TimelinePoint } from '../../types'

type IntradayPoint = TimelinePoint & { phase?: string; time?: string }

// 真实时刻 -> 交易分钟 x（午休压缩）。
// 早盘竞价 9:15-9:25 拉伸到 -15..-1（贴着 9:30 开盘段，跳过 9:25-9:30
// 撮合空档，与同花顺一致）；盘中 9:30-11:29 -> 0..119；
// 下午 13:00-14:56 -> 120..236；尾盘竞价 14:57-15:00 -> 237..240。
function timeToX(iso?: string): number | null {
  if (!iso) return null
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return null
  const mins = d.getHours() * 60 + d.getMinutes() + d.getSeconds() / 60
  if (mins < 570) {
    const t = Math.min(Math.max((mins - 555) / 10, 0), 1)
    return -15 + t * 14
  }
  if (mins <= 690) return mins - 570
  if (mins < 780) return 120
  return Math.min(mins - 660, 240)
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
  const { marketView } = useStock()
  const intraday = {
    ...marketView,
    data: (marketView.data?.intraday ?? null) as IntradayPoint[] | null,
  }

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

    const points = intraday.data ?? []
    const continuous = points.filter((p) => p.phase === 'continuous')
    const opening = points.filter((p) => p.phase === 'opening_auction')
    const closing = points.filter((p) => p.phase === 'closing_auction')

    const contData: [number, number][] = []
    const avgData: [number, number][] = []
    continuous.forEach((p, i) => {
      if (p.dt10 != null) contData.push([i, p.dt10])
      if (p.lead_price != null) avgData.push([i, p.lead_price])
    })
    const openData: [number, number][] = []
    opening.forEach((p) => {
      const x = timeToX(p.time)
      if (x != null && p.dt10 != null) openData.push([x, p.dt10])
    })
    const closeData: [number, number][] = []
    closing.forEach((p) => {
      const x = timeToX(p.time)
      if (x != null && p.dt10 != null) closeData.push([x, p.dt10])
    })

    chart.setOption({
      backgroundColor: '#141414',
      animation: false,
      grid: { left: 54, right: 10, top: 10, bottom: 26 },
      xAxis: {
        type: 'value',
        // 数据范围即轴范围（-15=9:15 竞价首点，240=15:00），并固定刻度
        // 间隔：显式 min/max 下 ECharts 会按 (max-min)/splitNumber 均分，
        // 把 -17/243 之类的边界也打成标签（曾显示 09:13/15:03）。
        min: -15,
        max: 240,
        interval: 60,
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
  }, [intraday.data])

  return (
    <>
      <div ref={hostRef} style={{ width: '100%', height: '100%' }} />
      {intraday.loading && (
        <div className="dim" style={{ position: 'absolute', padding: 8 }}>
          加载分时…
        </div>
      )}
      {intraday.error && (
        <div className="down" style={{ position: 'absolute', padding: 8 }}>
          {intraday.error}
        </div>
      )}
    </>
  )
}
