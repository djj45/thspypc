import { useEffect, useRef, useState } from 'react'
import {
  createChart,
  ColorType,
  type IChartApi,
  type ISeriesApi,
  type UTCTimestamp,
} from 'lightweight-charts'
import { KLINE_PERIODS, useStock } from '../../state/StockContext'
import type { KlinePeriod } from '../../state/StockContext'
import type { Kline } from '../../types'
import { useStockNames } from '../../data/useStockNames'

const FUQUAN = [
  { v: 'Q', label: '前复权' },
  { v: 'H', label: '后复权' },
  { v: '', label: '不复权' },
]

const PERIOD_LABELS: Record<KlinePeriod, string> = {
  day: '日',
  week: '周',
  month: '月',
  quarter: '季',
  year: '年',
  '60min': '60分',
  '30min': '30分',
  '15min': '15分',
  '5min': '5分',
  '1min': '1分',
}

// 均线参数与配色：A 股软件常用六条
const MA_DEFS = [
  { n: 5, color: '#f5d568' },
  { n: 10, color: '#ff9f43' },
  { n: 20, color: '#63a3f9' },
  { n: 30, color: '#c792ea' },
  { n: 60, color: '#4adbc8' },
  { n: 120, color: '#ff7b9c' },
] as const

function smaSeries(closes: number[], n: number): (number | null)[] {
  const out: (number | null)[] = []
  let sum = 0
  for (let i = 0; i < closes.length; i++) {
    sum += closes[i]
    if (i >= n) sum -= closes[i - n]
    out.push(i >= n - 1 ? sum / n : null)
  }
  return out
}

/** 分钟K time 为 null、bar_index 是全局分钟计数（相邻差=周期分钟数）。
 *  以最新交易日 09:30 为锚、按 bar_index 差合成时间轴：日内间距精确，
 *  隔夜/午休被等比拉开（K 线顺序与形态不受影响）。 */
function minuteTimes(rows: Kline[], periodMinutes: number): UTCTimestamp[] {
  const bars = rows.map((r) => r.bar_index ?? 0)
  const first = bars[0] ?? 0
  const anchor = new Date()
  anchor.setHours(9, 30, 0, 0)
  const base = Math.floor(anchor.getTime() / 1000)
  return bars.map((bar) => (base + (bar - first) * 60) as UTCTimestamp)
}

export function KlineChart() {
  const hostRef = useRef<HTMLDivElement>(null)
  const chartRef = useRef<IChartApi | null>(null)
  const candleRef = useRef<ISeriesApi<'Candlestick'> | null>(null)
  const volRef = useRef<ISeriesApi<'Histogram'> | null>(null)
  const maRefs = useRef<(ISeriesApi<'Line'> | null)[]>([])
  const [maOn, setMaOn] = useState(true)
  const { code, period, setPeriod, fuquan, setFuquan, klineState } = useStock()
  const names = useStockNames()
  const data = klineState.data
  const error = klineState.error
  const isMinute = period.endsWith('min')
  const periodMinutes = isMinute ? Number(period.slice(0, -3)) : 0

  useEffect(() => {
    const el = hostRef.current
    if (!el) return
    const chart = createChart(el, {
      width: el.clientWidth,
      height: el.clientHeight,
      layout: {
        background: { type: ColorType.Solid, color: '#141414' },
        textColor: '#888',
        fontSize: 11,
      },
      grid: {
        vertLines: { color: '#1c1c1c' },
        horzLines: { color: '#1c1c1c' },
      },
      rightPriceScale: { borderColor: '#2a2a2a' },
      timeScale: { borderColor: '#2a2a2a', timeVisible: false },
      crosshair: { mode: 0 },
    })
    // A 股惯例：红涨绿跌
    const candle = chart.addCandlestickSeries({
      upColor: '#ff3b3b',
      downColor: '#00c853',
      borderUpColor: '#ff3b3b',
      borderDownColor: '#00c853',
      wickUpColor: '#ff3b3b',
      wickDownColor: '#00c853',
    })
    const vol = chart.addHistogramSeries({
      priceFormat: { type: 'volume' },
      priceScaleId: 'vol',
    })
    vol.priceScale().applyOptions({ scaleMargins: { top: 0.82, bottom: 0 } })
    maRefs.current = MA_DEFS.map((def) =>
      chart.addLineSeries({
        color: def.color,
        lineWidth: 1,
        priceLineVisible: false,
        lastValueVisible: false,
        crosshairMarkerVisible: false,
      }),
    )
    chartRef.current = chart
    candleRef.current = candle
    volRef.current = vol
    const ro = new ResizeObserver(() =>
      chart.applyOptions({ width: el.clientWidth, height: el.clientHeight }),
    )
    ro.observe(el)
    return () => {
      ro.disconnect()
      chart.remove()
      chartRef.current = null
      candleRef.current = null
      volRef.current = null
      maRefs.current = []
    }
  }, [])

  useEffect(() => {
    const chart = chartRef.current
    if (chart) {
      chart.applyOptions({
        timeScale: { timeVisible: isMinute, secondsVisible: false },
      })
    }
  }, [isMinute])

  useEffect(() => {
    const candle = candleRef.current
    const vol = volRef.current
    const chart = chartRef.current
    const maSeries = maRefs.current
    if (!candle || !vol || !chart) return
    if (!data) {
      candle.setData([])
      vol.setData([])
      maSeries.forEach((s) => s?.setData([]))
      return
    }
    const times = isMinute
      ? minuteTimes(data, periodMinutes)
      : data.map((k) => k.time?.slice(0, 10) ?? '')
    candle.setData(
      data.map((r, i) => ({
        time: times[i],
        open: r.open,
        high: r.high,
        low: r.low,
        close: r.close,
      })),
    )
    vol.setData(
      data.map((r, i) => ({
        time: times[i],
        value: r.volume,
        color:
          r.close >= r.open ? 'rgba(255,59,59,0.5)' : 'rgba(0,200,83,0.5)',
      })),
    )
    const closes = data.map((r) => r.close)
    MA_DEFS.forEach((def, idx) => {
      const series = maSeries[idx]
      if (!series) return
      if (!maOn) {
        series.setData([])
        return
      }
      const values = smaSeries(closes, def.n)
      const points: { time: (typeof times)[number]; value: number }[] = []
      values.forEach((v, i) => {
        if (v != null) points.push({ time: times[i], value: v })
      })
      series.setData(points)
    })
    chart.timeScale().fitContent()
  }, [data, maOn, isMinute, periodMinutes])

  // 图例显示每条均线的最新值
  const maLegend = (() => {
    if (!data || !maOn) return []
    const closes = data.map((r) => r.close)
    return MA_DEFS.map((def) => {
      const values = smaSeries(closes, def.n)
      return { ...def, value: values[values.length - 1] ?? null }
    }).filter((item) => item.value != null)
  })()

  const title = `${PERIOD_LABELS[period]}K · ${names.get(code) ?? ''} ${code}`

  return (
    <>
      <div
        className="panel-title"
        style={{ display: 'flex', flexDirection: 'column', alignItems: 'stretch', gap: 2 }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
          {title}
          <span style={{ marginLeft: 'auto', display: 'flex', gap: 4 }}>
            <span
              className={`chip ${maOn ? 'active' : ''}`}
              onClick={() => setMaOn((v) => !v)}
              title="均线 MA5/10/20/30/60/120 开关"
            >
              均线
            </span>
            {FUQUAN.map((f) => (
              <span
                key={f.v}
                className={`chip ${fuquan === f.v ? 'active' : ''}`}
                onClick={() => setFuquan(f.v)}
              >
                {f.label}
              </span>
            ))}
          </span>
        </div>
        <div style={{ display: 'flex', gap: 4, overflowX: 'auto' }}>
          {KLINE_PERIODS.map((p) => (
            <span
              key={p}
              className={`chip ${period === p ? 'active' : ''}`}
              onClick={() => setPeriod(p)}
            >
              {PERIOD_LABELS[p]}
            </span>
          ))}
        </div>
      </div>
      {maLegend.length > 0 && (
        <div
          style={{
            display: 'flex',
            gap: 10,
            padding: '2px 8px',
            fontSize: 11,
            borderBottom: '1px solid #2a2a2a',
          }}
        >
          {maLegend.map((item) => (
            <span key={item.n} style={{ color: item.color }}>
              MA{item.n}: {(item.value as number).toFixed(2)}
            </span>
          ))}
        </div>
      )}
      <div className="chart-host" style={{ position: 'relative' }}>
        <div ref={hostRef} style={{ width: '100%', height: '100%' }} />
        {error && (
          <div className="down" style={{ position: 'absolute', padding: 8 }}>
            {error}
          </div>
        )}
        {klineState.loading && !data && (
          <div className="dim" style={{ position: 'absolute', padding: 8 }}>
            加载K线…
          </div>
        )}
      </div>
    </>
  )
}
