import { useEffect, useMemo, useRef, useState } from 'react'
import {
  createChart,
  ColorType,
  type IChartApi,
  type ISeriesApi,
  type Time,
} from 'lightweight-charts'
import {
  KLINE_MA_WARMUP,
  KLINE_VIEW_COUNT,
} from '../../state/StockContext'
import type { Kline } from '../../types'

// 板块指数日K（/api/board/{code}/kline，16384 → 0x42 日K 表）：
// 蜡烛 + 量柱 + MA5/10/20/60。与个股 KlineChart 的差异：无周期/复权切换
// （固定日K前复权）。均线预热（多拉 MA_WARMUP 根、展示裁回可视数量）与
// 范围记忆（按周期记忆缩放/平移，独立于个股日K 的存储键）与个股一致。

const MA_DEFS = [
  { n: 5, color: '#f5d568' },
  { n: 10, color: '#ff9f43' },
  { n: 20, color: '#63a3f9' },
  { n: 60, color: '#4adbc8' },
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

// 可视范围记忆：锚定右端（right=最后一根 bar 距可视右缘的偏移）+ 可见
// bar 数。端锚不随新 bar 追加漂移，跨板块/跨日稳定。与个股日K 的
// ths.kline.range.* 分开存，避免互相覆盖。
const RANGE_MEMORY_KEY = 'ths.kline.boardRangeMemory'
const rangeKeyOf = (period: string) => `ths.kline.boardRange.${period}`

interface SavedRange {
  right: number
  bars: number
}

function loadSavedRange(period: string): SavedRange | null {
  try {
    const raw = localStorage.getItem(rangeKeyOf(period))
    if (!raw) return null
    const parsed = JSON.parse(raw) as SavedRange
    if (
      parsed &&
      typeof parsed.right === 'number' &&
      Number.isFinite(parsed.right) &&
      typeof parsed.bars === 'number' &&
      parsed.bars > 0
    ) {
      return parsed
    }
  } catch {
    /* 损坏的缓存忽略 */
  }
  return null
}

export function BoardKlineChart({ rows }: { rows: Kline[] }) {
  const hostRef = useRef<HTMLDivElement>(null)
  const chartRef = useRef<IChartApi | null>(null)
  const candleRef = useRef<ISeriesApi<'Candlestick'> | null>(null)
  const volRef = useRef<ISeriesApi<'Histogram'> | null>(null)
  const maRefs = useRef<(ISeriesApi<'Line'> | null)[]>([])
  const lastDataRef = useRef<unknown>(null)
  const periodRef = useRef('day')
  const viewLenRef = useRef(0)
  const [rangeMemory, setRangeMemory] = useState(
    () => localStorage.getItem(RANGE_MEMORY_KEY) !== '0',
  )
  const rangeMemoryRef = useRef(rangeMemory)
  rangeMemoryRef.current = rangeMemory

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
    // 范围记忆：可视范围变化时节流落盘（按周期）。程序性的 fit/恢复也会
    // 触发订阅，写回同值无副作用。
    let rangeSaveTimer = 0
    chart.timeScale().subscribeVisibleLogicalRangeChange((range) => {
      if (!rangeMemoryRef.current || range == null) return
      const viewLen = viewLenRef.current
      if (!viewLen) return
      const payload = JSON.stringify({
        right: viewLen - range.to,
        bars: range.to - range.from,
      })
      window.clearTimeout(rangeSaveTimer)
      rangeSaveTimer = window.setTimeout(() => {
        try {
          const p = periodRef.current
          if (p) localStorage.setItem(rangeKeyOf(p), payload)
        } catch {
          /* 存储失败忽略 */
        }
      }, 300)
    })
    const ro = new ResizeObserver(() => {
      chart.applyOptions({ width: el.clientWidth, height: el.clientHeight })
    })
    ro.observe(el)
    return () => {
      window.clearTimeout(rangeSaveTimer)
      ro.disconnect()
      chart.remove()
      chartRef.current = null
      candleRef.current = null
      volRef.current = null
      maRefs.current = []
    }
  }, [])

  useEffect(() => {
    const candle = candleRef.current
    const vol = volRef.current
    const chart = chartRef.current
    const maSeries = maRefs.current
    if (!candle || !vol || !chart) return
    if (!rows.length) {
      candle.setData([])
      vol.setData([])
      maSeries.forEach((s) => s?.setData([]))
      lastDataRef.current = null
      return
    }
    // 数据变化（切板块）才重新铺满/恢复视野。useData 每 60s 轮询会产生新
    // 数组引用，不能按引用判断；用 板块+首根日期+根数 作为数据身份，同一
    // 板块的轮询刷新保持用户当前缩放/滚动位置。
    const dataKey = rows.length
      ? `${rows[0].code ?? ''}|${rows[0].time ?? ''}|${rows.length}`
      : ''
    const shouldFit = lastDataRef.current !== dataKey
    lastDataRef.current = dataKey
    // 实际拉了 VIEW+WARMUP 根：均线在可视区左侧也完整；展示裁回可视数量
    const view =
      rows.length > KLINE_VIEW_COUNT ? rows.slice(-KLINE_VIEW_COUNT) : rows
    const offset = rows.length - view.length
    viewLenRef.current = view.length
    const times = view.map((k) => (k.time?.slice(0, 10) ?? '') as Time)
    candle.setData(
      view.map((r, i) => ({
        time: times[i],
        open: r.open,
        high: r.high,
        low: r.low,
        close: r.close,
      })),
    )
    vol.setData(
      view.map((r, i) => ({
        time: times[i],
        value: r.volume,
        color:
          r.close >= r.open ? 'rgba(255,59,59,0.5)' : 'rgba(0,200,83,0.5)',
      })),
    )
    // 均线用全量（含预热段）计算，可视区从第一根起就有值
    const closes = rows.map((r) => r.close)
    MA_DEFS.forEach((def, idx) => {
      const series = maSeries[idx]
      if (!series) return
      const values = smaSeries(closes, def.n)
      const points: { time: Time; value: number }[] = []
      for (let j = 0; j < view.length; j++) {
        const v = values[offset + j]
        if (v != null) points.push({ time: times[j], value: v })
      }
      series.setData(points)
    })
    if (shouldFit) {
      const ts = chart.timeScale()
      const saved = rangeMemoryRef.current
        ? loadSavedRange(periodRef.current)
        : null
      if (saved) {
        const to = view.length - saved.right
        const from = Math.max(to - saved.bars, -0.5)
        try {
          ts.setVisibleLogicalRange({ from, to: Math.max(to, from + 1) })
        } catch {
          ts.fitContent()
        }
      } else {
        ts.fitContent()
      }
    }
  }, [rows])

  const maLegend = useMemo(() => {
    if (!rows.length) return []
    const closes = rows.map((r) => r.close)
    return MA_DEFS.map((def) => {
      const values = smaSeries(closes, def.n)
      return { ...def, value: values[values.length - 1] ?? null }
    }).filter((item) => item.value != null)
  }, [rows])

  return (
    <>
      {maLegend.length > 0 && (
        <div
          style={{
            display: 'flex',
            gap: 10,
            padding: '2px 8px',
            fontSize: 11,
            borderBottom: '1px solid #2a2a2a',
            alignItems: 'center',
          }}
        >
          {maLegend.map((item) => (
            <span key={item.n} style={{ color: item.color }}>
              MA{item.n}: {(item.value as number).toFixed(2)}
            </span>
          ))}
          <span
            className={`chip ${rangeMemory ? 'active' : ''}`}
            style={{ marginLeft: 'auto' }}
            onClick={() =>
              setRangeMemory((v) => {
                const next = !v
                try {
                  localStorage.setItem(RANGE_MEMORY_KEY, next ? '1' : '0')
                } catch {
                  /* 存储失败忽略 */
                }
                return next
              })
            }
            title="K线范围记忆：按周期记住缩放/平移范围，切换板块时保留"
          >
            记忆
          </span>
        </div>
      )}
      <div className="chart-host" style={{ position: 'relative' }}>
        <div ref={hostRef} style={{ width: '100%', height: '100%' }} />
      </div>
    </>
  )
}
