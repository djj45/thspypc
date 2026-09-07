import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import {
  createChart,
  ColorType,
  TickMarkType,
  type IChartApi,
  type ISeriesApi,
  type Time,
  type UTCTimestamp,
} from 'lightweight-charts'
import { KLINE_PERIODS, KLINE_MA_WARMUP, KLINE_VIEW_COUNT, useStock } from '../../state/StockContext'
import type { KlinePeriod } from '../../state/StockContext'
import { useStockNames } from '../../data/useStockNames'
import {
  buildMinuteAxis,
  useMinuteDailyBars,
  type MinuteAxis,
} from './klineMinuteAxis'
import { DaySeparatorPrimitive } from './klineDaySeparator'

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

/** 日K等非分钟周期的默认刻度（分钟轴未启用时的兜底，避免自定义
 *  formatter 常驻后把日K轴标签清空）。日K的 time 是 'YYYY-MM-DD'
 *  字符串，BusinessDay 对象与数字时间戳也要兜住。 */
function defaultTickLabel(time: Time, type: TickMarkType): string {
  if (typeof time === 'string') {
    if (type === TickMarkType.Year) return time.slice(0, 4)
    if (type === TickMarkType.Month) return time.slice(0, 7)
    return time.slice(5)
  }
  if (time && typeof time === 'object') {
    const { year, month, day } = time as { year: number; month: number; day: number }
    if (type === TickMarkType.Year) return `${year}`
    if (type === TickMarkType.Month) return `${year}-${String(month).padStart(2, '0')}`
    return `${String(month).padStart(2, '0')}-${String(day).padStart(2, '0')}`
  }
  const d = new Date(Number(time) * 1000)
  return `${String(d.getUTCMonth() + 1).padStart(2, '0')}-${String(
    d.getUTCDate(),
  ).padStart(2, '0')} ${String(d.getUTCHours()).padStart(2, '0')}:${String(
    d.getUTCMinutes(),
  ).padStart(2, '0')}`
}

/** 十字线悬浮标签的默认格式（非分钟周期：完整日期） */
function defaultTimeLabel(time: Time): string {
  if (typeof time === 'string') return time
  if (time && typeof time === 'object') {
    const { year, month, day } = time as { year: number; month: number; day: number }
    return `${year}-${String(month).padStart(2, '0')}-${String(day).padStart(2, '0')}`
  }
  const d = new Date(Number(time) * 1000)
  return `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, '0')}-${String(
    d.getUTCDate(),
  ).padStart(2, '0')}`
}

const RANGE_MEMORY_KEY = 'ths.kline.rangeMemory'
const rangeKeyOf = (period: string) => `ths.kline.range.${period}`

/** 可视范围记忆：锚定右端（right=最后一根 bar 距可视右缘的偏移）+
 *  可见 bar 数。端锚不随新 bar 追加漂移，跨股/跨日稳定。 */
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

export function KlineChart() {
  const hostRef = useRef<HTMLDivElement>(null)
  const chartRef = useRef<IChartApi | null>(null)
  const candleRef = useRef<ISeriesApi<'Candlestick'> | null>(null)
  const volRef = useRef<ISeriesApi<'Histogram'> | null>(null)
  const maRefs = useRef<(ISeriesApi<'Line'> | null)[]>([])
  const axisRef = useRef<MinuteAxis | null>(null)
  const separatorRef = useRef<DaySeparatorPrimitive | null>(null)
  const lastDataRef = useRef<unknown>(null)
  // K线范围记忆：按周期记住缩放/平移范围，切股时保留
  const [rangeMemory, setRangeMemory] = useState(
    () => localStorage.getItem(RANGE_MEMORY_KEY) !== '0',
  )
  const rangeMemoryRef = useRef(rangeMemory)
  rangeMemoryRef.current = rangeMemory
  const periodRef = useRef<KlinePeriod | null>(null)
  const viewLenRef = useRef(0)
  const [maOn, setMaOn] = useState(true)
  const { code, period, setPeriod, fuquan, setFuquan, klineState } = useStock()
  periodRef.current = period
  const names = useStockNames()
  const data = klineState.data
  const error = klineState.error
  const isMinute = period.endsWith('min')
  const periodMinutes = isMinute ? Number(period.slice(0, -3)) : 0
  const dailyBars = useMinuteDailyBars(code, isMinute, periodMinutes)
  // 实际拉了 VIEW+WARMUP 根：均线在可视区左侧也完整；展示裁回可视数量
  const view = useMemo(
    () =>
      data && data.length > KLINE_VIEW_COUNT ? data.slice(-KLINE_VIEW_COUNT) : data,
    [data],
  )
  const axis = useMemo<MinuteAxis | null>(
    () =>
      isMinute && view?.length
        ? buildMinuteAxis(view, periodMinutes, dailyBars)
        : null,
    [isMinute, view, periodMinutes, dailyBars],
  )
  axisRef.current = axis

  // 日分隔线跟随分钟轴：每个交易日首根（跳过第 0 根，不在最左边缘画线）
  useEffect(() => {
    separatorRef.current?.setMarks(
      axis
        ? axis.dayStarts
            .slice(1)
            .map((i) => ({
              time: axis.times[i],
              label: axis.metas[i].date.slice(5),
            }))
        : [],
    )
  }, [axis])

  // 记忆开关即时生效（跳过首次挂载）：关 = 立即铺满全图；开 = 把当前
  // 视野立即记为该周期记忆（订阅只在范围变化时落盘，主动补一次）
  const memoryToggleAppliedRef = useRef(false)
  useEffect(() => {
    if (!memoryToggleAppliedRef.current) {
      memoryToggleAppliedRef.current = true
      return
    }
    const chart = chartRef.current
    if (!chart || !view?.length) return
    const ts = chart.timeScale()
    if (!rangeMemory) {
      ts.fitContent()
      return
    }
    const range = ts.getVisibleLogicalRange()
    if (range == null) return
    try {
      localStorage.setItem(
        rangeKeyOf(period),
        JSON.stringify({
          right: view.length - range.to,
          bars: range.to - range.from,
        }),
      )
    } catch {
      /* 存储失败忽略 */
    }
    // 故意只依赖开关本身：切换时刻读取当期的 view/period
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [rangeMemory])

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
    // 轴刻度/十字线标签常驻自定义：分钟轴启用时显示真实日期/时刻
    // （合成时间轴只管等距定位），日K等周期回落到默认数值日期格式。
    const nearestMeta = (t: number) => {
      const axis = axisRef.current
      if (!axis || !axis.times.length) return null
      const base = axis.times[0] as number
      const i = Math.min(
        axis.metas.length - 1,
        Math.max(0, Math.round((t - base) / 60)),
      )
      return axis.metas[i]
    }
    chart.applyOptions({
      localization: {
        timeFormatter: (time: Time) => {
          const meta = nearestMeta(Number(time))
          return meta?.full || defaultTimeLabel(time)
        },
      },
      timeScale: {
        tickMarkFormatter: (time: Time, type: TickMarkType) => {
          if (type === TickMarkType.Time || type === TickMarkType.TimeWithSeconds) {
            const meta = nearestMeta(Number(time))
            return meta?.clock || defaultTickLabel(time, type)
          }
          // 分钟视图的日期信息由日分隔线顶部的日期标签表达，轴上不再
          // 重复（合成轴的“跨零点”与真实日界并不对应，直接标会错）
          const meta = nearestMeta(Number(time))
          return meta ? '' : defaultTickLabel(time, type)
        },
      },
    })
    // 分钟K日分隔线：画在 pane 画布上（与现价线同管线），缩放/平移自动重绘
    const separator = new DaySeparatorPrimitive()
    candle.attachPrimitive(separator)
    separatorRef.current = separator
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
    // 数据变化（切股/切周期）才重新铺满视图；仅日期对齐晚到导致的
    // 轴重建保持用户当前缩放/滚动位置
    const shouldFit = lastDataRef.current !== data
    lastDataRef.current = data
    if (!view) return
    const offset = data.length - view.length
    viewLenRef.current = view.length
    const times = isMinute
      ? axis?.times ?? []
      : view.map((k) => k.time?.slice(0, 10) ?? '')
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
      for (let j = 0; j < view.length; j++) {
        const v = values[offset + j]
        if (v != null) points.push({ time: times[j], value: v })
      }
      series.setData(points)
    })
    if (shouldFit) {
      const ts = chart.timeScale()
      // 范围记忆开启且有该周期的记忆时恢复（端锚换算），否则铺满
      const saved = rangeMemoryRef.current ? loadSavedRange(period) : null
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
  }, [data, maOn, isMinute, periodMinutes, axis, period])

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
              className={`chip ${rangeMemory ? 'active' : ''}`}
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
              title="K线范围记忆：按周期记住缩放/平移范围，切换股票时保留"
            >
              记忆
            </span>
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
