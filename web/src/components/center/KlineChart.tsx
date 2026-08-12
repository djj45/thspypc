import { useEffect, useRef } from 'react'
import {
  createChart,
  ColorType,
  type IChartApi,
  type ISeriesApi,
} from 'lightweight-charts'
import { KLINE_PERIODS, useStock } from '../../state/StockContext'

const FUQUAN = [
  { v: 'Q', label: '前复权' },
  { v: 'H', label: '后复权' },
  { v: '', label: '不复权' },
]

export function KlineChart() {
  const hostRef = useRef<HTMLDivElement>(null)
  const chartRef = useRef<IChartApi | null>(null)
  const candleRef = useRef<ISeriesApi<'Candlestick'> | null>(null)
  const volRef = useRef<ISeriesApi<'Histogram'> | null>(null)
  const { code, period, setPeriod, fuquan, setFuquan, klineState } = useStock()
  const data = klineState.data
  const error = klineState.error

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
    }
  }, [])

  useEffect(() => {
    const candle = candleRef.current
    const vol = volRef.current
    const chart = chartRef.current
    if (!candle || !vol || !chart) return
    if (!data) {
      candle.setData([])
      vol.setData([])
      return
    }
    const rows = data.map((k) => ({ ...k, day: (k.time || '').slice(0, 10) }))
    candle.setData(
      rows.map((r) => ({
        time: r.day,
        open: r.open,
        high: r.high,
        low: r.low,
        close: r.close,
      })),
    )
    vol.setData(
      rows.map((r) => ({
        time: r.day,
        value: r.volume,
        color:
          r.close >= r.open ? 'rgba(255,59,59,0.5)' : 'rgba(0,200,83,0.5)',
      })),
    )
    chart.timeScale().fitContent()
  }, [data])

  return (
    <>
      <div className="panel-title">
        日K · {code}
        <span style={{ marginLeft: 'auto', display: 'flex', gap: 4 }}>
          {KLINE_PERIODS.map((p) => (
            <span
              key={p}
              className={`chip ${period === p ? 'active' : ''}`}
              onClick={() => setPeriod(p)}
            >
              {p === 'day'
                ? '日'
                : p === 'week'
                  ? '周'
                  : p === 'month'
                    ? '月'
                    : p + 'm'}
            </span>
          ))}
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
