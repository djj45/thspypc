import { useEffect, useMemo, useRef } from 'react'
import * as echarts from 'echarts'
import type { ECharts } from 'echarts'
import { useStock } from '../../state/StockContext'
import type { TimelinePoint } from '../../types'

type IntradayPoint = TimelinePoint & { phase?: string; time?: string }

const UP = '#ff5b5b'
const DOWN = '#35c983'
const FLAT = '#9a9a9a'

// 真实时刻 -> 交易分钟 x（午休压缩）。
// 早盘竞价 9:15-9:25 拉伸到 -15..0（竞价末点与 9:30 分时首点在边界
// 衔接，同时压缩 9:25-9:30 撮合空档）；盘中 9:30-11:29 -> 0..119；
// 下午 13:00-14:56 -> 120..236；尾盘竞价 14:57-15:00 -> 237..240。
function timeToX(iso?: string): number | null {
  if (!iso) return null
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return null
  const mins = d.getHours() * 60 + d.getMinutes() + d.getSeconds() / 60
  if (mins < 570) {
    const t = Math.min(Math.max((mins - 555) / 10, 0), 1)
    return -15 + t * 15
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

/** 同花顺式对称涨跌幅坐标：上下对称取整到 N，刻度等分。
 *  例：最大偏离 +3%/-9.8% -> N=10、step=2，刻度 -10,-8,…,0,…,8,10。 */
function symmetricRange(maxDeflectPct: number): { limit: number; step: number } {
  const steps = [0.25, 0.5, 1, 2, 5, 10, 20]
  for (const step of steps) {
    const limit = Math.max(step, Math.ceil(maxDeflectPct / step) * step)
    if ((limit * 2) / step + 1 <= 11) return { limit, step }
  }
  const step = Math.ceil(maxDeflectPct / 5)
  return { limit: step * 5, step }
}

function pctColor(pct: number): string {
  if (pct > 1e-9) return UP
  if (pct < -1e-9) return DOWN
  return FLAT
}

function fmtWan(v: number): string {
  // 入参单位：万元；按 万 / 千万 / 亿 三档显示
  const abs = Math.abs(v)
  if (abs >= 1e4) return (v / 1e4).toFixed(2) + '亿'
  if (abs >= 1e3) return (v / 1e3).toFixed(1) + '千万'
  return v.toFixed(0) + '万'
}

export function TimelineChart() {
  const hostRef = useRef<HTMLDivElement>(null)
  const chartRef = useRef<ECharts | null>(null)
  const { intradayState: intraday, quote } = useStock()
  const prevClose = quote?.prevClose

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

  // 全部序列数据在渲染期计算：图表 effect 与副图数值图例共用一份结果
  const seriesData = useMemo(() => {
    const points = intraday.data ?? []
    const continuous = points.filter((p) => p.phase === 'continuous')
    const opening = points.filter((p) => p.phase === 'opening_auction')
    const closing = points.filter((p) => p.phase === 'closing_auction')

    const contData: [number, number][] = []
    const avgData: [number, number][] = []
    // 大单副图：dt227/dt229 为累计主动买/卖大单额（元），逐分钟差分。
    // 完整分时接口固定返回 241 个分钟点，其中下标 237..240 对应
    // 14:57..15:00。保留 237 作为蓝色分时到尾盘竞价的边界锚点；竞价
    // 存在时只裁掉 238..240，避免重复绘制又不会在 14:56 后断开。
    const continuousPoints = closing.length
      ? continuous.slice(0, 238)
      : continuous
    let prevBuy: number | null = null
    let prevSell: number | null = null
    const netBars: [number, number][] = []
    const netLine: [number, number][] = []
    continuousPoints.forEach((p, i) => {
      if (p.dt10 != null) contData.push([i, p.dt10])
      // 均价：指数用 lead_price（黄线），个股按 累计额/累计量 计算
      const avg =
        p.lead_price != null
          ? p.lead_price
          : p.dt19 != null && p.dt13 && p.dt13 > 0
            ? p.dt19 / p.dt13
            : null
      if (avg != null) avgData.push([i, avg])
      const buy = p.dt227
      const sell = p.dt229
      if (buy != null && sell != null) {
        const netMinute =
          (buy - (prevBuy ?? 0)) - (sell - (prevSell ?? 0))
        netBars.push([i, netMinute / 1e4])
        netLine.push([i, (buy - sell) / 1e4])
        prevBuy = buy
        prevSell = sell
      }
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
    return {
      points,
      contData,
      avgData,
      openData,
      closeData,
      netBars,
      netLine,
      // 最新累计净额与最新分钟净额（万元），供副图常显数值
      lastCum: netLine.length ? netLine[netLine.length - 1][1] : null,
      lastNet: netBars.length ? netBars[netBars.length - 1][1] : null,
    }
  }, [intraday.data])

  useEffect(() => {
    const chart = chartRef.current
    if (!chart) return

    const { points, contData, avgData, openData, closeData, netBars, netLine } =
      seriesData

    // 对称坐标（同花顺式）：左%右价格，三色刻度
    const hasPrev = prevClose != null && prevClose > 0
    // 副图 y 轴下标：柱（分钟净额）与累计曲线各自独立缩放，
    // 避免累计量级把分钟柱压扁。有昨收时主图占 0/1，副图 2/3；否则 1/2。
    const subBarYIdx = hasPrev ? 2 : 1
    const subLineYIdx = hasPrev ? 3 : 2
    // 大单副图 y 轴：左轴=分钟净额柱，右轴=累计净额曲线。
    // 两个量级差一个数量级，各自独立缩放且都要有刻度——累计曲线若挂
    // 隐藏轴，可视刻度(柱轴)与曲线高度对不上（曲线 51 亿、刻度只到 6 亿）。
    const subAxes = [
      {
        type: 'value' as const,
        gridIndex: 1,
        name: '分钟净额',
        nameTextStyle: { color: '#666', fontSize: 9 },
        scale: true,
        axisLabel: {
          color: '#888',
          fontSize: 10,
          formatter: (v?: string | number) => fmtWan(Number(v)),
        },
        splitLine: { lineStyle: { color: '#1c1c1c' } },
      },
      {
        type: 'value' as const,
        gridIndex: 1,
        position: 'right' as const,
        name: '累计',
        nameTextStyle: { color: '#666', fontSize: 9 },
        scale: true,
        axisLabel: {
          color: '#888',
          fontSize: 10,
          formatter: (v?: string | number) => fmtWan(Number(v)),
        },
        splitLine: { show: false },
      },
    ]
    let yExtra: echarts.EChartsOption = {}
    if (hasPrev) {
      let maxDeflect = 0
      for (const p of points) {
        if (p.dt10 == null) continue
        maxDeflect = Math.max(
          maxDeflect,
          Math.abs((p.dt10 / prevClose - 1) * 100),
        )
      }
      const { limit, step } = symmetricRange(maxDeflect)
      const yMin = prevClose * (1 - limit / 100)
      const yMax = prevClose * (1 + limit / 100)
      const yInterval = prevClose * (step / 100)
      const pctOf = (v: number) => (v / prevClose - 1) * 100
      const pctFormatter = (v?: string | number) => {
        const pct = pctOf(Number(v))
        return (pct > 0 ? '+' : '') + +pct.toFixed(2) + '%'
      }
      const priceFormatter = (v?: string | number) =>
        Number(v).toFixed(2)
      const signColor = (v?: string | number) => pctColor(pctOf(Number(v)))
      yExtra = {
        yAxis: [
          {
            type: 'value',
            min: yMin,
            max: yMax,
            interval: yInterval,
            axisLabel: {
              fontSize: 10,
              formatter: pctFormatter,
              color: signColor,
            },
            axisLine: { lineStyle: { color: '#2a2a2a' } },
            splitLine: { lineStyle: { color: '#1c1c1c' } },
          },
          {
            type: 'value',
            min: yMin,
            max: yMax,
            interval: yInterval,
            position: 'right',
            axisLabel: {
              fontSize: 10,
              formatter: priceFormatter,
              color: signColor,
            },
            axisLine: { lineStyle: { color: '#2a2a2a' } },
            splitLine: { show: false },
          },
          ...subAxes,
        ],
      }
    } else {
      yExtra = {
        yAxis: [
          {
            type: 'value',
            scale: true,
            axisLabel: { color: '#888', fontSize: 10 },
            axisLine: { lineStyle: { color: '#2a2a2a' } },
            splitLine: { lineStyle: { color: '#1c1c1c' } },
          },
          ...subAxes,
        ],
      }
    }

    const xAxisBase = (showLabel: boolean) => ({
      type: 'value' as const,
      gridIndex: showLabel ? 1 : 0,
      // 数据范围即轴范围（-15=9:15 竞价首点，240=15:00），并固定刻度
      // 间隔：显式 min/max 下 ECharts 会按 (max-min)/splitNumber 均分，
      // 把 -17/243 之类的边界也打成标签（曾显示 09:13/15:03）。
      min: -15,
      max: 240,
      interval: 60,
      axisLabel: {
        show: showLabel,
        color: '#888',
        fontSize: 10,
        formatter: (v: number) => xToLabel(v),
        hideOverlap: true,
      },
      axisLine: { lineStyle: { color: '#2a2a2a' } },
      splitLine: { show: showLabel, lineStyle: { color: '#1c1c1c' } },
    })

    const series: echarts.SeriesOption[] = [
      {
        name: '盘中',
        type: 'line',
        xAxisIndex: 0,
        yAxisIndex: 0,
        data: contData,
        showSymbol: false,
        lineStyle: { color: '#2a9df4', width: 1 },
        areaStyle: { color: 'rgba(42,157,244,0.15)' },
        markLine:
          prevClose != null && prevClose > 0
            ? {
                silent: true,
                symbol: 'none',
                label: { show: false },
                lineStyle: { color: '#666', type: 'dashed', width: 1 },
                data: [{ yAxis: prevClose }],
              }
            : undefined,
      },
      {
        name: '均价',
        type: 'line',
        xAxisIndex: 0,
        yAxisIndex: 0,
        data: avgData,
        showSymbol: false,
        lineStyle: { color: '#e8c36a', width: 1 },
      },
      {
        name: '早盘竞价',
        type: 'line',
        xAxisIndex: 0,
        yAxisIndex: 0,
        data: openData,
        showSymbol: false,
        lineStyle: { color: '#e8a13a', width: 1 },
      },
      {
        name: '尾盘竞价',
        type: 'line',
        xAxisIndex: 0,
        yAxisIndex: 0,
        data: closeData,
        showSymbol: false,
        lineStyle: { color: '#e8a13a', width: 1 },
      },
    ]
    if (netBars.length) {
      series.push(
        {
          name: '大单净额',
          type: 'bar',
          xAxisIndex: 1,
          yAxisIndex: subBarYIdx,
          data: netBars,
          barWidth: '60%',
          itemStyle: {
            color: (p: unknown) => {
              const value = (p as { value?: unknown }).value
              const net =
                typeof value === 'number'
                  ? value
                  : Array.isArray(value) && typeof value[1] === 'number'
                    ? value[1]
                    : 0
              return net >= 0
                ? 'rgba(255,91,91,0.75)'
                : 'rgba(53,201,131,0.75)'
            },
          },
        },
        {
          name: '大单累计',
          type: 'line',
          xAxisIndex: 1,
          yAxisIndex: subLineYIdx,
          data: netLine,
          showSymbol: false,
          lineStyle: { color: '#e8e8e8', width: 1 },
        },
      )
    }

    // 恒定双 grid（主图 + 大单副图）：副图轴固定引用 gridIndex 1，
    // grid 数量随数据增减会让 ECharts 的 axisBuilder 崩溃；无大单数据
    // 时副图保持空轴即可。
    const grids = [
      { left: 54, right: 54, top: 8, height: '58%' },
      { left: 54, right: 54, top: '74%', height: '18%' },
    ]

    chart.setOption(
      {
        backgroundColor: '#141414',
        animation: false,
        axisPointer: { link: [{ xAxisIndex: 'all' }] },
        tooltip: {
          trigger: 'axis',
          backgroundColor: '#1f1f1f',
          borderColor: '#333',
          textStyle: { color: '#ccc', fontSize: 11 },
          formatter: (params: unknown) => {
            const list = params as {
              seriesName: string
              value: [number, number]
              axisValueLabel?: string
            }[]
            if (!list?.length) return ''
            const x = list[0].value[0]
            const rows = list
              .map((item) => {
                const v = item.value[1]
                const text =
                  item.seriesName === '大单净额' || item.seriesName === '大单累计'
                    ? fmtWan(v)
                    : v.toFixed(2)
                return `${item.seriesName}: ${text}`
              })
              .join('<br/>')
            return `${xToLabel(x)}<br/>${rows}`
          },
        },
        grid: grids,
        xAxis: [xAxisBase(false), xAxisBase(true)],
        ...yExtra,
        series,
      },
      { notMerge: true },
    )
  }, [seriesData, prevClose])

  return (
    <>
      <div ref={hostRef} style={{ width: '100%', height: '100%' }} />
      {seriesData.lastCum != null && (
        <div
          style={{
            position: 'absolute',
            // 与副图 grid（top 74%）对齐的常显数值行
            top: '74%',
            left: 60,
            fontSize: 11,
            lineHeight: '14px',
            pointerEvents: 'none',
            display: 'flex',
            gap: 10,
          }}
        >
          <span className={seriesData.lastCum > 0 ? 'up' : seriesData.lastCum < 0 ? 'down' : 'flat'}>
            累计大单 {seriesData.lastCum > 0 ? '+' : ''}
            {fmtWan(seriesData.lastCum)}
          </span>
          {seriesData.lastNet != null && (
            <span className={seriesData.lastNet > 0 ? 'up' : seriesData.lastNet < 0 ? 'down' : 'flat'}>
              最新分钟 {seriesData.lastNet > 0 ? '+' : ''}
              {fmtWan(seriesData.lastNet)}
            </span>
          )}
        </div>
      )}
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
