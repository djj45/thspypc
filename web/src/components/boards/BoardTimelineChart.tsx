import { useEffect, useMemo, useRef } from 'react'
import * as echarts from 'echarts'
import type { ECharts } from 'echarts'
import { pctColor, symmetricRange, xToLabel } from '../center/TimelineChart'

// 板块指数分时（/api/board/{code}/timeline，0x42 表 241 点）：
// 主图 = 现价线 + 均价线（累计额/累计量），副图 = 分钟量差分柱。
// 与个股 TimelineChart 的差异：无竞价/大单副图（板块 0x42 无这些字段），
// x 轴直接用 minute_index（首点 09:30 = 0，尾点 15:00 = 240）。

// 板块分时点（/api/board/{code}/timeline）：只取图表需要的字段；
// is_baseline 标记 0x42 首行基准价哨兵（服务端附加，非 TimelinePoint 标准字段）。
interface BoardPoint {
  code?: string
  minute_index?: number
  is_baseline?: boolean
  date?: string
  dt10?: number
  dt13?: number
  dt19?: number
}

function fmtHand(v: number): string {
  const abs = Math.abs(v)
  if (abs >= 1e8) return (v / 1e8).toFixed(2) + '亿手'
  if (abs >= 1e4) return (v / 1e4).toFixed(1) + '万手'
  return v.toFixed(0) + '手'
}

export function BoardTimelineChart({
  points,
  prevClose,
}: {
  points: BoardPoint[]
  prevClose?: number
}) {
  const hostRef = useRef<HTMLDivElement>(null)
  const chartRef = useRef<ECharts | null>(null)

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

  const seriesData = useMemo(() => {
    // 0x42 首行可能是基准价哨兵（is_baseline / 无日期），剔除后按剩余
    // 顺序取 x：无论首点在 minute_index 1 还是 0，09:30 都映射到 0。
    const rows = points.filter((p) => !p.is_baseline && p.dt10 != null)
    const priceData: [number, number][] = []
    const avgData: [number, number][] = []
    const volBars: [number, number, number][] = []
    let prevVol: number | null = null
    let prevPrice: number | null = null
    rows.forEach((p, i) => {
      priceData.push([i, p.dt10 as number])
      const avg =
        p.dt19 != null && p.dt13 && p.dt13 > 0 ? p.dt19 / p.dt13 : null
      if (avg != null) avgData.push([i, avg])
      if (p.dt13 != null) {
        const up = prevPrice != null ? (p.dt10 as number) >= prevPrice : true
        volBars.push([i, (p.dt13 - (prevVol ?? 0)) / 100, up ? 1 : -1])
        prevVol = p.dt13
        prevPrice = p.dt10 as number
      }
    })
    return { rows, priceData, avgData, volBars }
  }, [points])

  useEffect(() => {
    const chart = chartRef.current
    if (!chart) return
    const { rows, priceData, avgData, volBars } = seriesData

    const hasPrev = prevClose != null && prevClose > 0
    const volYIdx = hasPrev ? 2 : 1
    const volAxis = {
      type: 'value' as const,
      gridIndex: 1,
      name: '成交量',
      nameTextStyle: { color: '#666', fontSize: 9 },
      axisLabel: {
        color: '#888',
        fontSize: 10,
        formatter: (v?: string | number) => fmtHand(Number(v)),
      },
      splitLine: { lineStyle: { color: '#1c1c1c' } },
    }
    let yExtra: echarts.EChartsOption = {}
    if (hasPrev) {
      let maxDeflect = 0
      for (const p of rows) {
        if (p.dt10 == null) continue
        maxDeflect = Math.max(
          maxDeflect,
          Math.abs(((p.dt10 as number) / (prevClose as number) - 1) * 100),
        )
      }
      const { limit, step } = symmetricRange(maxDeflect)
      const yMin = (prevClose as number) * (1 - limit / 100)
      const yMax = (prevClose as number) * (1 + limit / 100)
      const yInterval = (prevClose as number) * (step / 100)
      const pctOf = (v: number) => (v / (prevClose as number) - 1) * 100
      const pctFormatter = (v?: string | number) => {
        const pct = pctOf(Number(v))
        return (pct > 0 ? '+' : '') + +pct.toFixed(2) + '%'
      }
      const priceFormatter = (v?: string | number) => Number(v).toFixed(2)
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
          volAxis,
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
          volAxis,
        ],
      }
    }

    const xAxisBase = (gridIndex: number, showLabel: boolean) => ({
      type: 'value' as const,
      gridIndex,
      min: 0,
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
        name: '现价',
        type: 'line',
        xAxisIndex: 0,
        yAxisIndex: 0,
        data: priceData,
        showSymbol: false,
        lineStyle: { color: '#2a9df4', width: 1 },
        areaStyle: { color: 'rgba(42,157,244,0.15)' },
        markLine:
          hasPrev
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
    ]
    if (volBars.length) {
      series.push({
        name: '成交量',
        type: 'bar',
        xAxisIndex: 1,
        yAxisIndex: volYIdx,
        data: volBars.map(([x, vol, dir]) => ({
          value: [x, vol],
          itemStyle: {
            color:
              dir >= 0 ? 'rgba(255,59,59,0.6)' : 'rgba(0,200,83,0.6)',
          },
        })),
        barWidth: '60%',
      })
    }

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
            }[]
            if (!list?.length) return ''
            const x = list[0].value[0]
            const rows = list
              .map((item) => {
                const v = item.value[1]
                const text =
                  item.seriesName === '成交量' ? fmtHand(v) : v.toFixed(2)
                return `${item.seriesName}: ${text}`
              })
              .join('<br/>')
            return `${xToLabel(x)}<br/>${rows}`
          },
        },
        grid: [
          { left: 54, right: 54, top: 8, height: '58%' },
          { left: 54, right: 54, top: '74%', height: '20%' },
        ],
        xAxis: [xAxisBase(0, false), xAxisBase(1, true)],
        ...yExtra,
        series,
      },
      { notMerge: true },
    )
  }, [seriesData, prevClose])

  return <div ref={hostRef} style={{ width: '100%', height: '100%' }} />
}
