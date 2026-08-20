import { useEffect, useRef } from 'react'
import * as echarts from 'echarts'
import type { ECharts } from 'echarts'
import type { ReplayIndexPoint } from '../types'

export function ReplayChart({
  points,
  selectedTs,
  onSelect,
}: {
  points: ReplayIndexPoint[]
  selectedTs: number | null
  onSelect: (ts: number) => void
}) {
  const host = useRef<HTMLDivElement>(null)
  const chartRef = useRef<ECharts | null>(null)
  const pointsRef = useRef(points)
  const onSelectRef = useRef(onSelect)
  pointsRef.current = points
  onSelectRef.current = onSelect

  useEffect(() => {
    if (!host.current) return
    const chart = echarts.init(host.current, undefined, { renderer: 'canvas' })
    chartRef.current = chart
    const resize = new ResizeObserver(() => chart.resize())
    resize.observe(host.current)
    // ECharts的series click只在细线附近命中，实际使用时常被误认为必须双击。
    // 改在两个绘图区接收单击，再把横坐标换算成最近的数据点。
    chart.getZr().on('click', (event) => {
      const pixel: [number, number] = [event.offsetX, event.offsetY]
      const inPrice = chart.containPixel({ gridIndex: 0 }, pixel)
      const inVolume = chart.containPixel({ gridIndex: 1 }, pixel)
      if (!inPrice && !inVolume) return
      const converted = chart.convertFromPixel(
        { xAxisIndex: inPrice ? 0 : 1 },
        pixel,
      )
      const value = Array.isArray(converted) ? converted[0] : converted
      const current = pointsRef.current
      let index = typeof value === 'number' && Number.isFinite(value)
        ? Math.round(value)
        : -1
      if (index < 0 || index >= current.length) {
        index = current.findIndex((point) => point.time === String(value))
      }
      if (index < 0) {
        // 部分ECharts版本对category轴的convertFromPixel返回NaN。按当前
        // dataZoom百分比和绘图区宽度兜底换算，仍能精确到最近的索引点。
        const zoom = (chart.getOption().dataZoom as Array<{
          start?: number
          end?: number
        }> | undefined)?.[0]
        const start = Number(zoom?.start ?? 0)
        const end = Number(zoom?.end ?? 100)
        const ratio = Math.max(0, Math.min(
          1,
          (event.offsetX - 55) / Math.max(1, chart.getWidth() - 55 - 14),
        ))
        index = Math.round(
          ((start + (end - start) * ratio) / 100) * (current.length - 1),
        )
      }
      const selected = current[index]
      if (selected) onSelectRef.current(selected.ts)
    })
    return () => {
      resize.disconnect()
      chart.dispose()
      chartRef.current = null
    }
  }, [])

  useEffect(() => {
    const chart = chartRef.current
    if (!chart) return
    const labels = points.map((point) => point.time)
    const volumes = points.map((point, index) => {
      const current = Number(point.volume ?? 0)
      const previous = index > 0 ? Number(points[index - 1].volume ?? 0) : current
      return Math.max(0, current - previous)
    })
    chart.setOption({
      backgroundColor: '#141414',
      animation: false,
      axisPointer: { link: [{ xAxisIndex: 'all' }] },
      tooltip: { trigger: 'axis', backgroundColor: '#222', borderColor: '#444', textStyle: { color: '#ddd', fontSize: 11 } },
      grid: [
        { left: 55, right: 14, top: 14, height: '64%' },
        { left: 55, right: 14, top: '76%', height: '16%' },
      ],
      xAxis: [
        {
          type: 'category', data: labels, boundaryGap: false,
          axisLabel: { show: false }, axisLine: { lineStyle: { color: '#333' } },
        },
        {
          type: 'category', gridIndex: 1, data: labels, boundaryGap: true,
          axisLabel: { color: '#888', fontSize: 10, interval: Math.max(1, Math.floor(points.length / 6)) },
          axisLine: { lineStyle: { color: '#333' } },
        },
      ],
      yAxis: [
        { type: 'value', scale: true, axisLabel: { color: '#888', fontSize: 10 }, splitLine: { lineStyle: { color: '#202020' } } },
        { type: 'value', gridIndex: 1, axisLabel: { color: '#777', fontSize: 9 }, splitLine: { show: false } },
      ],
      dataZoom: [
        { type: 'inside', xAxisIndex: [0, 1], start: Math.max(0, 100 - 18000 / Math.max(points.length, 1)), end: 100 },
        { type: 'slider', xAxisIndex: [0, 1], height: 13, bottom: 2, borderColor: '#333', fillerColor: 'rgba(42,82,152,.35)', textStyle: { color: '#777' } },
      ],
      series: [
        {
          id: 'price', name: '价格', type: 'line', data: points.map((point) => point.price),
          showSymbol: false, lineStyle: { color: '#2a9df4', width: 1 },
        },
        {
          id: 'volume', name: '成交量', type: 'bar', xAxisIndex: 1, yAxisIndex: 1,
          data: volumes, itemStyle: { color: '#596b83' },
        },
      ],
    }, true)
  }, [points])

  useEffect(() => {
    const chart = chartRef.current
    if (!chart) return
    const selected = selectedTs == null
      ? -1
      : points.findIndex((point) => point.ts === selectedTs)
    // 只合并更新光标线，不能用notMerge重建整张图；否则用户当前dataZoom
    // 范围会被恢复成默认的末尾窗口。
    chart.setOption({
      series: [{
        id: 'price',
        markLine: selected >= 0 ? {
          silent: true,
          symbol: 'none',
          lineStyle: { color: '#e8c36a', width: 1 },
          label: { show: false },
          data: [{ xAxis: selected }],
        } : { data: [] },
      }],
    })
  }, [points, selectedTs])

  return <div ref={host} style={{ width: '100%', height: '100%' }} />
}
