import type {
  IChartApi,
  ISeriesPrimitive,
  ISeriesPrimitivePaneRenderer,
  ISeriesPrimitivePaneView,
  SeriesAttachedParameter,
  SeriesType,
  Time,
  UTCTimestamp,
} from 'lightweight-charts'

export interface DayMark {
  time: UTCTimestamp
  label: string // 'MM-DD'
}

interface MarkEntry {
  x: number
  label: string
}

// fancy-canvas 是 lightweight-charts 的传递依赖（pnpm 严格模式下项目
// 代码不可直接 import），用最小结构类型描述画布目标即可
interface BitmapScope {
  context: CanvasRenderingContext2D
  bitmapSize: { width: number; height: number }
  horizontalPixelRatio: number
}

interface MediaScope {
  context: CanvasRenderingContext2D
}

interface CanvasTarget {
  useBitmapCoordinateSpace(handler: (scope: BitmapScope) => void): void
  useMediaCoordinateSpace(handler: (scope: MediaScope) => void): void
}

/** 分隔线与日期标签直接画在 LWC 的 pane 画布上（与现价线同一条渲染
 *  管线）：DPI 缩放下由画布保证清晰，缩放/平移随图表自动重绘。 */
class DaySeparatorRenderer implements ISeriesPrimitivePaneRenderer {
  constructor(private readonly entries: readonly MarkEntry[]) {}

  draw(target: CanvasTarget): void {
    if (!this.entries.length) return
    // 位图坐标画线：虚线、3/4 像素宽（比网格线更轻），dash 按像素比缩放
    target.useBitmapCoordinateSpace((scope: BitmapScope) => {
      const { context, bitmapSize, horizontalPixelRatio } = scope
      context.strokeStyle = 'rgba(255,255,255,0.55)'
      context.lineWidth = Math.max(0.5, horizontalPixelRatio * 0.75)
      context.setLineDash([
        4 * horizontalPixelRatio,
        3 * horizontalPixelRatio,
      ])
      context.beginPath()
      for (const e of this.entries) {
        const x = Math.round(e.x * horizontalPixelRatio) + 0.5 * horizontalPixelRatio
        context.moveTo(x, 0)
        context.lineTo(x, bitmapSize.height)
      }
      context.stroke()
    })
    // 媒体坐标画文字标签；从最新一天往回铺，相邻至少 48px
    target.useMediaCoordinateSpace((scope: MediaScope) => {
      const { context } = scope
      context.font = '11px sans-serif'
      context.textBaseline = 'top'
      let anchorX = Infinity
      for (let i = this.entries.length - 1; i >= 0; i--) {
        const e = this.entries[i]
        if (anchorX - e.x < 48) continue
        anchorX = e.x
        const w = context.measureText(e.label).width
        context.fillStyle = 'rgba(20,20,20,0.9)'
        context.fillRect(e.x + 2, 2, w + 6, 14)
        context.fillStyle = '#ddd'
        context.fillText(e.label, e.x + 5, 3)
      }
    })
  }
}

/** 分钟K日分隔线 primitive：每个交易日首根 bar 处一条贯穿竖线。 */
export class DaySeparatorPrimitive implements ISeriesPrimitive {
  private chart: IChartApi | null = null
  private requestUpdate: (() => void) | null = null
  private marks: readonly DayMark[] = []
  private entries: MarkEntry[] = []
  private readonly paneView: ISeriesPrimitivePaneView = {
    zOrder: () => 'top',
    renderer: () =>
      this.entries.length ? new DaySeparatorRenderer(this.entries) : null,
  }

  attached(param: SeriesAttachedParameter<Time, SeriesType>): void {
    this.chart = param.chart
    this.requestUpdate = param.requestUpdate
  }

  detached(): void {
    this.chart = null
    this.requestUpdate = null
  }

  updateAllViews(): void {
    this.entries = []
    const chart = this.chart
    if (!chart) return
    const ts = chart.timeScale()
    for (const mark of this.marks) {
      const x = ts.timeToCoordinate(mark.time)
      if (x == null) continue
      this.entries.push({ x, label: mark.label })
    }
  }

  paneViews(): readonly ISeriesPrimitivePaneView[] {
    return [this.paneView]
  }

  setMarks(marks: readonly DayMark[]): void {
    this.marks = marks
    this.requestUpdate?.()
  }
}
