import { useEffect } from 'react'
import { StockProvider, useStock } from './state/StockContext'
import { Header } from './components/Header'
import { TimelineChart } from './components/center/TimelineChart'
import { KlineChart } from './components/center/KlineChart'
import { StockInfo } from './components/right/StockInfo'
import { DepthPanel } from './components/right/DepthPanel'
import { DxjlPanel } from './components/right/DxjlPanel'
import { LeftGrid } from './components/left/LeftGrid'
import { usePersistedWidth } from './components/left/shared'

// 左栏总宽可拖拽（与中栏图表之间的分隔条），持久化。
const LEFT_MIN = 560
const LEFT_MAX = Math.max(LEFT_MIN + 100, window.innerWidth - 620)

/** 键盘↑↓ + 分时/K线区域滚轮切换股票（顺序由 StockContext 决定）。 */
function StockNav() {
  const { navigate } = useStock()
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const t = e.target as HTMLElement | null
      if (
        t &&
        (t.tagName === 'INPUT' ||
          t.tagName === 'TEXTAREA' ||
          t.tagName === 'SELECT' ||
          t.isContentEditable)
      ) {
        return
      }
      if (e.key === 'ArrowUp') {
        e.preventDefault()
        navigate(-1)
      } else if (e.key === 'ArrowDown') {
        e.preventDefault()
        navigate(1)
      }
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [navigate])

  useEffect(() => {
    let last = 0
    const onWheel = (e: WheelEvent) => {
      const t = e.target as HTMLElement | null
      if (!t || !t.closest('.chart-host')) return
      e.preventDefault()
      if (Math.abs(e.deltaY) < 10) return
      const now = performance.now()
      if (now - last < 120) return
      last = now
      navigate(e.deltaY > 0 ? 1 : -1)
    }
    window.addEventListener('wheel', onWheel, { passive: false })
    return () => window.removeEventListener('wheel', onWheel)
  }, [navigate])
  return null
}

export default function App() {
  const left = usePersistedWidth('ths.layout.leftW', 1040, LEFT_MIN, LEFT_MAX)
  return (
    <StockProvider>
      <div className="app">
        <Header />
        <StockNav />
        <div
          className="body"
          style={{
            gridTemplateColumns: `${left.w}px 5px minmax(260px, 1fr) 280px`,
          }}
        >
          <div className="col">
            <LeftGrid leftW={left.w} />
          </div>
          <div className="vsplit" onPointerDown={left.onPointerDown} />
          <div className="col center">
            <div className="panel" style={{ flex: 1, minHeight: 0 }}>
              <div className="panel-title">分时</div>
              <div className="chart-host">
                <TimelineChart />
              </div>
            </div>
            <div className="panel" style={{ flex: 1, minHeight: 0 }}>
              <KlineChart />
            </div>
          </div>
          <div className="col">
            <div className="panel" style={{ flex: 1, minHeight: 0 }}>
              <div className="panel-title">盘口</div>
              <div className="panel-body">
                <StockInfo />
                <DepthPanel />
              </div>
            </div>
            <div className="panel" style={{ flex: 1, minHeight: 0 }}>
              <div className="panel-title">短线精灵</div>
              <div className="panel-body">
                <DxjlPanel />
              </div>
            </div>
          </div>
        </div>
      </div>
    </StockProvider>
  )
}
