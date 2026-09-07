import { useCallback, useEffect, useRef, useState } from 'react'
import {
  normalizeStockCode,
  StockProvider,
  useStock,
} from './state/StockContext'
import type { StockPageMode } from './state/StockContext'
import { Header } from './components/Header'
import { useStockNames } from './data/useStockNames'
import { TimelineChart } from './components/center/TimelineChart'
import { KlineChart } from './components/center/KlineChart'
import { StockInfo } from './components/right/StockInfo'
import { DepthPanel } from './components/right/DepthPanel'
import { DxjlPanel } from './components/right/DxjlPanel'
import { LeftGrid } from './components/left/LeftGrid'
import { usePersistedWidth } from './components/left/shared'
import { TimelinePage } from './pages/TimelinePage'
import { SuperorderPage } from './pages/SuperorderPage'
import { StockStreamProvider } from './state/StockStreamContext'

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

function KanpanPage() {
  const left = usePersistedWidth('ths.layout.leftW', 1040, LEFT_MIN, LEFT_MAX)
  const { code } = useStock()
  const names = useStockNames()
  const stockLabel = `${names.get(code) ?? ''} ${code}`.trim()
  return (
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
          <div className="panel-title">分时 · {stockLabel}</div>
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
  )
}

function readView(): StockPageMode {
  const value = new URLSearchParams(window.location.search).get('view')
  return value === 'timeline' || value === 'superorder' ? value : 'kanpan'
}

function RoutedShell({
  view,
  onView,
}: {
  view: StockPageMode
  onView: (view: StockPageMode) => void
}) {
  const { code, setCode } = useStock()
  const restored = useRef(false)

  useEffect(() => {
    if (restored.current) return
    restored.current = true
    const initial = normalizeStockCode(
      new URLSearchParams(window.location.search).get('code'),
      code,
    )
    if (initial && initial !== code) setCode(initial)
  }, [code, setCode])

  useEffect(() => {
    const query = new URLSearchParams(window.location.search)
    query.set('view', view)
    query.set('code', code)
    window.history.replaceState(null, '', `/?${query.toString()}`)
  }, [code, view])

  return (
    <div className="app">
      <Header view={view} onView={onView} />
      <StockNav />
      {view === 'kanpan' ? (
        <KanpanPage />
      ) : (
        <StockStreamProvider key={code} code={code} enabled>
          {view === 'timeline' ? <TimelinePage /> : <SuperorderPage />}
        </StockStreamProvider>
      )}
    </div>
  )
}

export default function App() {
  const [view, setView] = useState<StockPageMode>(readView)
  useEffect(() => {
    const onPopState = () => setView(readView())
    window.addEventListener('popstate', onPopState)
    return () => window.removeEventListener('popstate', onPopState)
  }, [])
  const changeView = useCallback((next: StockPageMode) => {
    if (next === view) return
    const query = new URLSearchParams(window.location.search)
    query.set('view', next)
    window.history.pushState(null, '', `/?${query.toString()}`)
    setView(next)
  }, [view])

  return (
    <StockProvider mode={view}>
      <RoutedShell view={view} onView={changeView} />
    </StockProvider>
  )
}
