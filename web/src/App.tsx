import { StockProvider } from './state/StockContext'
import { Header } from './components/Header'
import { TimelineChart } from './components/center/TimelineChart'
import { KlineChart } from './components/center/KlineChart'
import { StockInfo } from './components/right/StockInfo'
import { DepthPanel } from './components/right/DepthPanel'
import { DxjlPanel } from './components/right/DxjlPanel'

// 左栏 6 格占位（阶段 B 后续填板块表/全市场表/自选/动态）。
function LeftPlaceholders() {
  const titles = [
    '同花顺板块',
    '全市场',
    '自定义板块',
    '自选',
    '动态板块',
    '动态板块',
  ]
  return (
    <div className="left-grid">
      {titles.map((t) => (
        <div className="cell" key={t}>
          <div className="cell-title">{t}</div>
          <div className="dim" style={{ padding: 8, fontSize: 11 }}>
            待接入
          </div>
        </div>
      ))}
    </div>
  )
}

export default function App() {
  return (
    <StockProvider>
      <div className="app">
        <Header />
        <div className="body">
          <div className="col">
            <LeftPlaceholders />
          </div>
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
