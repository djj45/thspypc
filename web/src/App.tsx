import { StockProvider } from './state/StockContext'
import { Header } from './components/Header'
import { TimelineChart } from './components/center/TimelineChart'
import { KlineChart } from './components/center/KlineChart'
import { StockInfo } from './components/right/StockInfo'
import { DepthPanel } from './components/right/DepthPanel'
import { DxjlPanel } from './components/right/DxjlPanel'
import { LeftGrid } from './components/left/LeftGrid'

export default function App() {
  return (
    <StockProvider>
      <div className="app">
        <Header />
        <div className="body">
          <div className="col">
            <LeftGrid />
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
