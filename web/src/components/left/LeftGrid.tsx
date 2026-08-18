import { HotBoardsPanel } from './HotBoardsPanel'
import { RankPanel } from './RankPanel'
import { GroupsPanel } from './GroupsPanel'
import { SelfStocksPanel } from './SelfStocksPanel'
import { DynamicPlatesPanel } from './DynamicPlatesPanel'
import { DdeRankPanel } from './DdeRankPanel'
import { usePersistedWidth } from './shared'

// 左栏两列各三格（同花顺板块/自定义板块/动态板块 + 全市场/自选/主力排行），
// 中间分隔条可拖拽调宽（持久化），格子变窄时列表自动少显示几列。
export function LeftGrid({ leftW }: { leftW: number }) {
  const col1 = usePersistedWidth(
    'ths.layout.col1',
    Math.floor((leftW - 5) / 2),
    220,
    Math.max(240, leftW - 240),
  )
  // 读取持久化值时按当前左栏总宽再夹一次（左栏宽度可能后来变了）
  const col1W = Math.min(col1.w, Math.max(220, leftW - 240))
  return (
    <div className="left-grid">
      <div className="lcol" style={{ width: col1W, flex: '0 0 auto' }}>
        <HotBoardsPanel />
        <GroupsPanel />
        <DynamicPlatesPanel />
      </div>
      <div className="vsplit" onPointerDown={col1.onPointerDown} />
      <div className="lcol" style={{ flex: '1 1 0', minWidth: 0 }}>
        <RankPanel />
        <SelfStocksPanel />
        <DdeRankPanel />
      </div>
    </div>
  )
}
