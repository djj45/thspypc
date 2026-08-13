import { HotBoardsPanel } from './HotBoardsPanel'
import { RankPanel } from './RankPanel'
import { GroupsPanel } from './GroupsPanel'
import { SelfStocksPanel } from './SelfStocksPanel'
import { DynamicPlatesPanel } from './DynamicPlatesPanel'
import { DdeRankPanel } from './DdeRankPanel'

// 左栏 2×3 六格：同花顺板块 / 全市场 / 自定义板块 / 自选 / 动态板块 / 主力排行。
export function LeftGrid() {
  return (
    <div className="left-grid">
      <HotBoardsPanel />
      <RankPanel />
      <GroupsPanel />
      <SelfStocksPanel />
      <DynamicPlatesPanel />
      <DdeRankPanel />
    </div>
  )
}
