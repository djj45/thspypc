import { useMemo } from 'react'
import { api } from '../../api/endpoints'
import { useData } from '../../data/useData'
import type { Board, SystemBlock } from '../../types'
import { BoardTable, Cell, StateBox, type BoardRowData } from './shared'

export function HotBoardsPanel() {
  const boards = useData<Board[]>(() => api.hotBoards(), [], 'snapshot', 800)
  const blocks = useData<SystemBlock[]>(() => api.boards(), [])

  const nameMap = useMemo(
    () => new Map((blocks.data ?? []).map((b) => [b.block_id, b.name])),
    [blocks.data],
  )

  const rows: BoardRowData[] = useMemo(
    () =>
      (boards.data ?? []).map((b) => ({
        code: b.code,
        name: b.name ?? nameMap.get(b.code) ?? b.code,
        chgPct: b.chg_pct,
        speed4m: b.speed_4m ?? b.speed_1m,
        mainInflow: b.main_inflow,
        upCount: b.up_count,
        downCount: b.down_count,
        limitUp: b.limit_up,
      })),
    [boards.data, nameMap],
  )

  return (
    <Cell title="同花顺板块">
      <StateBox loading={boards.loading} error={boards.error} empty={rows.length === 0}>
        <BoardTable rows={rows} initialSort={{ key: 'chgPct', desc: true }} />
      </StateBox>
    </Cell>
  )
}
