import { useMemo, useState } from 'react'
import { api } from '../../api/endpoints'
import { useData } from '../../data/useData'
import type { Board, SystemBlock } from '../../types'
import { Cell, StateBox } from './shared'
import { clsOf, fmtAmt, fmtPct } from './format'

type BoardSort = 'chg' | 'speed' | 'inflow' | 'limit'

const SORTS: { key: BoardSort; label: string }[] = [
  { key: 'chg', label: '涨幅' },
  { key: 'speed', label: '涨速' },
  { key: 'inflow', label: '主力' },
  { key: 'limit', label: '涨停' },
]

function sortValue(b: Board, key: BoardSort): number {
  switch (key) {
    case 'chg':
      return b.chg_pct ?? -Infinity
    case 'speed':
      return b.speed_4m ?? b.speed_1m ?? -Infinity
    case 'inflow':
      return b.main_inflow ?? -Infinity
    case 'limit':
      return b.limit_up ?? -Infinity
  }
}

export function HotBoardsPanel() {
  const boards = useData<Board[]>(() => api.hotBoards(), [], 'snapshot', 800)
  const blocks = useData<SystemBlock[]>(() => api.boards(), [])
  const [sort, setSort] = useState<BoardSort>('chg')
  const [page, setPage] = useState(0)

  const nameMap = useMemo(
    () => new Map((blocks.data ?? []).map((b) => [b.block_id, b.name])),
    [blocks.data],
  )

  const sorted = useMemo(() => {
    const rows = [...(boards.data ?? [])]
    rows.sort((a, b) => sortValue(b, sort) - sortValue(a, sort))
    return rows
  }, [boards.data, sort])

  const pageSize = 40
  const pages = Math.max(1, Math.ceil(sorted.length / pageSize))
  const cur = Math.min(page, pages - 1)
  const slice = sorted.slice(cur * pageSize, (cur + 1) * pageSize)

  return (
    <Cell title="同花顺板块">
      <div className="cell-toolbar">
        {SORTS.map((s) => (
          <span
            key={s.key}
            className={sort === s.key ? 'chip active' : 'chip'}
            onClick={() => {
              setSort(s.key)
              setPage(0)
            }}
          >
            {s.label}
          </span>
        ))}
      </div>
      <StateBox loading={boards.loading} error={boards.error} empty={sorted.length === 0}>
        <table>
          <thead>
            <tr>
              <th className="left">板块</th>
              <th>涨幅</th>
              <th>主力</th>
            </tr>
          </thead>
          <tbody>
            {slice.map((b) => (
              <tr key={b.code}>
                <td className="left" title={b.code}>
                  {nameMap.get(b.code) ?? b.code}
                </td>
                <td className={clsOf(b.chg_pct)}>{fmtPct(b.chg_pct)}</td>
                <td className={clsOf(b.main_inflow)}>{fmtAmt(b.main_inflow)}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {pages > 1 && (
          <div className="pager">
            <button onClick={() => setPage(Math.max(0, cur - 1))} disabled={cur === 0}>
              ‹
            </button>
            <span className="dim">
              {cur + 1}/{pages}
            </span>
            <button
              onClick={() => setPage(Math.min(pages - 1, cur + 1))}
              disabled={cur === pages - 1}
            >
              ›
            </button>
          </div>
        )}
      </StateBox>
    </Cell>
  )
}
