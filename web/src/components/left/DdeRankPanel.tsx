import { api } from '../../api/endpoints'
import { useData } from '../../data/useData'
import { useStockNames } from '../../data/useStockNames'
import type { RankItem } from '../../types'
import { clsOf, fmtAmt } from './format'
import { Cell, StateBox, StockTable, type StockRowData } from './shared'

export function DdeRankPanel() {
  const { data, loading, error } = useData<RankItem[]>(
    () => api.ddeRank(),
    [],
    'snapshot',
    1000,
  )
  const nameMap = useStockNames()

  const rows: StockRowData[] = (data ?? []).map((r) => {
    const v = typeof r.value === 'number' ? r.value : undefined
    return {
      code: r.code,
      name: nameMap.get(r.code) ?? r.name ?? '',
      value: fmtAmt(v),
      valueCls: clsOf(v),
    }
  })

  return (
    <Cell title="主力排行">
      <StateBox loading={loading} error={error} empty={rows.length === 0}>
        <StockTable rows={rows} />
      </StateBox>
    </Cell>
  )
}
