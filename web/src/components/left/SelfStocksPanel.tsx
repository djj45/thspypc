import { api } from '../../api/endpoints'
import { useData } from '../../data/useData'
import { useStockNames } from '../../data/useStockNames'
import type { StockGroup } from '../../types'
import { fmtNum, isQuoteable } from './format'
import { Cell, StateBox, StockTable, type StockRowData } from './shared'

export function SelfStocksPanel() {
  const { data, loading, error } = useData<StockGroup>(() => api.selfStocks(), [])
  const nameMap = useStockNames()

  const rows: StockRowData[] = (data?.items ?? [])
    .filter((item) => isQuoteable(item.code))
    .map((item) => ({
      code: item.code,
      name: nameMap.get(item.code) ?? '',
      value: fmtNum(item.price),
      valueCls: 'flat',
    }))

  return (
    <Cell title="自选">
      <StateBox loading={loading} error={error} empty={!data || data.items.length === 0}>
        <StockTable rows={rows} />
      </StateBox>
    </Cell>
  )
}
