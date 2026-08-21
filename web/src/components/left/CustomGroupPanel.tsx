import { useEffect, useMemo, useState } from 'react'
import { api } from '../../api/endpoints'
import { useData } from '../../data/useData'
import { useStockNames } from '../../data/useStockNames'
import type { DynamicPlate } from '../../types'
import { isQuoteable } from './format'
import {
  Cell,
  StateBox,
  StockTable,
  useQuoteExt,
  type StockRowData,
} from './shared'

// 选中的分组：kind=自选/静态自定义/动态
interface GroupSel {
  kind: 'self' | 'static' | 'dynamic'
  name: string
}

const SELF_SEL: GroupSel = { kind: 'self', name: '自选股' }

function sameSel(a: GroupSel | null, b: GroupSel | null): boolean {
  return !!a && !!b && a.kind === b.kind && a.name === b.name
}

// 统一自定义板块面板：下拉可选 自选股 / 静态自定义板块 / 动态板块。
// 动态板块带刷新按钮——用云端问财语句(attrs.question)实时重查成分股；
// 每个面板实例的选择独立持久化（storageKey）。
export function CustomGroupPanel({
  storageKey,
  defaultKind = 'static',
  title = '自定义板块',
}: {
  storageKey: string
  defaultKind?: 'self' | 'static' | 'dynamic'
  title?: string
}) {
  const [sel, setSel] = useState<GroupSel | null>(() => {
    try {
      const saved = localStorage.getItem(storageKey)
      if (saved) return JSON.parse(saved) as GroupSel
    } catch {
      /* 忽略损坏缓存 */
    }
    return null
  })
  const groupsReq = useData(() => api.groups(), [])
  const platesReq = useData<DynamicPlate[]>(() => api.dynamicPlates(), [])
  const [refreshed, setRefreshed] = useState<DynamicPlate | null>(null)
  const [refreshing, setRefreshing] = useState(false)
  const [refreshError, setRefreshError] = useState('')
  const nameMap = useStockNames()

  const groups = useMemo(
    () =>
      (groupsReq.data ?? []).filter(
        (g) => !g.is_dynamic && g.group_id !== '__selfstock__',
      ),
    [groupsReq.data],
  )
  const plates = platesReq.data ?? []

  // 校验持久化的选择（板块可能已删）；无选择时按 defaultKind 挑默认
  useEffect(() => {
    if (groupsReq.loading || platesReq.loading) return
    if (sel) {
      const valid =
        sel.kind === 'self' ||
        (sel.kind === 'static' && groups.some((g) => g.name === sel.name)) ||
        (sel.kind === 'dynamic' && plates.some((p) => p.name === sel.name))
      if (valid) return
    }
    let pick: GroupSel | null = null
    if (defaultKind === 'self' && groupsReq.data) pick = SELF_SEL
    else if (defaultKind === 'dynamic' && plates.length > 0)
      pick = { kind: 'dynamic', name: plates[0].name }
    else if (defaultKind === 'static' && groups.length > 0)
      pick = { kind: 'static', name: groups[0].name }
    // 兜底顺序：静态 → 动态 → 自选
    if (!pick && groups.length > 0) pick = { kind: 'static', name: groups[0].name }
    if (!pick && plates.length > 0) pick = { kind: 'dynamic', name: plates[0].name }
    if (!pick && groupsReq.data) pick = SELF_SEL
    if (pick) persist(pick)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [groups, plates, groupsReq.loading, platesReq.loading, groupsReq.data])

  const persist = (next: GroupSel) => {
    setSel(next)
    setRefreshed(null)
    setRefreshError('')
    try {
      localStorage.setItem(storageKey, JSON.stringify(next))
    } catch {
      /* 存储失败忽略 */
    }
  }

  const activePlate = useMemo(
    () => (sel?.kind === 'dynamic' ? plates.find((p) => p.name === sel.name) : undefined),
    [sel, plates],
  )

  // 当前选中分组的成分代码（动态板块优先显示刷新后的实时结果）
  const codes = useMemo(() => {
    if (!sel) return [] as string[]
    if (sel.kind === 'self') {
      return [] // 自选走单独请求（见下）
    }
    if (sel.kind === 'static') {
      const g = groups.find((x) => x.name === sel.name)
      return (g?.items ?? []).map((i) => i.code).filter(isQuoteable)
    }
    const plate = refreshed?.name === sel.name ? refreshed : activePlate
    return (plate?.items ?? [])
      .map((full) => full.split('.')[0])
      .filter(isQuoteable)
  }, [sel, groups, activePlate, refreshed])

  const selfReq = useData(
    () => (sel?.kind === 'self' ? api.selfStocks() : Promise.resolve(null)),
    [sel?.kind],
  )
  const selfCodes = useMemo(
    () =>
      sel?.kind === 'self'
        ? (selfReq.data?.items ?? []).map((i) => i.code).filter(isQuoteable)
        : [],
    [sel?.kind, selfReq.data],
  )
  const finalCodes = sel?.kind === 'self' ? selfCodes : codes

  const onRefresh = () => {
    if (!activePlate) return
    setRefreshing(true)
    setRefreshError('')
    api
      .dynamicPlateRefresh(activePlate.name)
      .then((plate) => setRefreshed(plate))
      .catch((e: Error) => setRefreshError(e.message.slice(0, 50)))
      .finally(() => setRefreshing(false))
  }

  const [visibleCodes, setVisibleCodes] = useState<string[]>([])
  // 小型自定义板块（如260818的26只）必须整组刷新，才能保证涨幅排序能把
  // 视口外的新强弱股票移动进来；大分组仍只拉可视窗口，避免超长URL和重负载。
  const quoteCodes = finalCodes.length <= 100 ? finalCodes : visibleCodes
  const quotes = useQuoteExt(quoteCodes)

  const rows: StockRowData[] = useMemo(
    () =>
      finalCodes.map((code) => {
        const q = quotes.get(code)
        return {
          code,
          name: nameMap.get(code) ?? '',
          chgPct: q?.chg_pct ?? undefined,
          auctionChgPct: q?.auction_chg_pct ?? undefined,
          auctionAmount: q?.auction_amount ?? undefined,
          amount: q?.amount ?? undefined,
          speed4m: q?.speed_4m ?? undefined,
          mainInflow: q?.main_inflow ?? undefined,
          sealAmount: q?.seal_amount || undefined,
        }
      }),
    [finalCodes, quotes, nameMap],
  )

  const loading =
    groupsReq.loading || (sel?.kind === 'dynamic' && platesReq.loading)
  const error =
    groupsReq.error ||
    (sel?.kind === 'dynamic' ? platesReq.error || refreshError : '')

  return (
    <Cell title={title}>
      <div className="cell-toolbar">
        <select
          value={sel ? `${sel.kind}:${sel.name}` : ''}
          onChange={(e) => {
            const [kind, ...rest] = e.target.value.split(':')
            persist({ kind: kind as GroupSel['kind'], name: rest.join(':') })
          }}
        >
          <option value="self:自选股">自选股</option>
          {groups.length > 0 && (
            <optgroup label="自定义板块">
              {groups.map((g) => (
                <option key={g.group_id} value={`static:${g.name}`}>
                  {g.name}
                </option>
              ))}
            </optgroup>
          )}
          {plates.length > 0 && (
            <optgroup label="动态板块">
              {plates.map((p) => (
                <option key={p.name} value={`dynamic:${p.name}`}>
                  {p.name}
                </option>
              ))}
            </optgroup>
          )}
        </select>
        {sel?.kind === 'dynamic' && (
          <button
            className="mini-btn"
            onClick={onRefresh}
            disabled={refreshing || !activePlate}
            title={activePlate?.question ?? '云端未提供问财语句'}
          >
            {refreshing ? '刷新中…' : '↻ 刷新'}
          </button>
        )}
      </div>
      <StateBox
        loading={loading}
        error={error}
        empty={finalCodes.length === 0}
      >
        <StockTable
          key={sel ? `${sel.kind}:${sel.name}` : 'none'}
          rows={rows}
          onVisible={setVisibleCodes}
        />
      </StateBox>
    </Cell>
  )
}
