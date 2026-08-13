import { useState, type ReactNode } from 'react'
import { useStock } from '../../state/StockContext'

export function Cell({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div className="cell">
      <div className="cell-title">{title}</div>
      <div className="cell-body">{children}</div>
    </div>
  )
}

export function StateBox({
  loading,
  error,
  empty,
  children,
}: {
  loading: boolean
  error: string
  empty: boolean
  children: ReactNode
}) {
  if (loading) return <div className="dim" style={{ padding: 8 }}>加载中…</div>
  if (error) return <div className="down" style={{ padding: 8 }}>{error.slice(0, 60)}</div>
  if (empty) return <div className="dim" style={{ padding: 8 }}>暂无数据</div>
  return <>{children}</>
}

export interface StockRowData {
  code: string
  name?: string
  value?: string
  valueCls?: string
}

// 可点选股票列表：点击行 → setCode；当前选中代码高亮；本地分页。
export function StockTable({
  rows,
  pageSize = 60,
}: {
  rows: StockRowData[]
  pageSize?: number
}) {
  const { code, setCode } = useStock()
  const [page, setPage] = useState(0)
  const pages = Math.max(1, Math.ceil(rows.length / pageSize))
  const cur = Math.min(page, pages - 1)
  const slice = rows.slice(cur * pageSize, (cur + 1) * pageSize)

  return (
    <>
      <div className="stock-list">
        {slice.map((row) => (
          <div
            key={row.code}
            className={row.code === code ? 'stock-row selected' : 'stock-row'}
            onClick={() => setCode(row.code)}
          >
            <span className="sc">{row.code}</span>
            <span className="sn" title={row.name ?? ''}>{row.name ?? ''}</span>
            <span className={row.valueCls ?? 'flat'}>{row.value ?? ''}</span>
          </div>
        ))}
      </div>
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
    </>
  )
}
