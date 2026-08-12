import { api } from '../../api/endpoints'
import { useData } from '../../data/useData'
import { useStock } from '../../state/StockContext'
import type { Depth } from '../../types'

function fmtPrice(n: number) {
  return n.toFixed(2)
}
function fmtQty(n: number) {
  return n.toLocaleString('zh-CN', { maximumFractionDigits: 0 })
}
function fmtAmt(n: number) {
  if (n >= 1e8) return (n / 1e8).toFixed(2) + '亿'
  if (n >= 1e4) return (n / 1e4).toFixed(1) + '万'
  return n.toFixed(0)
}

export function DepthPanel() {
  const { code } = useStock()
  const { data, loading, error } = useData<Depth>(
    () => api.depth(code, 5),
    [code],
  )

  if (loading) return <div className="dim" style={{ padding: 8 }}>加载盘口…</div>
  if (error) return <div className="down" style={{ padding: 8 }}>{error}</div>
  if (!data || (!data.buy?.length && !data.sell?.length))
    return <div className="dim" style={{ padding: 8 }}>无盘口数据</div>

  const buy = data.buy ?? []
  const sell = data.sell ?? []

  return (
    <div style={{ padding: '4px 0' }}>
      {/* 卖盘倒序显示（卖五在上，卖一在下贴近买一）*/}
      {[...sell].reverse().map((lv) => (
        <div key={lv.level} className="depth-row">
          <span className="lvl">{lv.level}</span>
          <span className="down">{fmtPrice(lv.price)}</span>
          <span>{fmtQty(lv.qty)}</span>
          <span className="dim">{fmtAmt(lv.amount)}</span>
        </div>
      ))}
      <div
        style={{
          borderTop: '1px solid #333',
          borderBottom: '1px solid #333',
          padding: '3px 8px',
          margin: '2px 0',
          display: 'flex',
          justifyContent: 'space-between',
        }}
      >
        <span className="dim">现价 {data.fields ? '' : ''}</span>
        {data.seal_amount != null && data.seal_amount > 0 && (
          <span className="up">
            {data.seal_type === '跌停' ? '跌' : '涨'}停封单{' '}
            {fmtAmt(data.seal_amount)}
          </span>
        )}
      </div>
      {buy.map((lv) => (
        <div key={lv.level} className="depth-row">
          <span className="lvl">{lv.level}</span>
          <span className="up">{fmtPrice(lv.price)}</span>
          <span>{fmtQty(lv.qty)}</span>
          <span className="dim">{fmtAmt(lv.amount)}</span>
        </div>
      ))}
    </div>
  )
}
