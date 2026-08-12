import { api } from '../../api/endpoints'
import { useData } from '../../data/useData'
import { useStock } from '../../state/StockContext'
import type { Dxjl } from '../../types'

function fmtTime(us: number) {
  const d = new Date(us / 1000)
  const hh = String(d.getHours()).padStart(2, '0')
  const mm = String(d.getMinutes()).padStart(2, '0')
  const ss = String(d.getSeconds()).padStart(2, '0')
  return `${hh}:${mm}:${ss}`
}
function fmtAmt(n: number) {
  if (n >= 1e8) return (n / 1e8).toFixed(2) + '亿'
  if (n >= 1e4) return (n / 1e4).toFixed(1) + '万'
  return n.toFixed(0)
}

export function DxjlPanel() {
  const { code, setCode } = useStock()
  const { data, loading, error } = useData<Dxjl[]>(
    () => api.dxjlLatest(),
    [],
  )

  if (loading) return <div className="dim" style={{ padding: 8 }}>加载短线精灵…</div>
  if (error) return <div className="down" style={{ padding: 8 }}>{error}</div>
  if (!data || !data.length)
    return <div className="dim" style={{ padding: 8 }}>无短线精灵数据</div>

  return (
    <table>
      <thead>
        <tr>
          <th className="left">时间</th>
          <th className="left">代码</th>
          <th className="left">异动</th>
          <th>金额</th>
          <th>涨跌</th>
        </tr>
      </thead>
      <tbody>
        {data.slice(0, 200).map((d, i) => {
          const active = d.代码 === code
          return (
            <tr
              key={i}
              className={active ? 'selected' : ''}
              onClick={() => setCode(d.代码)}
            >
              <td className="left dim">{fmtTime(d.时间)}</td>
              <td className="left">{d.代码}</td>
              <td className="left">{d.异动类型}</td>
              <td>{d.金额 ? fmtAmt(d.金额) : '-'}</td>
              <td className={d.涨跌幅 > 0 ? 'up' : d.涨跌幅 < 0 ? 'down' : ''}>
                {d.涨跌幅 != null
                  ? (d.涨跌幅 >= 0 ? '+' : '') + d.涨跌幅.toFixed(2) + '%'
                  : '-'}
              </td>
            </tr>
          )
        })}
      </tbody>
    </table>
  )
}
