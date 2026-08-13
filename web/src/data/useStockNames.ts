import { api } from '../api/endpoints'
import { useData } from './useData'

// 全市场代码→名称映射：多个左栏面板共享同一份请求与缓存，避免重复拉 /api/stocks2。
let cache: Map<string, string> | null = null
let inflight: Promise<Map<string, string>> | null = null

export function fetchStockNameMap(): Promise<Map<string, string>> {
  if (cache) return Promise.resolve(cache)
  if (!inflight) {
    inflight = api
      .stocks2()
      .then((list) => {
        const map = new Map<string, string>()
        for (const item of list) {
          if (item.code && item.name) map.set(item.code, item.name)
        }
        cache = map
        return map
      })
      .catch((error) => {
        inflight = null
        throw error
      })
  }
  return inflight
}

export function useStockNames(): Map<string, string> {
  const { data } = useData<Map<string, string>>(
    () => fetchStockNameMap(),
    [],
    'snapshot',
    1500,
  )
  return data ?? new Map()
}
