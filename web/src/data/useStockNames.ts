import { useEffect, useState } from 'react'
import { api } from '../api/endpoints'

// 全市场代码→名称映射：多个左栏面板共享同一份请求与缓存，避免重复拉 /api/stocks2。
// 只有拿到非空名称表才进入长期缓存；后端冷启动偶尔会先返回「代码有、名称为空」，
// 此时不缓存并在 3s 后重试，直到后端名称源就绪（后端也会自愈磁盘缓存）。
let cache: Map<string, string> | null = null
let inflight: Promise<Map<string, string>> | null = null

export function fetchStockNameMap(): Promise<Map<string, string>> {
  if (cache && cache.size > 0) return Promise.resolve(cache)
  if (!inflight) {
    inflight = api
      .stocks2()
      .then((list) => {
        const map = new Map<string, string>()
        for (const item of list) {
          if (item.code && item.name) map.set(item.code, item.name)
        }
        if (map.size > 0) cache = map
        return map
      })
      .catch((error) => {
        throw error
      })
      .finally(() => {
        inflight = null
      })
  }
  return inflight
}

const EMPTY_MAP = new Map<string, string>()
const NAME_RETRY_MS = 3000

export function useStockNames(): Map<string, string> {
  const [names, setNames] = useState<Map<string, string>>(EMPTY_MAP)
  const [attempt, setAttempt] = useState(0)

  useEffect(() => {
    let alive = true
    let timer: ReturnType<typeof setTimeout> | undefined
    fetchStockNameMap()
      .then((map) => {
        if (!alive) return
        setNames(map)
        // 空名称表通常是后端冷启动竞态，稍后重试一次；成功后不再重试。
        if (map.size === 0) {
          timer = setTimeout(() => {
            if (alive) setAttempt((value) => value + 1)
          }, NAME_RETRY_MS)
        }
      })
      .catch(() => {
        if (!alive) return
        setNames(EMPTY_MAP)
        timer = setTimeout(() => {
          if (alive) setAttempt((value) => value + 1)
        }, NAME_RETRY_MS)
      })
    return () => {
      alive = false
      if (timer !== undefined) clearTimeout(timer)
    }
  }, [attempt])

  return names
}
