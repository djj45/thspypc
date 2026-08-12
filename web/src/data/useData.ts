import { useEffect, useRef, useState, useCallback } from 'react'

// 数据模式：snapshot=请求一次；poll=定时轮询（预留）；push=WebSocket 推送（预留）。
// 首版只实现 snapshot，poll/push 接口预留，后续接同花顺订阅推送。
export type DataMode = 'snapshot' | 'poll' | 'push'

export interface DataState<T> {
  data: T | null
  loading: boolean
  error: string
  refresh: () => void
}

/**
 * snapshot 数据 hook：mount 或 deps 变化时请求一次，返回 {data, loading, error, refresh}。
 * fetcher 闭包应通过 deps 声明依赖，避免 stale。
 */
export function useData<T>(
  fetcher: () => Promise<T>,
  deps: unknown[] = [],
  mode: DataMode = 'snapshot',
): DataState<T> {
  const [data, setData] = useState<T | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [tick, setTick] = useState(0)
  const fetcherRef = useRef(fetcher)
  fetcherRef.current = fetcher

  const refresh = useCallback(() => setTick((t) => t + 1), [])

  useEffect(() => {
    if (mode !== 'snapshot') return // poll/push 预留，首版不实现
    let alive = true
    setLoading(true)
    fetcherRef
      .current()
      .then((d) => {
        if (alive) {
          setData(d)
          setError('')
        }
      })
      .catch((e) => {
        if (alive) setError(e instanceof Error ? e.message : String(e))
      })
      .finally(() => {
        if (alive) setLoading(false)
      })
    return () => {
      alive = false
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, tick])

  return { data, loading, error, refresh }
}
