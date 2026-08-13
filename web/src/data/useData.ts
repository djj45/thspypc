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
 * delayMs>0 时延迟发请求：左栏列表用它在首屏 quote/depth 先上屏后再拉，避免
 * 与 MAIN 行情连接争用导致首屏变慢。
 */
export function useData<T>(
  fetcher: () => Promise<T>,
  deps: unknown[] = [],
  mode: DataMode = 'snapshot',
  delayMs = 0,
): DataState<T> {
  const [data, setData] = useState<T | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [tick, setTick] = useState(0)
  const fetcherRef = useRef(fetcher)
  fetcherRef.current = fetcher
  const firstRunRef = useRef(true)

  const refresh = useCallback(() => setTick((t) => t + 1), [])

  useEffect(() => {
    if (mode !== 'snapshot') return // poll/push 预留，首版不实现
    let alive = true
    let timer: ReturnType<typeof setTimeout> | undefined
    setLoading(true)
    const run = () => {
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
    }
    // 延迟只在首次挂载生效：首屏让 quote/depth 先上屏；之后 deps 变化
    // （如左栏切换排序键）立即发请求，不再每次白等 delayMs。
    const delay = firstRunRef.current ? delayMs : 0
    firstRunRef.current = false
    if (delay > 0) {
      timer = setTimeout(run, delay)
    } else {
      run()
    }
    return () => {
      alive = false
      if (timer !== undefined) clearTimeout(timer)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, tick, delayMs])

  return { data, loading, error, refresh }
}
