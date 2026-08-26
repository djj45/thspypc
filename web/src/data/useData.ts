import { useEffect, useRef, useState, useCallback } from 'react'
import {
  isRecoverableRequestError,
  recoverableRetryDelay,
} from '../api/client'

// 数据模式：snapshot=请求一次；poll=完成一次请求后定时刷新；push 由专用
// WebSocket hook 实现，这里仅保留类型入口。
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
  pollMs = 5_000,
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
    if (mode === 'push') return
    let alive = true
    let timer: ReturnType<typeof setTimeout> | undefined
    let failureCount = 0
    setLoading(true)
    const run = () => {
      let recoverableDelay: number | undefined
      fetcherRef
        .current()
        .then((d) => {
          if (alive) {
            failureCount = 0
            setData(d)
            setError('')
          }
        })
        .catch((e) => {
          if (!alive) return
          setError(e instanceof Error ? e.message : String(e))
          if (isRecoverableRequestError(e)) {
            failureCount += 1
            recoverableDelay = recoverableRetryDelay(failureCount)
          }
        })
        .finally(() => {
          if (!alive) return
          setLoading(false)
          // 以上一次完成为起点调度，慢请求不会叠加成并发轮询。snapshot
          // 首次遇到冷启动超时也会在后台自恢复；4xx 等确定错误不会重打。
          if (mode === 'poll' || recoverableDelay !== undefined) {
            const delay = recoverableDelay ?? Math.max(1_000, pollMs)
            timer = setTimeout(run, delay)
          }
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
  }, [...deps, tick, mode, delayMs, pollMs])

  return { data, loading, error, refresh }
}
