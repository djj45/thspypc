// fetch 封装。dev 期同源走 vite proxy（/api → 127.0.0.1:8765），生产可同源挂 StaticFiles。

// 统一请求超时：后端偶发被上游死 socket 挂住（凌晨盘后时段尤甚）时，
// 中止请求并报错——否则通道闸门的在途位被永久占用，该数据通道彻底卡死，
// 直到刷新页面。Web 协议路由的单次总预算是 2s，6s 再兜一层，覆盖一次
// 当前股票的短暂恢复重试，但不允许旧股票长期占住前端通道闸门。
const REQUEST_TIMEOUT_MS = 6_000

const RECOVERABLE_RETRY_DELAYS_MS = [1_500, 4_000, 8_000, 15_000] as const

export class ApiError extends Error {
  status: number
  constructor(path: string, status: number, body: string) {
    super(`${path}: HTTP ${status} ${body.slice(0, 120)}`)
    this.status = status
    this.name = 'ApiError'
  }
}

/** 冷启动、短暂断网和网关慢尾可以原地恢复；业务参数/权限错误不应重打。 */
export function isRecoverableRequestError(error: unknown): boolean {
  if (error instanceof ApiError) {
    // Vite dev proxy 在目标后端尚未监听时会把 ECONNREFUSED 包装成 500；
    // 生产侧 5xx 同样属于可恢复慢尾。退避封顶 15s，不会形成紧密重打。
    return [408, 425, 429, 500, 502, 503, 504].includes(error.status)
  }
  return (
    error instanceof Error &&
    (error.name === 'TimeoutError' ||
      error.name === 'AbortError' ||
      /signal timed out|failed to fetch|networkerror|network request failed/i.test(
        error.message,
      ))
  )
}

/** failureCount 从 1 开始；持续故障时封顶 15 秒，避免请求风暴。 */
export function recoverableRetryDelay(failureCount: number): number {
  const index = Math.min(
    Math.max(1, failureCount) - 1,
    RECOVERABLE_RETRY_DELAYS_MS.length - 1,
  )
  return RECOVERABLE_RETRY_DELAYS_MS[index]
}

export async function getJson<T>(
  path: string,
  timeoutMs = REQUEST_TIMEOUT_MS,
): Promise<T> {
  const r = await fetch(path, {
    signal: AbortSignal.timeout(timeoutMs),
  })
  if (!r.ok) {
    const body = await r.text().catch(() => '')
    throw new ApiError(path, r.status, body)
  }
  return (await r.json()) as T
}

export async function postJson<T>(path: string): Promise<T> {
  const r = await fetch(path, {
    method: 'POST',
    signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
  })
  if (!r.ok) {
    const body = await r.text().catch(() => '')
    throw new ApiError(path, r.status, body)
  }
  return (await r.json()) as T
}
