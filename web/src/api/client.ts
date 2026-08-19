// fetch 封装。dev 期同源走 vite proxy（/api → 127.0.0.1:8765），生产可同源挂 StaticFiles。

// 统一请求超时：后端偶发被上游死 socket 挂住（凌晨盘后时段尤甚）时，
// 中止请求并报错——否则通道闸门的在途位被永久占用，该数据通道彻底卡死，
// 直到刷新页面。Web 协议路由的单次总预算是 2s，6s 再兜一层，覆盖一次
// 当前股票的短暂恢复重试，但不允许旧股票长期占住前端通道闸门。
const REQUEST_TIMEOUT_MS = 6_000

export class ApiError extends Error {
  status: number
  constructor(path: string, status: number, body: string) {
    super(`${path}: HTTP ${status} ${body.slice(0, 120)}`)
    this.status = status
    this.name = 'ApiError'
  }
}

export async function getJson<T>(path: string): Promise<T> {
  const r = await fetch(path, {
    signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
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
