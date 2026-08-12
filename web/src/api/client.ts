// fetch 封装。dev 期同源走 vite proxy（/api → 127.0.0.1:8765），生产可同源挂 StaticFiles。

export class ApiError extends Error {
  status: number
  constructor(path: string, status: number, body: string) {
    super(`${path}: HTTP ${status} ${body.slice(0, 120)}`)
    this.status = status
    this.name = 'ApiError'
  }
}

export async function getJson<T>(path: string): Promise<T> {
  const r = await fetch(path)
  if (!r.ok) {
    const body = await r.text().catch(() => '')
    throw new ApiError(path, r.status, body)
  }
  return (await r.json()) as T
}

export async function postJson<T>(path: string): Promise<T> {
  const r = await fetch(path, { method: 'POST' })
  if (!r.ok) {
    const body = await r.text().catch(() => '')
    throw new ApiError(path, r.status, body)
  }
  return (await r.json()) as T
}
