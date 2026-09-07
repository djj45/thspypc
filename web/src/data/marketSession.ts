import { useSyncExternalStore } from 'react'

// A 股交易时段感知：控制前端轮询节奏（盘中高频、休市降为 10 分钟心跳）。
// 用本地时间判断；法定假日离线无法判定，假日期间会按盘中节奏轮询
// （与旧行为一致，仅多耗一点请求），由低频心跳语义兜底其余时段。
export type MarketPhase = 'live' | 'idle'

/** 休市期心跳间隔：保持通道可自愈（时钟漂移、节假日误判），而非彻底停发 */
export const IDLE_POLL_MS = 10 * 60_000

export function marketPhase(now: Date = new Date()): MarketPhase {
  const day = now.getDay()
  if (day === 0 || day === 6) return 'idle'
  const m = now.getHours() * 60 + now.getMinutes()
  // 9:15 集合竞价起数据开始变动，11:30 午间休市，13:00 下午开盘，15:00 收盘
  if (m >= 555 && m <= 690) return 'live'
  if (m >= 780 && m <= 900) return 'live'
  return 'idle'
}

let cachedPhase: MarketPhase = marketPhase()
const listeners = new Set<() => void>()

// 模块级单例心跳：所有订阅者共享一次翻转通知，不随组件增减定时器
if (typeof window !== 'undefined') {
  window.setInterval(() => {
    const next = marketPhase()
    if (next === cachedPhase) return
    cachedPhase = next
    for (const notify of listeners) notify()
  }, 30_000)
}

function subscribe(notify: () => void): () => void {
  listeners.add(notify)
  return () => {
    listeners.delete(notify)
  }
}

export function useMarketPhase(): MarketPhase {
  return useSyncExternalStore(
    subscribe,
    () => cachedPhase,
    () => cachedPhase,
  )
}
