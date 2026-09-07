import { useSyncExternalStore } from 'react'

/**
 * 超级盘口页的 实时/历史 全局开关。
 *
 * 模块级 store（useSyncExternalStore）：切换股票、切换视图都不重置，
 * 所有股票共用同一份模式；默认实时。
 */
export type SuperorderMode = 'live' | 'replay'

let mode: SuperorderMode = 'live'
const listeners = new Set<() => void>()

export function setSuperorderMode(next: SuperorderMode): void {
  if (next === mode) return
  mode = next
  listeners.forEach((listener) => listener())
}

function subscribe(listener: () => void): () => void {
  listeners.add(listener)
  return () => {
    listeners.delete(listener)
  }
}

export function useSuperorderMode(): [SuperorderMode, (next: SuperorderMode) => void] {
  const value = useSyncExternalStore(subscribe, () => mode)
  return [value, setSuperorderMode]
}
