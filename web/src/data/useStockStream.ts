import { useEffect, useMemo, useRef, useState } from 'react'
import { api } from '../api/endpoints'
import type { MarketEvent } from '../types'

const MAX_EVENTS = 600
const STREAM_SWITCH_COALESCE_MS = 120

/**
 * Stable identity shared by the live stream and the recent 7169 replay.
 *
 * A trade sequence is normally unique, but live batch pushes can overlap and
 * the same trade can also be present in the initial replay window.  Include
 * the order/trade fields as well so an upstream sequence collision does not
 * collapse two genuinely different executions.
 */
export function marketEventIdentity(event: MarketEvent): string {
  const eventKind =
    event.event ||
    (event.seq != null && (event.price != null || event.dt10 != null)
      ? 'trade'
      : '')
  return [
    event.code,
    eventKind,
    event.timestamp ?? event.ts ?? event.dt1 ?? event.time ?? '',
    event.seq ?? '',
    event.trade_no ?? event.previous_trade_no ?? '',
    event.delegate_a ?? '',
    event.delegate_b ?? '',
    event.cancel_id ?? event.order_id ?? '',
    event.price ?? event.dt10 ?? '',
    event.volume ?? event.dt13 ?? '',
    event.direction ?? event.side ?? event.dt20 ?? '',
  ].join('\u0001')
}

function shouldDedupeEvent(event: MarketEvent): boolean {
  return (
    event.event === 'trade' ||
    event.event === 'cancel' ||
    event.event === 'order_queue'
  )
}

export function isRealtimeMarketSession(now = new Date()): boolean {
  const day = now.getDay()
  if (day === 0 || day === 6) return false
  const minute = now.getHours() * 60 + now.getMinutes()
  return (
    (minute >= 9 * 60 + 15 && minute <= 11 * 60 + 30) ||
    (minute >= 13 * 60 && minute <= 15 * 60)
  )
}

export function useStockStream(code: string, enabled = true) {
  const [events, setEvents] = useState<MarketEvent[]>([])
  const [sessionOpen, setSessionOpen] = useState(isRealtimeMarketSession)
  const [state, setState] = useState(
    enabled && isRealtimeMarketSession() ? 'connecting' : 'closed',
  )
  const [error, setError] = useState('')
  const generation = useRef(0)

  useEffect(() => {
    const refresh = () => setSessionOpen(isRealtimeMarketSession())
    refresh()
    const timer = window.setInterval(refresh, 30_000)
    return () => window.clearInterval(timer)
  }, [])

  useEffect(() => {
    const current = ++generation.current
    let socket: WebSocket | null = null
    let retryTimer = 0
    let stopped = false
    let attempt = 0
    setEvents([])
    const active = enabled && sessionOpen
    setState(active ? 'connecting' : 'closed')
    setError('')

    if (!active) return () => {}

    const open = async () => {
      if (stopped || generation.current !== current) return
      // 先完成该股票的 4214 注册，再建实时流。分时/盘口/超级盘口共用
      // 同一个浏览器侧 single-flight，不会在切股时并发争抢注册响应。
      await api.stockReady(code)
      if (stopped || generation.current !== current) return
      await new Promise((resolve) =>
        setTimeout(resolve, STREAM_SWITCH_COALESCE_MS),
      )
      if (stopped || generation.current !== current) return
      socket = new WebSocket(api.stockStreamUrl(code))
      socket.onopen = () => {
        setState('connected')
        setError('')
      }
      socket.onmessage = (message) => {
        if (generation.current !== current) return
        try {
          const event = JSON.parse(String(message.data)) as MarketEvent
          if (event.event === 'status') {
            setState(event.state ?? 'connected')
            if (event.state === 'subscribed') attempt = 0
            if (event.error) setError(event.error)
            return
          }
          // A market lane can still receive a delayed frame for a code whose
          // local unsubscribe grace period has not elapsed.  The server also
          // filters by code, but keep the browser boundary fail-closed so a
          // stale or malformed event can never enter the newly selected tape.
          if (event.code !== code) return
          setEvents((rows) => {
            if (
              shouldDedupeEvent(event) &&
              rows.some(
                (currentEvent) =>
                  marketEventIdentity(currentEvent) ===
                  marketEventIdentity(event),
              )
            ) {
              return rows
            }
            const next = [...rows, event]
            return next.length > MAX_EVENTS
              ? next.slice(next.length - MAX_EVENTS)
              : next
          })
        } catch (reason) {
          setError(reason instanceof Error ? reason.message : String(reason))
        }
      }
      socket.onerror = () => setError('实时通道连接异常')
      socket.onclose = () => {
        if (stopped || generation.current !== current) return
        setState('reconnecting')
        const delay = Math.min(1000 * 2 ** attempt, 10_000)
        attempt += 1
        retryTimer = window.setTimeout(open, delay)
      }
    }

    open()
    return () => {
      stopped = true
      window.clearTimeout(retryTimer)
      socket?.close()
    }
  }, [code, enabled, sessionOpen])

  const trades = useMemo(
    () => events.filter((event) => event.event === 'trade'),
    [events],
  )
  const latestDepth = useMemo(
    () => [...events].reverse().find((event) => event.event === 'depth'),
    [events],
  )
  const latestQueues = useMemo(() => {
    const result: Partial<Record<'buy' | 'sell', MarketEvent>> = {}
    for (let index = events.length - 1; index >= 0; index -= 1) {
      const event = events[index]
      if (event.event !== 'order_queue' || !event.side || result[event.side]) {
        continue
      }
      result[event.side] = event
      if (result.buy && result.sell) break
    }
    return result
  }, [events])

  return { events, trades, latestDepth, latestQueues, state, error }
}
