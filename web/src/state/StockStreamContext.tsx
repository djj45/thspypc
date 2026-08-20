import { createContext, useContext, type ReactNode } from 'react'
import { useStockStream } from '../data/useStockStream'

type StockStreamState = ReturnType<typeof useStockStream>
const StreamContext = createContext<StockStreamState | null>(null)

export function StockStreamProvider({
  code,
  enabled = true,
  children,
}: {
  code: string
  enabled?: boolean
  children: ReactNode
}) {
  const stream = useStockStream(code, enabled)
  return <StreamContext.Provider value={stream}>{children}</StreamContext.Provider>
}

export function useSharedStockStream(): StockStreamState {
  const value = useContext(StreamContext)
  if (value === null) {
    throw new Error('useSharedStockStream 必须在 StockStreamProvider 内使用')
  }
  return value
}
