import { createContext, useContext, useState, type ReactNode } from 'react'

// 当前选中股票的行情概要（由 Header 拉 list_quotes 后回填，供盘口/信息条等共享）
export interface QuoteInfo {
  price?: number
  prevClose?: number
  open?: number
  high?: number
  low?: number
  vol?: number
  amount?: number
  chg?: number
  chgPct?: number
}

interface StockCtx {
  code: string
  setCode: (c: string) => void
  quote: QuoteInfo | null
  setQuote: (q: QuoteInfo | null) => void
}

const Ctx = createContext<StockCtx>({
  code: '600519',
  setCode: () => {},
  quote: null,
  setQuote: () => {},
})

export function StockProvider({ children }: { children: ReactNode }) {
  const [code, setCode] = useState('600519')
  const [quote, setQuote] = useState<QuoteInfo | null>(null)
  return (
    <Ctx.Provider value={{ code, setCode, quote, setQuote }}>
      {children}
    </Ctx.Provider>
  )
}

// eslint-disable-next-line react-refresh/only-export-components
export const useStock = () => useContext(Ctx)
