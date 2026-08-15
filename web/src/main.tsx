import ReactDOM from 'react-dom/client'
import App from './App'
import './styles.css'

// 注意：开发环境刻意不用 React.StrictMode。StrictMode 会在 dev 下把每个
// effect 挂载两次，导致左栏/状态接口全部双发，冷启动时与个股请求争抢
// MAIN 连接和浏览器 6 连接上限（生产构建本就不双发）。
ReactDOM.createRoot(document.getElementById('root')!).render(<App />)
