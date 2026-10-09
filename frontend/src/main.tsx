import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { installNetworkGuard } from '../../src/lib/networkGuard.ts'
import './index.css'
import App from './App.tsx'

installNetworkGuard()

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
