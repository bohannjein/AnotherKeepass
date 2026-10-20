import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import '@fontsource-variable/roboto-flex/wght.css'
import './index.css'
import App from './App.tsx'
import { backend } from './backend'

// unexpected UI errors go to the app log file (desktop), so problems can be traced later
window.addEventListener('error', e => backend.log('error', `${e.message} @ ${e.filename}:${e.lineno}`))
window.addEventListener('unhandledrejection', e => backend.log('error', `unhandled: ${String(e.reason)}`))

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
requestAnimationFrame(() => backend.log('info', `ui ready after ${Math.round(performance.now())} ms`))
