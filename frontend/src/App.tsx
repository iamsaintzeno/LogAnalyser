import { AppShell } from './components/layout/AppShell';
import { Dashboard } from './pages/Dashboard';
import { UploadPage } from './pages/UploadPage';
import { StateLabPage } from './pages/StateLabPage';
import { useAnalyzerStore } from './store/useAnalyzerStore';

export default function App() {
  const status = useAnalyzerStore((state) => state.status);
  const showStateLab = import.meta.env.DEV && new URLSearchParams(window.location.search).get('lab') === '1';
  if (showStateLab) return <AppShell><StateLabPage /></AppShell>;
  return <AppShell>{status === 'done' ? <Dashboard /> : <UploadPage />}</AppShell>;
}
