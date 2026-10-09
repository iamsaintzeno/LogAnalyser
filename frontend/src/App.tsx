import { AppShell } from './components/layout/AppShell';
import { Dashboard } from './pages/Dashboard';
import { UploadPage } from './pages/UploadPage';
import { useAnalyzerStore } from './store/useAnalyzerStore';

export default function App() {
  const status = useAnalyzerStore((state) => state.status);
  return <AppShell>{status === 'done' ? <Dashboard /> : <UploadPage />}</AppShell>;
}
