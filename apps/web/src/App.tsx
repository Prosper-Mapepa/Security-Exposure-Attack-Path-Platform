import { Navigate, Route, Routes } from 'react-router-dom';
import { Shell } from './components/Shell';
import { PageLoading } from './components/ui';
import { useAuth } from './lib/auth';
import { AssetDetailPage, AssetsPage } from './pages/AssetsPages';
import { ForgotPage, LoginPage, RegisterPage, ResetPage } from './pages/AuthPages';
import { HowItWorksPage } from './pages/HowItWorksPage';
import { LandingPage } from './pages/LandingPage';
import { DashboardPage } from './pages/DashboardPage';
import { DeveloperPage, FindingDetailPage, FindingsPage } from './pages/FindingsPages';
import { AttackPathsPage, AuditPage, EventsPage, IncidentsPage, RemediationsPage, ReportsPage, ScanDetailPage, ScansPage, SettingsPage } from './pages/OperationsPages';

function Protected() {
  const { user, loading } = useAuth();
  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-ink">
        <PageLoading label="Checking session" />
      </div>
    );
  }
  if (!user) return <Navigate to="/login" replace />;
  return <Shell />;
}

function Home() {
  const { user, loading } = useAuth();
  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-ink">
        <PageLoading label="Checking session" />
      </div>
    );
  }
  if (user) return <Navigate to="/dashboard" replace />;
  return <LandingPage />;
}

export function App() {
  return (
    <Routes>
      <Route path="/" element={<Home />} />
      <Route path="/how-it-works" element={<HowItWorksPage />} />
      <Route path="/login" element={<LoginPage />} />
      <Route path="/register" element={<RegisterPage />} />
      <Route path="/forgot-password" element={<ForgotPage />} />
      <Route path="/reset-password" element={<ResetPage />} />
      <Route element={<Protected />}>
        <Route path="/dashboard" element={<DashboardPage />} />
        <Route path="/assets" element={<AssetsPage />} />
        <Route path="/assets/:id" element={<AssetDetailPage />} />
        <Route path="/findings" element={<FindingsPage />} />
        <Route path="/findings/:id" element={<FindingDetailPage />} />
        <Route path="/scans" element={<ScansPage />} />
        <Route path="/scans/:id" element={<ScanDetailPage />} />
        <Route path="/attack-paths" element={<AttackPathsPage />} />
        <Route path="/incidents" element={<IncidentsPage />} />
        <Route path="/remediations" element={<RemediationsPage />} />
        <Route path="/events" element={<EventsPage />} />
        <Route path="/developer" element={<DeveloperPage />} />
        <Route path="/reports" element={<ReportsPage />} />
        <Route path="/audit" element={<AuditPage />} />
        <Route path="/settings" element={<SettingsPage />} />
      </Route>
      <Route path="*" element={<Navigate to="/dashboard" replace />} />
    </Routes>
  );
}
