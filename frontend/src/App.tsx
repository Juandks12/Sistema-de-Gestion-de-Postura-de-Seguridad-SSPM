import { Navigate, Route, Routes } from 'react-router-dom';
import { RequireAuth } from './auth/RequireAuth';
import { AppShell } from './components/layout/AppShell';
import { AccountPage } from './pages/AccountPage';
import { AlertsPage } from './pages/AlertsPage';
import { AssetDetailPage } from './pages/AssetDetailPage';
import { AssetsPage } from './pages/AssetsPage';
import { DashboardPage } from './pages/DashboardPage';
import { FindingsPage } from './pages/FindingsPage';
import { LoginPage } from './pages/LoginPage';
import { AuditPage } from './pages/AuditPage';
import { ForgotPasswordPage } from './pages/auth/ForgotPasswordPage';
import { InvitationPage } from './pages/auth/InvitationPage';
import { ResetPasswordPage } from './pages/auth/ResetPasswordPage';
import { ReportsPage } from './pages/ReportsPage';
import { ScansPage } from './pages/ScansPage';
import { SettingsPage } from './pages/SettingsPage';
import { UsersPage } from './pages/UsersPage';

export function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route path="/forgot-password" element={<ForgotPasswordPage />} />
      <Route path="/reset-password" element={<ResetPasswordPage />} />
      <Route path="/invitation" element={<InvitationPage />} />
      <Route element={<RequireAuth />}>
        <Route element={<AppShell />}>
          <Route index element={<DashboardPage />} />
          <Route path="assets" element={<AssetsPage />} />
          <Route path="assets/:id" element={<AssetDetailPage />} />
          <Route path="findings" element={<FindingsPage />} />
          <Route path="scans" element={<ScansPage />} />
          <Route path="alerts" element={<AlertsPage />} />
          <Route path="reports" element={<ReportsPage />} />
          <Route path="settings" element={<SettingsPage />} />
          <Route path="users" element={<UsersPage />} />
          <Route path="audit" element={<AuditPage />} />
          <Route path="account" element={<AccountPage />} />
        </Route>
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
