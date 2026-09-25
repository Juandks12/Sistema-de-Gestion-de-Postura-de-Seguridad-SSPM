import { Navigate, Route, Routes } from 'react-router-dom';
import { RequireAuth } from './auth/RequireAuth';
import { AppShell } from './components/layout/AppShell';
import { AccountPage } from './pages/AccountPage';
import { AssetDetailPage } from './pages/AssetDetailPage';
import { AssetsPage } from './pages/AssetsPage';
import { DashboardPage } from './pages/DashboardPage';
import { FindingsPage } from './pages/FindingsPage';
import { LoginPage } from './pages/LoginPage';
import { ScansPage } from './pages/ScansPage';
import { UsersPage } from './pages/UsersPage';

export function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route element={<RequireAuth />}>
        <Route element={<AppShell />}>
          <Route index element={<DashboardPage />} />
          <Route path="assets" element={<AssetsPage />} />
          <Route path="assets/:id" element={<AssetDetailPage />} />
          <Route path="findings" element={<FindingsPage />} />
          <Route path="scans" element={<ScansPage />} />
          <Route path="users" element={<UsersPage />} />
          <Route path="account" element={<AccountPage />} />
        </Route>
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
