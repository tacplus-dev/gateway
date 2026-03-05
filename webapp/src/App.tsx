import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { ConfigProvider, theme } from 'antd';
import { AuthProvider } from './auth/AuthContext';
import { ProtectedRoute } from './auth/ProtectedRoute';
import { LoginPage } from './auth/LoginPage';
import { Layout } from './Layout';
import { HomePage } from './HomePage';
import { SentinelDashboard } from './modules/sentinel';
import { PolicyDashboard } from './modules/policy';

export default function App() {
  return (
    <ConfigProvider
      theme={{
        algorithm: theme.darkAlgorithm,
        token: {
          colorPrimary: '#006BFF',
          borderRadius: 6,
        },
      }}
    >
      <AuthProvider>
        <BrowserRouter>
          <Routes>
            <Route path="/login" element={<LoginPage />} />
            <Route
              element={
                <ProtectedRoute>
                  <Layout />
                </ProtectedRoute>
              }
            >
              <Route index element={<HomePage />} />
              <Route path="/sentinel" element={<SentinelDashboard />} />
              <Route path="/policy" element={<PolicyDashboard />} />
            </Route>
          </Routes>
        </BrowserRouter>
      </AuthProvider>
    </ConfigProvider>
  );
}
