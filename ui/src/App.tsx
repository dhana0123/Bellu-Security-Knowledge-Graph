import { BrowserRouter, Route, Routes } from 'react-router';
import { AuthProvider } from './auth/AuthContext';
import { Login } from './auth/Login';
import { BuildBanner } from './common/BuildBanner';
import { Layout } from './common/Layout';
import { CveDetail } from './cve/CveDetail';
import { GraphView } from './graph/GraphView';
import { Search } from './search/Search';
import { Stats } from './stats/Stats';

export function App() {
  return (
    <BrowserRouter basename="/ui">
      <AuthProvider>
        <Routes>
          <Route
            path="/login"
            element={
              <>
                <BuildBanner />
                <Login />
              </>
            }
          />
          <Route element={<Layout />}>
            <Route index element={<Search />} />
            <Route path="/cve/:id" element={<CveDetail />} />
            <Route path="/graph/:type/:id" element={<GraphView />} />
            <Route path="/stats" element={<Stats />} />
            <Route path="*" element={<Search />} />
          </Route>
        </Routes>
      </AuthProvider>
    </BrowserRouter>
  );
}
