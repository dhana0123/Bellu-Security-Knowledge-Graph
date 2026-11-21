import { BrowserRouter, useRoutes } from 'react-router';
import { AuthProvider } from './auth/AuthContext';
import { appRoutes } from './routes';

function AppRoutes() {
  return useRoutes(appRoutes);
}

export function App() {
  return (
    <BrowserRouter basename="/ui">
      <AuthProvider>
        <AppRoutes />
      </AuthProvider>
    </BrowserRouter>
  );
}
