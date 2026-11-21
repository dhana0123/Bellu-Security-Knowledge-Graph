import { Link, Navigate, Outlet } from 'react-router';
import { useAuth } from '../auth/AuthContext';
import { BuildBanner } from './BuildBanner';

export function Layout() {
  const { authed, logout } = useAuth();
  if (!authed) return <Navigate to="/login" replace />;
  return (
    <>
      <BuildBanner />
      <header className="nav">
        <strong>BSKG</strong>
        <nav aria-label="Main">
          <Link to="/">Search</Link> <Link to="/stats">Stats</Link>
        </nav>
        <button type="button" onClick={logout}>
          Sign out
        </button>
      </header>
      <main>
        <Outlet />
      </main>
    </>
  );
}
