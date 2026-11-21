import { Link, NavLink, Navigate, Outlet, useLocation } from 'react-router';
import { useAuth } from '../auth/AuthContext';
import { BuildBanner } from './BuildBanner';
import { btn } from './classes';

const navLink = ({ isActive }: { isActive: boolean }) =>
  `rounded-md px-3 py-1.5 text-sm font-medium ${isActive ? 'bg-slate-800 text-white' : 'text-slate-300 hover:bg-slate-800/60 hover:text-white'}`;

export function Layout() {
  const { authed, logout } = useAuth();
  const { pathname } = useLocation();
  if (!authed) return <Navigate to="/login" replace />;
  return (
    <>
      <BuildBanner />
      <header className="border-b border-slate-800 bg-slate-900">
        <div className="mx-auto flex max-w-7xl items-center gap-4 px-4 py-2">
          <Link to="/" className="text-lg font-bold tracking-tight text-sky-400">
            BSKG
          </Link>
          <nav aria-label="Main" className="flex gap-1">
            <NavLink to="/" className={({ isActive }) => navLink({ isActive: isActive || pathname.startsWith('/graph') })} end>
              Graph
            </NavLink>
            <NavLink to="/search" className={navLink}>
              Search
            </NavLink>
            <NavLink to="/stats" className={navLink}>
              Stats
            </NavLink>
          </nav>
          <button type="button" className={`${btn} ml-auto`} onClick={logout}>
            Sign out
          </button>
        </div>
      </header>
      <main className="mx-auto max-w-7xl px-4 py-6">
        <Outlet />
      </main>
    </>
  );
}
