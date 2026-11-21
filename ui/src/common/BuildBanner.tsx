import { useAuth } from '../auth/AuthContext';
import { bannerMessage } from './banner';

export function BuildBanner() {
  const { graph } = useAuth();
  const msg = bannerMessage(graph);
  if (!msg) return null;
  return (
    <div role="status" className="bg-amber-400 px-4 py-2 text-sm font-semibold text-slate-950">
      {msg}
    </div>
  );
}
