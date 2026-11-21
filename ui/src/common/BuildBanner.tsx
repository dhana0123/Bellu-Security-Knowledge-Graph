import { useAuth } from '../auth/AuthContext';
import { bannerMessage } from './banner';

export function BuildBanner() {
  const { graph } = useAuth();
  const msg = bannerMessage(graph);
  if (!msg) return null;
  return (
    <div role="status" className="banner">
      {msg}
    </div>
  );
}
