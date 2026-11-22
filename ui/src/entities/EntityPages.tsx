import { Link, useParams } from 'react-router';
import { useAuth } from '../auth/AuthContext';
import { link } from '../common/classes';
import { EntityPage, LinkList } from '../common/EntityPage';
import { ExternalLink } from '../common/ExternalLink';
import { SeverityBadge } from '../common/SeverityBadge';
import { useRequest } from '../common/useRequest';
import { atlasTechniquePath, attackPatternPath, cvePath, graphPath, techniquePath } from '../cve/links';
import { repoPath } from '../graph/style';

export function PackagePage() {
  const { purl = '' } = useParams();
  const { client } = useAuth();
  const req = useRequest((s) => client.package(purl, s), [client, purl]);
  const d = req.data;
  return (
    <EntityPage title={purl} graphType="Package" graphKey={purl} loading={req.loading} error={req.error} properties={d?.package}>
      {d && (
        <>
          <LinkList
            title="Vulnerabilities"
            items={d.vulnerabilities}
            render={(v) => (
              <>
                <Link className={link} to={cvePath(v.cveID)}>{v.cveID}</Link> <SeverityBadge score={v.v3baseScore} />
                {v.publishedDate ? ` published ${v.publishedDate}` : ''}
              </>
            )}
          />
          <LinkList
            title="Repositories"
            items={d.repositories}
            render={(r) => (
              <>
                <ExternalLink href={r.url}>{repoPath(r.url)}</ExternalLink>
                {r.host ? ` (${r.host})` : ''}
                {' · '}
                <Link className={link} to={graphPath('Repository', r.url)}>Open in graph</Link>
              </>
            )}
          />
        </>
      )}
    </EntityPage>
  );
}
export function AttackPatternPage() {
  const { id = '' } = useParams();
  const { client } = useAuth();
  const req = useRequest((s) => client.attackPattern(id, s), [client, id]);
  const d = req.data;
  return (
    <EntityPage title={id} graphType="AttackPattern" graphKey={id} loading={req.loading} error={req.error} properties={d?.attackPattern}>
      {d && (
        <>
          <LinkList
            title="Weaknesses"
            items={d.weaknesses}
            render={(w) => (
              <>
                <Link className={link} to={graphPath('Weakness', w.cweID)}>{w.cweID}</Link>
                {w.cweName ? ` ${w.cweName}` : ''}
              </>
            )}
          />
          <LinkList
            title="ATT&CK techniques"
            items={d.techniques}
            render={(t) => (
              <>
                <Link className={link} to={techniquePath(t.attackID)}>{t.attackID}</Link>
                {t.name ? ` ${t.name}` : ''}
              </>
            )}
          />
        </>
      )}
    </EntityPage>
  );
}
export function TechniquePage() {
  const { id = '' } = useParams();
  const { client } = useAuth();
  const req = useRequest((s) => client.technique(id, s), [client, id]);
  const d = req.data;
  return (
    <EntityPage title={id} graphType="Technique" graphKey={id} loading={req.loading} error={req.error} properties={d?.technique}>
      {d && (
        <>
          <LinkList
            title="Attack patterns"
            items={d.attackPatterns}
            render={(a) => (
              <>
                <Link className={link} to={attackPatternPath(a.capecID)}>{a.capecID}</Link>
                {a.name ? ` ${a.name}` : ''}
              </>
            )}
          />
          <LinkList
            title="ATLAS techniques"
            items={d.atlasTechniques}
            render={(a) => (
              <>
                <Link className={link} to={atlasTechniquePath(a.atlasID)}>{a.atlasID}</Link>
                {a.name ? ` ${a.name}` : ''}
              </>
            )}
          />
        </>
      )}
    </EntityPage>
  );
}
export function AtlasTechniquePage() {
  const { id = '' } = useParams();
  const { client } = useAuth();
  const req = useRequest((s) => client.atlasTechnique(id, s), [client, id]);
  const d = req.data;
  return (
    <EntityPage title={id} graphType="AtlasTechnique" graphKey={id} loading={req.loading} error={req.error} properties={d?.atlasTechnique}>
      {d && (
        <LinkList
          title="ATT&CK techniques"
          items={d.techniques}
          render={(t) => (
            <>
              <Link className={link} to={techniquePath(t.attackID)}>{t.attackID}</Link>
              {t.name ? ` ${t.name}` : ''}
            </>
          )}
        />
      )}
    </EntityPage>
  );
}
