import type { RouteObject } from 'react-router';
import { Login } from './auth/Login';
import { BuildBanner } from './common/BuildBanner';
import { Layout } from './common/Layout';
import { CveDetail } from './cve/CveDetail';
import { AtlasTechniquePage, AttackPatternPage, PackagePage, TechniquePage } from './entities/EntityPages';
import { GraphView } from './graph/GraphView';
import { Search } from './search/Search';
import { Stats } from './stats/Stats';

/** The app's routes. The index and the catch-all show the whole-graph overview; Search lives at /search. */
export const appRoutes: RouteObject[] = [
  { path: '/login', 
    element: (
      <>
        <BuildBanner />
        <Login />
      </>
    ),
  },
  {
    element: <Layout />,
    children: [
      { index: true, element: <GraphView /> },
      { path: '/search', element: <Search /> },
      { path: '/cve/:id', element: <CveDetail /> },
      { path: '/package/:purl', element: <PackagePage /> },
      { path: '/attack-pattern/:id', element: <AttackPatternPage /> },
      { path: '/technique/:id', element: <TechniquePage /> },
      { path: '/atlas-technique/:id', element: <AtlasTechniquePage /> },
      { path: '/graph', element: <GraphView /> },
      { path: '/graph/:type/:id', element: <GraphView /> },
      { path: '/stats', element: <Stats /> },
      { path: '*', element: <GraphView /> },
    ],
  },
];
