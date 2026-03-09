import type { VercelConfig } from '@vercel/config/v1';

export const config: VercelConfig = {
  crons: [
    {
      path: '/api/crons/cleanup/database',
      schedule: '0 2 * * *',
    },
    // {
    //  path: '/api/crons/trigger-update-jobs',
    //  // schedule: '*/30 * * * *',
    //  schedule: '12 */2 * * *',
    // },
    {
      path: '/api/crons/trigger-sync-projects',
      // schedule: '23 */6 * * *',
      schedule: '23 6 * * *',
    },
    {
      path: '/api/crons/trigger-scan-vulnerabilities',
      schedule: '0 12 * * *',
    },
  ],
  // https://turborepo.dev/docs/reference/turbo-ignore
  // https://community.vercel.com/t/monorepo-initiates-deployment-even-if-skip-built-is-enabled/27233/4
  ignoreCommand: 'npx turbo-ignore && node vercel-ignore-step.js',
  git: {
    deploymentEnabled: {
      'dependabot/*': false,
    },
  },
  github: {
    autoJobCancelation: true,
  },
};
