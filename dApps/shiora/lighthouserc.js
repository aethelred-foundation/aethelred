module.exports = {
  ci: {
    collect: {
      startServerCommand: 'npm --prefix dApps/shiora run start',
      startServerReadyPattern: 'ready on',
      url: [
        'http://localhost:3001/',
        'http://localhost:3001/insights',
        'http://localhost:3001/records',
      ],
      numberOfRuns: 3,
      settings: {
        preset: 'desktop',
      },
    },
    assert: {
      assertions: {
        'categories:performance': ['warn', { minScore: 0.8 }],
        'categories:accessibility': ['error', { minScore: 0.9 }],
        'categories:best-practices': ['warn', { minScore: 0.85 }],
        'categories:seo': ['warn', { minScore: 0.85 }],
      },
    },
    upload: {
      target: 'temporary-public-storage',
    },
  },
};
