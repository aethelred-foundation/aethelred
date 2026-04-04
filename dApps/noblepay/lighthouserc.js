module.exports = {
  ci: {
    collect: {
      startServerCommand: 'npm --prefix dApps/noblepay run start',
      startServerReadyPattern: 'Ready',
      url: [
        'http://localhost:3002/',
        'http://localhost:3002/payments',
        'http://localhost:3002/cross-chain',
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
