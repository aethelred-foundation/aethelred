/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  swcMinify: true,

  // Environment variables
  env: {
    NEXT_PUBLIC_RPC_URL: process.env.NEXT_PUBLIC_RPC_URL || 'https://rpc.mainnet.aethelred.org',
    NEXT_PUBLIC_API_URL: process.env.NEXT_PUBLIC_API_URL || 'https://api.mainnet.aethelred.org',
  },

  // Image optimization
  images: {
    domains: ['aethelred.org'],
  },

  // Webpack configuration
  webpack: (config, { isServer }) => {
    // Add custom webpack plugins or loaders here
    return config;
  },

  // Headers for security
  async headers() {
    return [
      {
        source: '/:path*',
        headers: [
          {
            key: 'X-Frame-Options',
            value: 'DENY',
          },
          {
            key: 'X-Content-Type-Options',
            value: 'nosniff',
          },
          {
            key: 'X-XSS-Protection',
            value: '1; mode=block',
          },
          {
            key: 'Referrer-Policy',
            value: 'strict-origin-when-cross-origin',
          },
          {
            key: 'Content-Security-Policy',
            value: [
              `default-src 'self'`,
              `base-uri 'self'`,
              `frame-ancestors 'none'`,
              `object-src 'none'`,
              `img-src 'self' data: https:`,
              `font-src 'self' data: https:`,
              `style-src 'self' 'unsafe-inline'`,
              `script-src 'self' 'unsafe-inline'`,
              `connect-src 'self' https: wss:`,
              `form-action 'self'`,
            ].join('; '),
          },
        ],
      },
    ];
  },

  // Redirects
  async redirects() {
    return [
      {
        source: '/explorer',
        destination: '/',
        permanent: true,
      },
    ];
  },
};

module.exports = nextConfig;
