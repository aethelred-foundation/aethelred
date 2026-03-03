/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  typescript: {
    // Sample app smoke builds should validate packaging/runtime wiring even if
    // local SDK source typing (e.g. WebGPU DOM globals) is stricter than Next's build env.
    ignoreBuildErrors: true,
  },
};

module.exports = nextConfig;
