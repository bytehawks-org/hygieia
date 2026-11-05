/** Static export: served by hygeia-api, no Node at runtime. */
const dev = process.env.NODE_ENV === 'development';

/** @type {import('next').NextConfig} */
const config = {
  output: 'export',
  trailingSlash: true, // /rules/ -> rules/index.html, which ServeDir resolves
  images: { unoptimized: true },
  reactStrictMode: true,
  poweredByHeader: false,
  // `next dev` only: proxy the API (a production build is same-origin with hygeia-api)
  ...(dev ? { async rewrites() { return [{ source: '/v1/:path*', destination: 'http://127.0.0.1:8080/v1/:path*' }]; } } : {}),
};
export default config;
