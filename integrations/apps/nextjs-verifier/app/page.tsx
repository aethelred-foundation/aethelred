export default function HomePage() {
  return (
    <main style={{ maxWidth: 960, margin: "0 auto", padding: "48px 24px" }}>
      <h1 style={{ margin: 0, fontSize: "2rem" }}>Aethelred Next.js Verifier Sample</h1>
      <p style={{ opacity: 0.85, lineHeight: 1.6 }}>
        This sample demonstrates native Aethelred verification wrappers for both Next.js App Router route
        handlers and legacy Pages API routes.
      </p>
      <ul style={{ lineHeight: 1.8 }}>
        <li><code>/api/health</code> (App Router)</li>
        <li><code>/api/verify</code> (App Router, wrapped)</li>
        <li><code>/api/legacy-verify</code> (Pages Router, wrapped)</li>
      </ul>
    </main>
  );
}
