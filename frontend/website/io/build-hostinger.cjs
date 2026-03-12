const fs = require('fs');
const path = require('path');

const sourceDir = __dirname;
const websiteRoot = path.resolve(sourceDir, '..');
const outputDir = path.join(sourceDir, 'hostinger-public_html');
const zipName = 'aethelred-io-hostinger-public_html.zip';

const htmlFiles = fs.readdirSync(sourceDir).filter((file) => file.endsWith('.html'));
const pageMap = new Map(
  htmlFiles.map((file) => {
    const stem = path.basename(file, '.html');
    const route = stem === 'index' ? '/' : `/${stem}.html`;
    return [file, route];
  })
);

const externalOrgMap = new Map([
  ['../org/index.html', 'https://www.aethelred.org/'],
  ['../org/network.html', 'https://www.aethelred.org/network'],
  ['../org/token.html', 'https://www.aethelred.org/token'],
  ['../org/governance.html', 'https://www.aethelred.org/governance'],
  ['../org/privacy.html', 'https://www.aethelred.org/privacy'],
  ['../org/terms.html', 'https://www.aethelred.org/terms'],
  ['../org/cookies.html', 'https://www.aethelred.org/cookies'],
  ['../org/investors.html', 'https://www.aethelred.org/investors'],
  ['../org/nodes.html', 'https://www.aethelred.org/nodes']
]);

const hostingerHtaccess = `Options -MultiViews
DirectoryIndex index.html

<IfModule mod_rewrite.c>
RewriteEngine On

RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteCond %{DOCUMENT_ROOT}/$1.html -f
RewriteRule ^(.+?)/?$ $1.html [L]
</IfModule>

ErrorDocument 404 /404.html

<IfModule mod_expires.c>
ExpiresActive On
ExpiresByType text/html "access plus 0 seconds"
ExpiresByType text/plain "access plus 0 seconds"
ExpiresByType application/xml "access plus 0 seconds"
ExpiresByType text/xml "access plus 0 seconds"
ExpiresByType text/css "access plus 1 month"
ExpiresByType application/javascript "access plus 1 month"
ExpiresByType text/javascript "access plus 1 month"
ExpiresByType image/svg+xml "access plus 1 month"
ExpiresByType image/png "access plus 1 month"
ExpiresByType image/jpeg "access plus 1 month"
ExpiresByType font/woff2 "access plus 1 year"
</IfModule>

<IfModule mod_headers.c>
  <FilesMatch "\\.(html|xml|txt)$">
    Header set Cache-Control "public, max-age=0, must-revalidate"
  </FilesMatch>
  <FilesMatch "\\.(css|js|woff2|svg|png|jpg|jpeg)$">
    Header set Cache-Control "public, max-age=2592000, immutable"
  </FilesMatch>
  Header always set X-Content-Type-Options "nosniff"
  Header always set Referrer-Policy "strict-origin-when-cross-origin"
  Header always set X-Frame-Options "SAMEORIGIN"
  Header always set Permissions-Policy "camera=(), microphone=(), geolocation=()"
</IfModule>

<IfModule mod_deflate.c>
AddOutputFilterByType DEFLATE text/html text/plain text/css text/javascript application/javascript application/json application/xml image/svg+xml
</IfModule>
`;

function ensureDir(dirPath) {
  fs.mkdirSync(dirPath, { recursive: true });
}

function copyFile(sourcePath, destPath) {
  ensureDir(path.dirname(destPath));
  fs.copyFileSync(sourcePath, destPath);
}

function copyDir(sourcePath, destPath) {
  ensureDir(destPath);
  for (const entry of fs.readdirSync(sourcePath, { withFileTypes: true })) {
    const src = path.join(sourcePath, entry.name);
    const dst = path.join(destPath, entry.name);
    if (entry.isDirectory()) {
      copyDir(src, dst);
    } else if (entry.isFile()) {
      copyFile(src, dst);
    }
  }
}

function rewriteHostedMetadata(content) {
  let next = content;
  for (const file of htmlFiles) {
    const stem = path.basename(file, '.html');
    if (stem === 'index') {
      continue;
    }
    const cleanUrl = `https://www.aethelred.io/${stem}`;
    const htmlUrl = `https://www.aethelred.io/${stem}.html`;
    next = next.replace(new RegExp(`${cleanUrl}(?=(?:#|\"|<|\\\\s))`, 'g'), htmlUrl);
  }
  return next;
}

function rewriteHref(value) {
  if (externalOrgMap.has(value)) {
    return externalOrgMap.get(value);
  }

  const hashIndex = value.indexOf('#');
  const pathPart = hashIndex === -1 ? value : value.slice(0, hashIndex);
  const hashPart = hashIndex === -1 ? '' : value.slice(hashIndex);

  if (pageMap.has(pathPart)) {
    return `${pageMap.get(pathPart)}${hashPart}`;
  }

  return value;
}

function makeHtmlHostingerReady(content) {
  let next = content;

  next = next.replace(/href="(\.\.\/org\/[^"]+)"/g, (_, href) => `href="${rewriteHref(href)}"`);

  next = next.replace(/href="([^"]+\.html(?:#[^"]*)?)"/g, (match, href) => {
    const rewritten = rewriteHref(href);
    return rewritten === href ? match : `href="${rewritten}"`;
  });

  next = next.replace(/href="styles\.css"/g, 'href="/styles.css"');
  next = next.replace(/src="site\.js"/g, 'src="/site.js"');
  next = next.replace(/href="aethelred-mark\.png"/g, 'href="/aethelred-mark.png"');
  next = next.replace(/src="aethelred-mark\.png"/g, 'src="/aethelred-mark.png"');
  next = next.replace(/(href|src)="assets\//g, '$1="/assets/');
  next = next.replace(/(href|src)="og-image\.jpg"/g, '$1="/og-image.jpg"');

  if (!next.includes('site.webmanifest')) {
    next = next.replace(
      /<link rel="apple-touch-icon" href="\/aethelred-mark\.png">/,
      '<link rel="apple-touch-icon" href="/aethelred-mark.png">\n  <link rel="manifest" href="/site.webmanifest">\n  <link rel="preload" href="/assets/fonts/manrope-latin.woff2" as="font" type="font/woff2" crossorigin>\n  <link rel="preload" href="/assets/fonts/jetbrains-mono-latin.woff2" as="font" type="font/woff2" crossorigin>'
    );
  }

  return rewriteHostedMetadata(next);
}

function makeCssHostingerReady(content) {
  return content.replace(/\.\.\/assets\/fonts\//g, '/assets/fonts/');
}

function makeSitemapHostingerReady(content) {
  let next = content;
  for (const file of htmlFiles) {
    const stem = path.basename(file, '.html');
    if (stem === 'index') {
      continue;
    }
    next = next.replace(
      new RegExp(`https://www\\.aethelred\\.io/${stem}(?=<)`, 'g'),
      `https://www.aethelred.io/${stem}.html`
    );
  }
  return next;
}

function build() {
  fs.rmSync(outputDir, { recursive: true, force: true });
  ensureDir(outputDir);

  const fontSourceDir = path.join(websiteRoot, 'assets', 'fonts');
  const logoSourceDir = path.join(sourceDir, 'assets', 'logos');

  copyDir(fontSourceDir, path.join(outputDir, 'assets', 'fonts'));
  copyDir(logoSourceDir, path.join(outputDir, 'assets', 'logos'));

  copyFile(path.join(sourceDir, 'aethelred-mark.png'), path.join(outputDir, 'aethelred-mark.png'));
  copyFile(path.join(sourceDir, 'og-image.jpg'), path.join(outputDir, 'og-image.jpg'));
  copyFile(path.join(sourceDir, 'robots.txt'), path.join(outputDir, 'robots.txt'));
  const sitemap = fs.readFileSync(path.join(sourceDir, 'sitemap.xml'), 'utf8');
  fs.writeFileSync(path.join(outputDir, 'sitemap.xml'), makeSitemapHostingerReady(sitemap));
  copyFile(path.join(sourceDir, 'site.webmanifest'), path.join(outputDir, 'site.webmanifest'));

  const css = fs.readFileSync(path.join(sourceDir, 'styles.css'), 'utf8');
  fs.writeFileSync(path.join(outputDir, 'styles.css'), makeCssHostingerReady(css));

  copyFile(path.join(sourceDir, 'site.js'), path.join(outputDir, 'site.js'));
  fs.writeFileSync(path.join(outputDir, '.htaccess'), hostingerHtaccess);

  for (const file of htmlFiles) {
    const sourcePath = path.join(sourceDir, file);
    const html = fs.readFileSync(sourcePath, 'utf8');
    fs.writeFileSync(path.join(outputDir, file), makeHtmlHostingerReady(html));
  }

  const bundleNote = [
    'Hostinger upload target: public_html',
    'Generated from the io site build script.',
    `Upload the contents of this folder or the ${zipName} archive to Hostinger.`,
    'The bundle is flattened for simple hosting: one .html file per page with direct .html links.',
    'The .htaccess file keeps caching, compression, the 404 page, and optional clean-route fallback.'
  ].join('\n');

  fs.writeFileSync(path.join(outputDir, 'README.txt'), bundleNote);
}

build();
