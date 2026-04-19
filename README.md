# Keikomik Mirror Proxy

Full reverse-proxy mirror untuk **keikomik.web.id** dengan optimasi SEO lengkap. Support deploy ke **Railway**, **Render**, **VPS**, atau platform apapun yang support Node.js / Docker.

## Fitur SEO Anti-Duplikat

| Masalah GSC | Solusi |
|---|---|
| **Duplikat, Google memilih versi kanonis yang berbeda** | Semua `<link rel="canonical">` di-rewrite ke domain mirror. Jika tidak ada canonical tag, otomatis ditambahkan. |
| **Tidak ditemukan (404)** | Status code 404 diteruskan apa adanya dari origin, tidak di-mask. Google bisa de-index dengan benar. |
| **Halaman dengan pengalihan** | Semua redirect `Location` header di-rewrite ke domain mirror, sehingga tidak redirect ke origin. |
| **Data terstruktur Breadcrumb** | JSON-LD `<script type="application/ld+json">` di-parse dan semua URL origin di-rewrite ke mirror. |
| **Data terstruktur tidak dapat diurai** | JSON-LD di-validate setelah rewrite. Jika parse gagal, tetap dilakukan text replacement. |
| **Sitemap** | Semua URL di sitemap.xml di-rewrite ke domain mirror. robots.txt juga di-rewrite directive Sitemap-nya. |

## Yang Di-Rewrite

- `<link rel="canonical">` dan `<link rel="alternate">`
- `<meta property="og:url">`, `og:image`, `twitter:url`, `twitter:image`
- Semua `href` dan `src` yang mengarah ke origin
- `srcset` attributes
- `<form action>`
- JSON-LD structured data (termasuk Breadcrumb, Article, dll)
- Inline `<script>` dan `<style>` yang mengandung URL origin
- CSS dan JS files yang mengandung URL origin
- Sitemap XML (semua `<loc>` dan `<url>`)
- robots.txt (directive `Sitemap:`)
- Redirect `Location` header
- Response header yang mengandung URL origin

## Environment Variables

| Variable | Default | Keterangan |
|---|---|---|
| `ORIGIN_HOST` | `keikomik.web.id` | Domain website yang di-mirror |
| `ORIGIN_PROTOCOL` | `https` | Protocol origin |
| `MIRROR_HOST` | *(dari request Host header)* | **WAJIB diisi** — domain mirror kamu |
| `MIRROR_PROTOCOL` | `https` | Protocol mirror |
| `PORT` | `3000` | Port server |

> **PENTING**: Set `MIRROR_HOST` ke domain mirror kamu (contoh: `keikomik-mirror.up.railway.app`) agar canonical tag dan semua URL mengarah ke domain yang benar.

## Deploy

### Railway

1. Push repo ini ke GitHub
2. Buat project baru di [Railway](https://railway.app)
3. Connect repo GitHub
4. Set environment variables:
   ```
   MIRROR_HOST=keikomik-xxx.up.railway.app
   MIRROR_PROTOCOL=https
   ```
5. Deploy otomatis

### Render

1. Push repo ini ke GitHub
2. Buat Web Service baru di [Render](https://render.com)
3. Connect repo GitHub, Render akan detect `render.yaml`
4. Set `MIRROR_HOST` di environment variables
5. Deploy

### VPS (dengan Docker)

```bash
git clone <repo-url> keikomik-mirror
cd keikomik-mirror
docker build -t keikomik-mirror .
docker run -d \
  -p 3000:3000 \
  -e ORIGIN_HOST=keikomik.web.id \
  -e MIRROR_HOST=mirror.domainmu.com \
  -e MIRROR_PROTOCOL=https \
  --name keikomik-mirror \
  --restart unless-stopped \
  keikomik-mirror
```

### VPS (tanpa Docker)

```bash
git clone <repo-url> keikomik-mirror
cd keikomik-mirror
npm install --production
# Set env
export MIRROR_HOST=mirror.domainmu.com
export MIRROR_PROTOCOL=https
# Jalankan dengan pm2
npm install -g pm2
pm2 start server.js --name keikomik-mirror
pm2 save
pm2 startup
```

## Tips SEO

1. **Selalu set `MIRROR_HOST`** — tanpa ini, canonical tag bisa salah
2. **Submit sitemap** ke Google Search Console: `https://mirror.domainmu.com/sitemap.xml`
3. **Tunggu 1-2 minggu** setelah deploy sebelum cek indexing — Google butuh waktu re-crawl
4. **Gunakan HTTPS** — pastikan mirror domain punya SSL certificate
5. **Jangan jalankan origin dan mirror dengan konten identik tanpa canonical** — script ini sudah handle canonical otomatis