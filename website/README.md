# website

The public site: **one self-contained HTML file**.

No build step, no npm install, no framework, no external fonts or scripts. That
is a deliberate choice rather than laziness — a marketing page for a project
whose entire pitch is "verify, don't trust" should not pull a few hundred
transitive dependencies to render four sections of text, and a single file can
be read end to end before anyone serves it.

## Local preview

Open it directly, or serve it if you prefer real paths:

```bash
python3 -m http.server -d website 8000   # → http://localhost:8000
```

## Deploying

**GitHub Pages** is wired up in
[`.github/workflows/pages.yml`](../.github/workflows/pages.yml): pushes to
`main` that touch `website/` publish automatically. Enable it once under
*Settings → Pages → Source: GitHub Actions*.

**Anywhere else** — Netlify, Cloudflare Pages, S3, a USB stick — publish the
`website/` directory. There is nothing to compile.

## Editing

Styling lives in a `<style>` block at the top, themed through CSS custom
properties with a `prefers-color-scheme` dark variant. Change a colour once at
`:root` and it propagates.

**Keep the numbers honest.** The performance figures and test counts are real
measurements from `peregrine bench` and the test suites, not aspirations. If
they drift from what the repository actually does, fix the page — an
unaudited-scaffold banner beside inflated benchmarks would undercut the point
of the whole project.
