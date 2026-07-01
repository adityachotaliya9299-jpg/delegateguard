# DelegateGuard Dashboard

Next.js 14 dashboard for DelegateGuard — the EIP-7702 security toolkit.

## Pages

| Route | Description |
|-------|-------------|
| `/` | Landing page — hero, features, coverage, CLI demo |
| `/dashboard` | Internal scan UI — configure, run, view findings, export |

## Local development

```bash
cd dashboard
npm install
npm run dev
# Open http://localhost:3000
```

## Deploy to Vercel

```bash
npm install -g vercel
vercel --prod
```

## Dashboard features

- Configure scan target (GitHub URL or local path)
- Choose mode: Delegate analyzer (DC), Protocol scanner (PA), or both
- Live progress bar during scan
- Severity breakdown chart
- Expandable findings table with filter by severity / bug class
- Export as Markdown report or JSON
- Demo mode (rich mock dataset) when no target is provided

## Real CLI integration

Set `ENABLE_REAL_SCAN=1` in `.env.local` and ensure `delegateguard` is on PATH to connect the dashboard to the real Python CLI. See `.env.example`.