# Development Setup

## Overview
This setup serves the built React frontend from the Go backend. The frontend is automatically rebuilt on changes and embedded into the Go binary.

## How It Works

1. **Frontend builds to `backend/dist`**: Vite is configured to output to `../backend/dist`
2. **Go embeds the dist folder**: Using `//go:embed dist` directive
3. **API routes**: All `/api/*` routes are handled by Go handlers
4. **Frontend routes**: All other routes serve the React app (supports client-side routing)

## Development Workflow

### Start Development Mode
```bash
npm run dev
```

This runs both:
- **Frontend**: Vite build in watch mode (rebuilds on changes) → outputs to `backend/dist`
- **Backend**: Go server with Air (auto-reloads on changes) → serves from port 9000

### Access Your App
- **Frontend**: http://localhost:9000 (or any route like `/home`)
- **API**: http://localhost:9000/api/* (your API endpoints)

### Standalone Frontend Development (Optional)
If you want to run just the Vite dev server:
```bash
npm run dev:standalone
```
This runs Vite's dev server on port 5173 with HMR.

## File Structure

```
backend/
  ├── dist/           # Built frontend (gitignored, auto-generated)
  └── main.go         # Embeds dist folder and serves it
frontend/
  └── src/            # React source code
```

## API Calls

In your React code, use relative paths:
```typescript
// ✅ Good - works in both dev and production
fetch('/api/get')
fetch('/api/post')

// ❌ Bad - hardcoded localhost
fetch('http://localhost:9000/api/get')
```

## Scripts

- `npm run dev` - Run both frontend (build watch) and backend (with Air)
- `npm run dev:frontend` - Run only frontend build watch
- `npm run dev:backend` - Run only backend server
- `npm run dev:standalone` - Run Vite dev server (port 5173)
- `npm run build:frontend` - Production build of frontend

## Notes

- The `backend/dist` folder is gitignored
- First build might take a few seconds
- Go server auto-reloads when dist contents change (via Air)
- Frontend changes trigger rebuild → Go detects change → server reloads
- You may see Tailwind CSS warnings during build - they're harmless (see `TAILWIND_WARNINGS.md`)
