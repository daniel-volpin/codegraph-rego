# CodeGraph Frontend

This Vite + React (TypeScript) client surfaces the main workflows exposed by the FastAPI backend:

- Upload Java projects and trigger ingestion/embedding.
- Run semantic + graph searches over the indexed codebase.
- Evaluate ISO 27001 policies and optionally enrich violations with LLM insights.

## Getting Started

```bash
cd frontend
npm install
npm run dev
```

The development server starts at <http://127.0.0.1:5173> by default. The React app talks to the FastAPI backend via REST, so ensure the API is running (default: <http://127.0.0.1:8000>).

### Environment

| Variable | Purpose | Default |
| --- | --- | --- |
| `VITE_API_BASE_URL` | Base URL for FastAPI endpoints | `http://127.0.0.1:8000` |

Create a `.env` file in `frontend/` to override the default:

```bash
echo 'VITE_API_BASE_URL=http://localhost:9000' > .env
```

### Available Scripts

- `npm run dev` – start the Vite dev server.
- `npm run build` – type-check and create a production build.
- `npm run preview` – serve the build output locally.

## Project Structure

```init
frontend/
  src/
    pages/        # Upload/search/policy views
    components/   # Layout, navigation
    lib/          # Simple API client & shared types
```

React Query manages async state (uploads, searches, policy checks), while React Router handles navigation between the major workflows.
