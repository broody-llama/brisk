# Brisk Risk Tracker

Brisk is now a standalone internal tool with:

- **React + Vite frontend** for assessment input and review tables.
- **FastAPI backend** that generates risk/control tracker drafts from evidence text.
- Optional **LLM mode** (if `OPENAI_API_KEY` is configured), with deterministic fallback.
- **Autonomous vendor research mode** that can gather public vendor evidence from web sources when no evidence is pasted.

## Run locally

### 1) Start backend API

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install fastapi uvicorn
uvicorn backend.app:app --reload --port 8000
```

### 2) Start frontend

In another terminal:

```bash
npm install
npm run dev
```

Open the local Vite URL (usually `http://localhost:5173`).

## AI mode (optional)

If you want Brisk to call an LLM instead of fallback extraction:

```bash
export OPENAI_API_KEY=your_key
export OPENAI_MODEL=gpt-4.1-mini
```

Without those env vars, Brisk still works using deterministic evidence parsing.

## Autonomous research mode

- In the UI, keep **Enable autonomous vendor research** checked and leave evidence blank.
- Brisk will attempt to discover and summarize vendor sources automatically, then generate risks/controls and attach source links in the ticket response.

## Tests

```bash
python3 -m unittest discover -s tests -p 'test_*.py'
```
