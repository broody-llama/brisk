# Brisk Risk Ticket Toolkit

This repo now includes both:

- A **frontend** built with Vite + React for interactive XML generation.
- A **Python CLI** (`generate_risk_ticket.py`) for terminal-based generation.

## Frontend (Vite + React)

### Run locally

```bash
npm install
npm run dev
```

Open the local URL shown by Vite (usually `http://localhost:5173`).

### Build production assets

```bash
npm run build
npm run preview
```

## Python CLI

```bash
./generate_risk_ticket.py "Acme Vendor" saas
```

Supported vendor types:
- `saas`
- `payments`
- `analytics`
- `infrastructure`

## Security hardening

- Vendor names are validated against an allow-list of supported characters.
- User-provided values are XML-escaped before being written to output.
- Length limits are enforced on vendor names to reduce abuse and malformed output risk.
- Generated documents are wrapped in a single `<risk_management_ticket>` root element to ensure valid XML parsing.

## Tests

```bash
python3 -m unittest discover -s tests -p 'test_*.py'
```
