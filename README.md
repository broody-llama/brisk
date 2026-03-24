# Brisk Risk Ticket Toolkit

This repo includes:

- `risk_ticket_template.xml`: a reusable XML ticket template.
- `generate_risk_ticket.py`: a generator that creates vendor-specific tickets by vendor type.

## Usage

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

## Tests

```bash
python3 -m unittest discover -s tests -p 'test_*.py'
```
