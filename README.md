# E-commerce Platform

Go-based e-commerce API demonstrating multi-agent AI detection with Avarion.

## AI Governance

This repository showcases Avarion's ability to detect and govern multiple AI coding agents:

| Package | AI Agent | Status |
|---------|----------|--------|
| `pkg/cart/` | GitHub Copilot | Allowed |
| `pkg/checkout/` | Claude Code | Allowed |
| `pkg/inventory/` | Cursor | Allowed |
| `pkg/auth/` | None | Restricted |

## Quick Start

```bash
go build -o server ./cmd/server
./server
```

## Security Notice

The `pkg/auth/` directory contains security-critical authentication code.
AI-assisted modifications are not permitted in this zone.
