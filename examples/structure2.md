# Repository Structure (Detailed)

> Complete file listing with descriptions — regenerated on 2026-02-20

## Governance & Tooling

| Path | Purpose |
|------|---------|
| `.avarion/CLAUDE_GOVERNANCE.md` | AI governance instructions |
| `.avarion/crown-jewels.yaml` | Critical asset definitions |
| `.avarion/permissions.yaml` | Permission policies |
| `.avarion/zones.yaml` | Zone-based access control |
| `.avarion/trust-root.json` | Signed policy trust anchor |
| `.claude/settings.local.json` | Local Claude Code settings |
| `.mcp.json` | MCP server configuration |

## Application Code

```
cmd/
└── server/
    ├── main.go              # Application entrypoint
    └── routes.go            # HTTP route registration

pkg/
├── auth/
│   ├── jwt.go               # JWT token generation & validation
│   └── middleware.go         # Auth middleware for protected routes
├── cart/
│   └── handler.go           # Cart CRUD operations
├── checkout/
│   ├── processor.go         # Payment processing logic
│   └── receipt.go           # Order receipt generation
├── inventory/
│   └── tracker.go           # Stock level management
└── notifications/
    └── dispatcher.go        # Email and push notification dispatch
```

## Scripts

| Script | Description |
|--------|-------------|
| `scripts/migrate.sh` | Run database migrations |
| `scripts/seed.sh` | Seed development database with sample data |

## Root Files

- `.gitignore` — Git ignore rules
- `go.mod` — Go module definition
- `go.sum` — Dependency checksums
- `Makefile` — Common build and test targets
- `README.md` — Project overview
