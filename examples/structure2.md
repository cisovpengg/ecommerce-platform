# Repository Structure (Detailed)

> Complete file listing with descriptions

## Governance & Tooling

| Path | Purpose |
|------|---------|
| `.avarion/CLAUDE_GOVERNANCE.md` | AI governance instructions |
| `.avarion/crown-jewels.yaml` | Critical asset definitions |
| `.avarion/permissions.yaml` | Permission policies |
| `.avarion/zones.yaml` | Zone-based access control |
| `.claude/settings.local.json` | Local Claude Code settings |
| `.mcp.json` | MCP server configuration |

## Application Code

```
cmd/
└── server/
    └── main.go              # Application entrypoint

pkg/
├── auth/
│   └── jwt.go               # JWT token generation & validation
├── cart/
│   └── handler.go           # Cart CRUD operations
├── checkout/
│   └── processor.go         # Payment processing logic
└── inventory/
    └── tracker.go           # Stock level management
```

## Root Files

- `.gitignore` — Git ignore rules
- `go.mod` — Go module definition
- `README.md` — Project overview
