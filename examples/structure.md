# Repository Directory Structure

> Last updated: 2026-02-20

This document provides a high-level overview of the project layout and module boundaries.

## Top-Level Directories

```
ecommerce-platform/
├── .avarion/          # Avarion governance configuration
├── .claude/           # Claude Code configuration
├── cmd/
│   └── server/        # Server entrypoint (HTTP listener)
├── examples/          # Documentation and examples
├── internal/          # Private packages not importable externally
├── pkg/
│   ├── auth/          # Authentication and JWT handling
│   ├── cart/          # Shopping cart functionality
│   ├── checkout/      # Checkout and payment processing
│   ├── inventory/     # Inventory tracking and stock management
│   └── notifications/ # Email and push notification dispatch
├── scripts/           # Build and deployment helper scripts
└── tests/             # Integration and end-to-end tests
```

## Dependency Graph

`checkout` depends on `cart`, `inventory`, and `auth`. The `notifications` package is called from `checkout` after successful payment processing.

## Notes

- All Go source lives under `cmd/`, `pkg/`, and `internal/`.
- Configuration files for AI tooling are in `.avarion/` and `.claude/`.
- Integration tests live in `tests/` and require a running database.
