# Repository Directory Structure

> Last updated: 2026-02-20

This document provides a high-level overview of the project layout.

## Top-Level Directories

```
ecommerce-platform/
├── .avarion/          # Avarion governance configuration
├── .claude/           # Claude Code configuration
├── cmd/
│   └── server/        # Server entrypoint (HTTP listener)
├── examples/          # Documentation and examples
├── pkg/
│   ├── auth/          # Authentication and JWT handling
│   ├── cart/          # Shopping cart functionality
│   ├── checkout/      # Checkout and payment processing
│   └── inventory/     # Inventory tracking and stock management
```

## Notes

- All Go source lives under `cmd/` and `pkg/`.
- Configuration files for AI tooling are in `.avarion/` and `.claude/`.
