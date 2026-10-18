# Prosze Project Completion Plan

## Global Constraints

- README.md is the product contract: local redaction happens before outbound AI traffic and placeholders restore on inbound traffic.
- Keep the C++ CLI dependency-free and compatible with the existing Visual Studio project.
- Keep proxy behavior local, loopback-safe by default, and compatible with JSON and SSE traffic.
- Preserve existing Python commands and tests unless the C++ implementation intentionally becomes the documented fast path.
- Never expose original secret values in ordinary logs or status output.
- Add deterministic tests and document the actual supported commands and build paths.

## Tasks

1. Review the current project and produce a prioritized implementation brief.
2. Bring the main C++ CLI in line with the README, including the bare command flow and core privacy behavior.
3. Implement or migrate the fast proxy path to C++ while preserving the Python proxy compatibility path where practical.
4. Update README.md and project_updates.md to match the delivered architecture and usage.
5. Add/run deterministic tests for C++ and Python behavior, proxy boundaries, and CLI smoke flows.

