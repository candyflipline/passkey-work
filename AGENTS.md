<!-- BEGIN:nextjs-agent-rules -->
# This is NOT the Next.js you know

This version has breaking changes — APIs, conventions, and file structure may all differ from your training data. Read the relevant guide in `node_modules/next/dist/docs/` before writing any code. Heed deprecation notices.
<!-- END:nextjs-agent-rules -->

## Architecture

This project should follow Loyal's vertical-slice architecture style as it grows.

### Current Structure

- `src/app/` - Next.js App Router routes, layouts, pages, and route handlers.
- `src/app/page.tsx` - Main web page entrypoint.
- `src/app/layout.tsx` - Root layout and global document shell.
- `src/app/globals.css` - Global Tailwind/CSS entrypoint.

### Vertical Slice Direction

Organize new work by feature first, not by technical layer. Keep route files as thin orchestration layers and move reusable UI, domain logic, server logic, data access, and integrations into the feature that owns them.

For substantial new features, prefer this shape:

```text
src/features/<feature-name>/
  index.ts        # public entrypoints only
  ui/
  server/
  domain/
  data/
  integrations/
  types.ts
```

Rules for feature work:

- Extend an existing slice in place when behavior belongs to that feature.
- Avoid deep imports across slices; import through a slice's public `index.ts` when cross-slice access is truly needed.
- Keep feature-specific behavior inside its owning slice until it is clearly reused by multiple slices.
- Promote shared, stable cross-slice primitives to `src/lib/` only after reuse is proven.
- Keep `src/app/**/page.tsx`, `layout.tsx`, and route handlers focused on composition, request handling, and wiring.
- Preserve server/client boundaries. Server-only helpers should live in dedicated server modules such as `server.ts` or `*.server.ts` and must not be imported by client components.

### Shared Library Direction

Use `src/lib/` for cross-slice infrastructure and integration primitives only. Do not create broad horizontal folders for feature-specific code just because files share a technical type.

Examples of code that may belong in `src/lib/` after reuse is proven:

- Framework-safe utilities
- Shared API clients
- Shared auth/passkey primitives
- Shared validation or serialization helpers
- Stable integration wrappers used by multiple features

## Light Protocol and Compressed PDAs

This repo is preparing to build Solana programs that use Light Protocol compressed PDAs. Treat Light docs as live protocol/tooling docs; start from `https://www.zkcompression.com/llms.txt`, then read the compressed PDA overview and guide before implementing.

Keep this context in mind:

- Compressed PDA addresses include the address tree in derivation, so programs and clients must agree on and verify the expected tree.
- Client flows use `@lightprotocol/stateless.js` to derive or fetch compressed addresses, request validity proofs, pack Light accounts, and pass them through `remainingAccounts`.
- Use `bun run light:validator` for local compressed-account testing, and the `zkcompression` MCP server or installed Light skills when current Light-specific context is needed.
- Add on-chain Rust dependencies only when adding the first compressed PDA program, and confirm current Light/Anchor/Solana compatibility before pinning versions.

## Git and Pull Requests

Use the same commit and PR conventions as Loyal's main repositories.

### Commit Conventions

Commits should use Conventional Commits:

```text
type(scope): description
```

Allowed types:

- `feat`
- `fix`
- `chore`
- `docs`
- `style`
- `refactor`
- `perf`
- `test`
- `build`
- `ci`
- `revert`

Scope is optional but encouraged. Use the area being changed, such as `passkey`, `ui`, `auth`, `docs`, or `ci`.

Examples:

```text
feat(passkey): add registration entrypoint
fix(auth): handle missing credential response
docs(agents): document vertical slice conventions
refactor(ui): extract passkey button panel
```

Commit rules:

- Never add `Co-Authored-By` trailers or co-author attribution.
- Keep the subject line under 100 characters.
- Use imperative mood in the description, such as `add`, not `added` or `adds`.
- Do not end the subject line with a period.
- Validate locally before pushing with the relevant lint/test commands for the files changed.

### Branch and Worktree Conventions

When working from a Linear issue, branches should follow the Linear-style format:

```text
<issue-number-short-description>
```

Example:

```text
ASK-123-add-passkey-registration
```

For larger issue work in the main Loyal app repo, prefer a separate git worktree created from `main`. In this smaller project, do not switch branches or create worktrees unless the task calls for it.

### Pull Requests

- PR titles must follow the same conventional commit format: `type(scope): description`.
- PR bodies should be a simple one or two sentence summary of the changes, without heavy templates or checklists unless the repo later adopts one.
- Only merge after required checks and deployment previews are successful.
- Prefer squash-and-merge for PRs.
- Keep PRs scoped to one feature or fix; avoid mixing unrelated refactors with product changes.
