# AI Workflow — poolpay-api

Contributing to this repo does **not** require any AI tooling — a plain editor and the standard toolchain are enough. This guide is for contributors who *choose* to use an AI assistant and want it to navigate the codebase efficiently (instead of grepping 40 files per question).

## TL;DR

> Prerequisite: `uv` (Astral's Python package manager). The simplest install is `curl -LsSf https://astral.sh/uv/install.sh | sh` — if you're cautious about piping a remote script straight into a shell (reasonable!), download it first (`curl -LsSf https://astral.sh/uv/install.sh -o uv-install.sh`), inspect it, then run `sh uv-install.sh`. The [uv install guide](https://docs.astral.sh/uv/getting-started/installation/) also lists Homebrew, winget, and standalone installer options. If you'd rather skip `uv` entirely, swap step 1 for `pipx install graphifyy` (or `pip install --user graphifyy`).

```bash
uv tool install graphifyy        # one-time global install
graphify install --platform claude   # one-time Claude Code skill registration (or pick another agent)
cd /path/to/poolpay-api
graphify update .                # builds graphify-out/ — your local code knowledge graph
```

That's it. `graphify-out/` is a derived artefact and shouldn't be committed. The simplest fix is to add it to this clone's `.git/info/exclude` (works immediately, no Git config needed). Alternatively, if you have a global excludes file configured (`git config --global core.excludesfile` — usually `~/.config/git/ignore` or `~/.gitignore_global`), add it there so it's ignored across every repo.

## What is graphify?

A CLI that turns the codebase into a queryable knowledge graph (AST-based, no LLM needed for the basic graph). It writes three artefacts to `graphify-out/`:

| File | Purpose |
|---|---|
| `graph.html` | Interactive browser visualisation — click nodes, search, filter |
| `GRAPH_REPORT.md` | Markdown summary: god nodes, surprising connections, suggested questions |
| `graph.json` | Programmatic access for AI assistants |

When you ask Claude Code (or any supporting agent) a codebase question, it reads `GRAPH_REPORT.md` instead of grepping. Faster, fewer tokens, structurally aware.

## Supported agents

Graphify ships with skills for:

- Claude Code → `graphify install --platform claude`
- Cursor → `graphify install --platform cursor`
- OpenCode / Codex / Gemini CLI / Aider / GitHub Copilot CLI / Trae / Hermes / Kiro / Pi / Antigravity → see `graphify install --help`

Pick the one you use. They all read the same `graphify-out/` artefacts.

## Maintenance

After meaningful structural changes (new modules, big renames, removed files), refresh the graph:

```bash
graphify update .
```

AST-only mode is local + free (no API cost). For semantic enrichment with an LLM, set `GEMINI_API_KEY` and run `graphify extract .` — optional. Treat `GEMINI_API_KEY` as a secret: keep it in your shell profile or a secret manager, and never paste it into tracked files (`.env` files, scripts, docs, commit messages).

## Useful commands inside the agent

Once the agent has the graph loaded, prefer these over grep:

| Question | Command |
|---|---|
| "How does X relate to Y?" | `/graphify path "X" "Y"` |
| "Explain this concept" | `/graphify explain "concept"` |
| "Open question about codebase" | `/graphify query "your question"` |

## What's NOT in this repo

- The graph artefacts (`graphify-out/`) — each dev builds their own; keep it out of commits via your global gitignore or `.git/info/exclude`
- Claude Code per-repo settings — graphify integrates via a **global skill** in your `~/.claude/`, not via repo hooks. Nothing to commit, nothing future devs inherit by accident.
- Project context / decisions / roadmap — those live in the team's knowledge wiki (currently in the maintainer's Obsidian vault; public mirror TBD)

## Companion repos

- **poolpay-app** — the Next.js dashboard. Same graphify setup applies in that repo; build its graph separately with `graphify update .` from its root.

## Troubleshooting

| Issue | Fix |
|---|---|
| `command not found: graphify` | Run `uv tool install graphifyy`, ensure `~/.local/bin` (or `uv` install dir) is on `PATH` |
| Graph feels stale | Run `graphify update .` — AST-only, fast, free |
| Agent doesn't seem to use the graph | Confirm `graphify-out/GRAPH_REPORT.md` exists and the platform skill is installed (`graphify install --platform <agent>`) |

## Why this is opt-in

The graph is a **derived artefact**, not source. Each dev's local copy reflects their local code state. Committing it would create constant noise (regenerated on every code change), so we keep it local-only via each contributor's global gitignore (or `.git/info/exclude`).
