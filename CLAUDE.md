# Shedu — project instructions

Shedu is a plain-language, report-only security agent for small Linux servers (Go, Telegram).
Working language: English in code, file names, commit messages and terminal output.

Internal planning docs (roadmap, specs, overview, test graph) live in `private/`, which is
git-ignored here and has its own repository. See `private/CLAUDE.full.md` for the full
dev-kit workflow.

## Stack commands
- Build: `make build` → `bin/shedu`
- Tests: `go test ./...` (unit tests never need root; fixtures in `testdata/`)
- One-shot audit: `sudo ./bin/shedu check` · daemon: `sudo ./bin/shedu run`
- Local Telegram dev setup (no sudo): `scripts/dev_telegram.sh`
- Close a dev-kit step: `private/scripts/step_done.sh <n> "<commit message>"`
- Pre-push secret scan, once per clone (installs `.git/hooks/pre-push` here and in
  `private/`): `scripts/install_hooks.sh` · test: `scripts/secret_scan_test.sh` ·
  rules and opt-outs: `scripts/secret_scan.sh --help`

## Rules of this codebase
- Standard library only unless a spec step explicitly approves a dependency.
- Checks and watchers parse input they are given (bytes, io.Reader, path); never shell out
  inside the pure function, so everything is testable with fixtures.
- Every finding carries a plain-language explanation and a copy-pasteable fix command.
- Report-only: the agent never modifies the host. It writes only under `/var/lib/shedu`
  (state) and `/etc/shedu` (config, by install.sh).
- Terminal output is English; Hebrew only on Telegram.
