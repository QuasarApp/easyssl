# AGENTS.md

Working guidance for AI coding agents and developers in the `QuasarApp/easyssl` repository.

## Description

EasySSL is a QuasarApp wrapper library that makes using OpenSSL simpler:
interfaces for signing and encrypting data, key creation and async
authentication. Supported algorithms: ECDSA, RSA.

- **Language:** C++17 + Qt (Core, Network)
- **Build system:** CMake ≥ 3.19 (typically with Ninja)
- **License:** GPLv3

### Repository layout

| Path | Contents |
|---|---|
| `src/lib` | the `easyssl` library (crypto/auth interfaces) |
| `cmake/BuildOpenSSL.cmake` | optional OpenSSL source build (default path) |
| `tests/` | Qt Test suite (`easyssltests`: auth, crypto, crt units) |
| `submodules/CMake` | the QuasarApp CMake layer (`QuasarApp/CMake` submodule) |
| `docs/`, `pages/` | documentation (Doxygen API docs + landing page → `quasarapp.github.io`) |

### Architecture

- Wraps OpenSSL behind QuasarApp's async model; with `BUILD_WITH_OPENSSL=ON`
  (default) OpenSSL is cloned and built from source before the library, with
  `OFF` the system OpenSSL is used.
- The QuasarApp CMake layer (`initAll()`) provides the `test` /
  `testeasyssl` / `deploy` / `doc` targets.

## Developing process

### Toolchain

| Tool | Version / notes |
|---|---|
| CMake | ≥ 3.19 |
| Compiler | C++17 |
| Qt | 5 or 6 (modules: Core, Network, Test; CI: 6.12.0 on Linux, 6.10.3 on Windows) |
| Ninja | preferred generator |
| OpenSSL | built from source by default (`BUILD_WITH_OPENSSL=ON`) or system dev package |
| CQtDeployer | `cqtdeployer` on `PATH` — required by the `deploy`/`testeasyssl` targets |

### Build

Step by step; CI (`.github/workflows/ci.yml`) runs the same flow on
every pull request — a Release build on Linux (Qt 6.12.0) and Windows
(Qt 6.10.3, an aqt workaround), then the test suite via the `test` target.

**1. One-time toolchain setup.** Qt 6.10.3 via aqtinstall
(`aqt install-qt linux desktop 6.10.3 gcc_64 -O /opt/Qt`) plus CMake ≥ 3.19
and Ninja. Either rely on the default OpenSSL source build or install the
system OpenSSL dev packages.

**2. Get the sources.** The CMake-layer submodule is mandatory:

```sh
git clone --recurse-submodules https://github.com/QuasarApp/easyssl.git
# or, for an existing clone:
git submodule update --init --recursive
```

**3. Configure.**

```sh
cmake -B build -G Ninja \
  -DCMAKE_PREFIX_PATH=/opt/Qt/6.10.3/gcc_64 \
  -DBUILD_SHARED_LIBS=ON \
  -DCMAKE_BUILD_TYPE=Debug \
  -DEASYSSL_TESTS=ON
# -DBUILD_WITH_OPENSSL=OFF   # use the system OpenSSL instead of the source build
```

**4. Build.** (With the default `BUILD_WITH_OPENSSL=ON` this also builds
OpenSSL — expect a long first build.)

```sh
cmake --build build --parallel 16
```

**5. Find the result.** The suite executable lands in its per-target build
dir (`build/tests/easyssltests`); the deliverable is the `easyssl` library
(`libeasyssl`).

CMake options:

- `EASYSSL_TESTS` — build the test suite (default `ON`)
- `BUILD_WITH_OPENSSL` — build OpenSSL from source (default `ON`; not
  supported on wasm32)
- `EASYSSL_STATIC_SSL` — statically link the SSL libraries (default `OFF`)

### Branching, labels and pull requests (workflow for AI agents)

- Work is issue-driven: one GitHub issue → one branch named
  `task_<issue-number>`, branched **strictly from `main`** — never from
  another task branch.
- Commit messages: short imperative subject + issue reference, e.g.
  `fix: <summary> (issue #<issue>)`, `docs: <summary> (issue #<issue>)`.
- Keep the build and lint green; a red CI blocks the merge.

**The exact commands.**

```sh
# 1. every task starts from a freshly fetched main
git fetch origin
git checkout -b task_<issue> origin/main

# 2. label the issue while working. Workflow labels in this repo:
#    in-progress, high/medium/low priority, question
gh issue edit <issue> --add-label in-progress

# 3. post the initial checklist as a comment; afterwards update that same
#    comment in place, never re-post it
gh issue comment <issue> --body-file /tmp/checklist.md
gh issue comment <issue> --edit-last --body-file /tmp/checklist.md

# 4. push and open the PR — see "Creating the pull request" below
git push -u origin task_<issue>
gh pr create --base main --head task_<issue> \
  --title "<type>: <short imperative summary> (issue #<issue>)" \
  --body-file /tmp/pr_body.md

# 5. the issue goes to waiting-for-review; watch CI from the CLI
gh issue edit <issue> --remove-label in-progress --add-label waiting-for-review
gh pr checks <number>
```

This repo does not define a `waiting-for-review` label yet — create it
before first use: `gh label create waiting-for-review --color 'fbca04'`.

**Status messages — what to post and when.** An agent must keep a
human-readable trail on the issue (and on the PR once it exists). Every
message is a GitHub comment with a `##` heading; the checklist comment is
updated in place (`--edit-last`), never duplicated.

| Stage | Label(s) | Comment template |
|---|---|---|
| Start | `in-progress` | `## Task issue_XXX: <title> — initial checklist (branch task_XXX from main)` — one `- [ ]` line per sub-task |
| Each step done | — | edit the checklist comment: mark the line `- [x]` + one short evidence note (command run, result) |
| Blocked / needs input | `blocked` / `question` | `## Blocked — task_XXX` — what is blocking and exactly what is needed to continue |
| PR opened | `waiting-for-review` | `## Progress — task_XXX` — all lines `- [x]` + `**PR: <url>**` + one-line verification summary |
| Review changes requested | `waiting-for-review` | `## Review-fix cycle — PR #NNN — update` — one `- [x]` line per review point, each with the evidence |
| CI red on the PR | `in-progress` | `## CI failure — PR #NNN` — failing check, cause, fix plan; push the fix, then update the comment |

**Creating the pull request.** An agent has no browser and cannot create a
pull request from the GitHub web UI — it must use the `gh` CLI (a token with
the `repo` scope; in this organisation the agent runs as `QuasarAppCI`):

```sh
gh pr create \
  --base main \
  --head task_<issue> \
  --title "<type>: <short imperative summary> (issue #<issue>)" \
  --body-file /tmp/pr_body.md
```

- The body carries what changed and the verification actually performed
  (commands + their real output); `(issue #<n>)` in the title links the PR
  to the issue. Use `--draft` while still iterating.
- A pull request exists only when `gh pr create` prints its URL. Confirm
  with `gh pr view <number> --json number,url,mergeable` before reporting
  "PR created" — never post that status on faith.
- If work is blocked, keep the PR open, set the issue label to `blocked` and
  post the status message above.

### Documentation rules

- `docs/` (Doxygen API docs + Markdown pages, deployed by
  `.github/workflows/deploy-docs.yml`) is the public documentation — keep it
  in sync with API
  changes in the same PR.

## Testing process

### Test infrastructure

Qt Test suite in `tests/` (`tstMain.cpp` + `tests/units/`: auth, crypto,
crt): the executable `easyssltests` links `Qt::Test` and `easyssl`; built
with `EASYSSL_TESTS=ON` (default; forced `OFF` on Android, iOS and wasm32).
The QuasarApp CMake layer registers the suite under the `test` aggregate:
`test` → `testeasyssl` → `deployTesteasyssl` — `cqtdeployer` deploys the
suite and its Qt runtime into the gitignored `Testing/easyssl/` directory
and generates the `easyssltests.sh` run script — then `testeasyssl`
executes that script from `Testing/easyssl/`. `cqtdeployer` must be on
`PATH`.

### Running the tests from CMake

The supported entry point is the `test` target (the same command CI runs):

```sh
cmake -B build -G Ninja -DCMAKE_PREFIX_PATH=/opt/Qt/6.10.3/gcc_64 \
  -DCMAKE_BUILD_TYPE=Debug -DEASYSSL_TESTS=ON
cmake --build build --parallel 16
cmake --build build --target test
```

A green run ends with `Totals: 7 passed, 0 failed`. (The raw executable in
`build/tests/easyssltests` can be run directly as well, but the `test`
target is what deploys and runs the suite the way CI does.)
