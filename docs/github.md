# Publishing to GitHub

<!-- Copyright 2026 Mukilesh -->
<!-- -->
<!-- Licensed under the Apache License, Version 2.0 (the "License"); -->
<!-- you may not use this file except in compliance with the License. -->
<!-- You may obtain a copy of the License at -->
<!-- -->
<!--     http://www.apache.org/licenses/LICENSE-2.0 -->
<!-- -->
<!-- Unless required by applicable law or agreed to in writing, software -->
<!-- distributed under the License is distributed on an "AS IS" BASIS, -->
<!-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. -->
<!-- See the License for the specific language governing permissions and -->
<!-- limitations under the License. -->


## The repository state

The project lives in one repository with two Cargo workspaces:

| Path                        | Contents                                   |
| --------------------------- | ------------------------------------------ |
| `crates/clipwarden-core`      | the detection engine (pure Rust, no I/O)   |
| `crates/clipwarden-clipboard` | the Windows clipboard integration          |
| `crates/clipwarden-daemon`    | the background service, tray and CLI        |
| `apps/desktop`               | the Tauri dashboard (its own workspace)     |

The work is committed on the branch `opencode`. Every version is one commit,
so the history reads like a changelog:

```text
v0.11.0 portable release, GitHub ready repository
v0.10.0 settings tab and a working password protected configuration
v0.9.0  background behaviour, tray-only exit and console-free service
v0.8.0  fix the dashboard IPC calls for Tauri 2
v0.7.0  harden the control channel with overlapped I/O
...
```

## Pushing for the first time

```powershell
git remote add origin https://github.com/<you>/<repository>.git
git push -u origin opencode
```

After that, `git push` is enough.

## GH013 — "Repository rule violations found for refs/heads/main"

GitHub refused the push because the branch `main` of the remote repository is
protected by a **ruleset** or by **branch protection**. The error means: your
push violates a rule that the repository owner configured — it is not a
problem with the code.

The most common rules and how to satisfy them:

| Rule                                            | What to do                                                                  |
| ----------------------------------------------- | --------------------------------------------------------------------------- |
| **Require a pull request** (no direct pushes)  | Push the `opencode` branch and open a pull request into `main`.              |
| **Require signed commits**                      | Sign the commits, see below.                                                |
| **Require linear history**                      | Do not merge; rebase instead: `git pull --rebase origin main`.               |
| **Require branches to be up to date**           | Merge or rebase `main` into your branch first.                              |
| **Block force pushes**                          | Do not use `--force`; use `--force-with-lease` if a rewrite is unavoidable.  |
| **Restrict who can push**                       | Ask the repository owner to grant you write access.                         |

### Pushing to `main` directly

If the ruleset only asks for signed commits, sign the history and push:

```powershell
# Use your SSH key for signing (no GPG needed).
git config gpg.format ssh
git config user.signingkey "$env:USERPROFILE\.ssh\id_ed25519.pub"
git config commit.gpgsign true

# Sign every existing commit of the branch.
git rebase --exec "git commit --amend --no-edit -S" --root

git push -u origin main
```

With GPG instead of SSH:

```powershell
git config gpg.format openpgp
git config user.signingkey <your-key-id>
git config commit.gpgsign true
```

### The easiest way: pull request

```powershell
git push -u origin opencode
```

Then open `https://github.com/<you>/<repository>/compare/main...opencode` and
create the pull request. Rulesets that require a pull request are satisfied
this way, and the history stays intact.

## Before the first push

```powershell
# The tests must pass.
cargo test --workspace
cargo build --release --workspace
cargo build --release --manifest-path apps\desktop\src-tauri\Cargo.toml
```

The portable package is assembled from the binaries of `target\release`: the
two programs, `uninstall.exe`, `LICENSE`, `NOTICE` and a short
`README.txt`.

## Local maintenance scripts

The scripts in `scripts\` are the tooling of the maintainer and are therefore
not part of the published source:

| Script | Purpose |
| --- | --- |
| `build-release.ps1` | Builds every binary and packs the portable ZIP |
| `add-license-headers.ps1` | Puts the Apache header into every source file |
| `sanitize-secrets.ps1` | Removes the example credentials from older revisions |
| `generate-icons.mjs` | Draws the application icon from code |

They are ignored by git and stay on the machine of the maintainer. Everything
that a user needs to build the program is in the repository.

## Repository metadata

The `repository` field in `Cargo.toml` and `apps\desktop\src-tauri\Cargo.toml`
points at the repository of the project. Change it if you publish the code
under a different address:

```toml
repository = "https://github.com/<you>/<repository>"
```

The same applies to the links in `README.md` and the `identifier` in
`apps\desktop\src-tauri\tauri.conf.json` (`dev.mukilesh.clipwarden`), which
should become something unique to you — for example
`com.yourname.clipwarden`. The identifier is used for the data folder of the
application, so it should not change once the software has been used.