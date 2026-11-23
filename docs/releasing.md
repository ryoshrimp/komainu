# Releasing to crates.io

komainu is published as eight crates. They depend on each other, so they are published in this
order (the order is encoded in `scripts/release.py`):

1. `komainu-domain`
2. `komainu-application`
3. `komainu-adapter-std`
4. `komainu-testkit`
5. `komainu-adapter-postgres`
6. `komainu-http`
7. `komainu`
8. `komainu-server`

`komainu-testkit` comes before `komainu-adapter-postgres` and `komainu-http` because
`komainu-adapter-postgres`, `komainu-http`, `komainu` and `komainu-server` all have a versioned
dev-dependency on `komainu-testkit`, which `cargo publish -p` resolves from the registry.

## Before publishing

- Set the new version in `[workspace.package]` and in the `version = "..."` of every internal
  crate in `[workspace.dependencies]` of the root `Cargo.toml`.
- Move the entries under `[Unreleased]` in `CHANGELOG.md` to a section for the new version with
  the release date, and update the links at the bottom of the file.
- Run the checks in the README's Development section, then merge the PR to `main`.
- Run `python3 scripts/release.py` (dry-run, no token needed). It runs
  `cargo publish --workspace --dry-run --locked`, which packages and verifies every crate against
  a local overlay of the others, so crates that depend on a not-yet-published version still pass.

`komainu-application` lists `komainu-testkit` as a path-only dev-dependency. `komainu-testkit`
depends on `komainu-application`, so a versioned dev-dependency would make `cargo package` fail
on the cycle; without a version, the dev-dependency is dropped from the package.

## One-time Trusted Publishing setup

Publishing uses GitHub Actions OIDC, not a stored crates.io API token.

1. Create the GitHub `crates-io` deployment environment. Restrict deployment branches to `main`;
   enable required reviewers if your plan supports it.
2. As an owner on crates.io, open the **Trusted Publishing** settings of **each** of the eight
   crates above and add the same GitHub publisher:

   | Field | Value |
   | --- | --- |
   | Repository owner | `ryoshrimp` |
   | Repository name | `komainu` |
   | Workflow filename | `release.yml` (not the full path) |
   | Environment | `crates-io` |

   A brand-new crate must be published once manually with a token before Trusted Publishing can
   be configured for it. If a crate has no version on crates.io yet, do the first release locally
   with `python3 scripts/release.py --publish` and your local cargo credentials, then set up
   Trusted Publishing.
3. Do not add a `CARGO_REGISTRY_TOKEN` secret; there is intentionally no fallback to a long-lived
   token.

These account-side settings must be configured by a maintainer; the workflow file does not
configure crates.io or GitHub environment protections.

### Security model

- There is no long-lived publishing secret to leak or rotate. crates.io verifies the repository,
  workflow filename, and environment using GitHub's signed OIDC identity.
- The exchanged token is short-lived and revoked by the auth action's post-job cleanup.
  Authentication happens after verification, immediately before publication.
- Only the `publish` job has `id-token: write`. It runs only on `main` from a manual dispatch,
  uses the protected environment, restores no build cache, and does not persist checkout
  credentials. Actions are pinned to full commit SHAs; review the pins periodically.

This reduces credential exposure; it does not make a compromised workflow safe. Protect `main`
and review changes to the release workflow and scripts.

## Release with one operation

From Actions, select **Release**, choose `main`, enable **publish**, and run. The workflow runs
fmt, clippy, tests and the script's unit tests before publishing. Without **publish**, it runs
the dry-run (`python3 scripts/release.py`) and needs no token.

The script skips exact versions already on crates.io, so a partially completed release is
resumed by re-running the same workflow. Cargo waits for each crate to appear in the index before
publishing the next. Yanked versions and registry errors fail the run rather than being skipped.
Publishing cannot be rolled back (a version can only be yanked); if a published version is wrong,
prepare a new version.

Equivalent local commands (use a clean, committed tree):

```sh
python3 scripts/release.py            # dry-run by default
python3 scripts/release.py --publish  # irreversible; local cargo credentials required
```

This workflow does not create Git tags or GitHub Releases.
