# Releasing to crates.io

komainu is published as eight crates. They depend on each other, so publish them in this order
and wait until each one appears in the crates.io index before publishing the next:

1. `komainu-domain`
2. `komainu-application`
3. `komainu-adapter-std`
4. `komainu-adapter-postgres`
5. `komainu-http`
6. `komainu-testkit`
7. `komainu`
8. `komainu-server`

## Before publishing

- Set the new version in `[workspace.package]` and in the `version = "..."` of every internal
  crate in `[workspace.dependencies]` of the root `Cargo.toml`.
- Run the checks in the README's Development section.
- Confirm that `cargo publish --dry-run -p komainu-domain` passes. The other crates cannot be
  verified by `--dry-run` until their dependencies are on crates.io; check that
  `cargo package --workspace --no-verify` builds every `.crate`.

## Publishing

For each crate in the order above:

```sh
cargo publish -p <crate>
```

Publishing cannot be undone (a version can only be yanked), so do it by hand and only after the
checks above pass. This repository's tooling never runs `cargo publish`.

`komainu-application` lists `komainu-testkit` as a path-only dev-dependency. `komainu-testkit` depends on `komainu-application`, so a versioned dev-dependency would make `cargo package` fail on the cycle; without a version, the dev-dependency is dropped from the package.
