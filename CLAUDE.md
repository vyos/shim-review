# CLAUDE.md

## Project purpose

VyOS's submission to the upstream `rhboot/shim-review` process: signed UEFI Secure Boot shim binary plus the supporting build artefacts the reviewers need. Pull requests against `rhboot/shim-review` link back to this fork for the actual files.

## Tech stack

- No code build. Repo holds binary artefacts and documentation.
- A `Dockerfile` defines the reproducible build environment used to produce `shimx64.efi`.

## Build / test / run

To reproduce the shim binary:

```sh
docker build -t vyos-shim-build .
```

`docker build` is self-contained: it clones the source repos, builds the shim package, and verifies the resulting binary against the committed `shimx64.efi` via `hexdump`/`diff`. A non-zero exit means the build does not reproduce.

Submitted artefacts live at the repo root (`shimx64.efi`, `shim_16.0-1+vyos1_amd64.build`, `shim_16.0-1+vyos1_amd64.buildinfo`, certificate files).

## Repository layout

- `README.md`, `ISSUE_TEMPLATE.md`, `CODE_OF_CONDUCT.md`, `docs/`, `examples/` — inherited from upstream review template.
- `Dockerfile` — build environment.
- `shim_16.0-1+vyos1_amd64.{build,buildinfo}`, `shimx64.efi` — the artefacts.
- `vyos-uefi-ca.der`, `debian-uefi-ca.der`, `pjones.asc` — CA / signer certs.

## Cross-repo context

Pairs with `vyos/efi-boot-shim` (the source repo for the VyOS shim build). Shim review is a one-way submission upstream to `rhboot/shim-review`; once accepted, Microsoft signs the resulting `shimx64.efi`. Boot artefacts ultimately consumed by `vyos/vyos-build` ISO assembly.

## Conventions

- Default branch `main` (matches upstream).
- Tag submissions per upstream rules: `vyos-shim-{version}-{arch}-{YYYYMMDD}` (e.g. `vyos-shim-16.0-amd64-20250707`).
- This repo follows the **upstream** rhboot/shim-review template — do not VyOS-ify the issue/PR templates without breaking submissions.

## Mirror relationship

No mirror twin. Lives only in `vyos`. The upstream is `rhboot/shim-review`, tracked as `upstream/main`.

## Notes for future contributors

- The artefact files at the repo root are what reviewers download — keep names canonical and matching the build log.
- Any rebuild requires the secure-boot CA chain to remain identical; see `vyos-uefi-ca.der`.
- Don't repurpose this repo for general shim dev — that's `vyos/efi-boot-shim`.
