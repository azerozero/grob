# Maintain dependencies with Renovate

Grob runs Renovate in [GitHub Actions](../../.github/workflows/renovate.yml)
using the private `azerozero-grob-renovate` GitHub App. Install the App only on
`azerozero/grob`. The workflow also restricts each installation token to `grob`.

## Configure the App

Register the App under the `azerozero` organization using the settings in
[the App manifest](../../.github/renovate-app-manifest.json). Keep webhooks
disabled: scheduled and manual workflow runs drive this installation.

The App needs read access to administration, metadata, Dependabot alerts, and
organization members. It needs write access to checks, commit statuses, contents,
issues, pull requests, and workflows. These permissions follow
[Renovate's GitHub App requirements](https://docs.renovatebot.com/modules/platform/github/#running-as-a-github-app).
Do not add the App to a branch-protection bypass list.

Set these values in the `grob` repository's Actions settings:

| Kind | Name | Value |
|------|------|-------|
| Variable | `RENOVATE_APP_CLIENT_ID` | The App's client ID |
| Variable | `RENOVATE_ENABLED` | `true` after the first dry run and hosted-App removal |
| Secret | `RENOVATE_APP_PRIVATE_KEY` | The complete private key in PEM format |

The workflow creates a short-lived installation token and revokes it when the
job finishes. Its ordinary `GITHUB_TOKEN` has read-only access and is used for
checkout and dependency changelogs. App keys must stay out of Git and logs.

## Run and inspect an update scan

Run a preview from `main`:

```bash
gh workflow run renovate.yml --ref main -f dry_run=true
gh run list --workflow renovate.yml --limit 5
```

Inspect the run's logs with `gh run view <run-id> --log`. A dry run scans for
updates without creating branches, issues, or pull requests.

Before the first live run, remove the Mend-hosted Renovate App's access to
`grob`. Keep its access to other repositories if they use it. Two Renovate
installations must not manage this repository's branches simultaneously.
Set `RENOVATE_ENABLED` to `true` after the dry run succeeds and the hosted App
no longer has access. Until then, the workflow only accepts manual dry runs.

Start a live run:

```bash
gh workflow run renovate.yml --ref main -f dry_run=false
```

Scheduled scans run hourly at minute 17 UTC. The schedule in
[`renovate.json`](../../renovate.json) still limits routine branch creation and
lockfile maintenance to Monday before 06:00 UTC. A live manual run respects that
schedule too. Use the Dependency Dashboard to request an individual update
outside the scheduled window.

Patch updates, eligible development dependencies, non-major GitHub Actions
updates, and lockfile maintenance use PR-based squash auto-merge. Other minor
and major updates follow the review rules in `renovate.json`. Required checks
and branch protection still apply to every PR.

## Troubleshoot and rotate credentials

- **Missing credentials or authentication failure:** check the repository
  variable, PEM secret, and App installation on `grob`.
- **No PRs after a successful scan:** check the Monday window and the Dependency
  Dashboard before changing the schedule.
- **CLA blocks the bot:** keep the App's exact bot login in the allowlist in
  [the CLA workflow](../../.github/workflows/cla.yml).
- **Rotate the private key:** generate a new key in the App settings, replace
  `RENOVATE_APP_PRIVATE_KEY`, and verify a dry run before deleting the old key.
- **Pause live updates:** set `RENOVATE_ENABLED` to `false`. Manual dry runs
  remain available. Set it back to `true` to resume scheduled scans.

Keep the pinned Renovate version and action revisions current through the
dependency PRs. The [runner configuration](../../.github/renovate-config.json)
contains installation settings; dependency policy belongs in `renovate.json`.
