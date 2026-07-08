# AegisAgent GitHub App manifest

`aegis-app-manifest.json` is a [GitHub App manifest](https://docs.github.com/en/apps/sharing-github-apps/registering-a-github-app-from-a-manifest) — the fastest way to register the App with exactly the permissions AegisAgent's GitHub integration actually uses, no manual checkbox-clicking through GitHub's permission list required. See [`docs/github-integration.md`](../docs/github-integration.md) for the full setup guide (env vars, webhook config, obtaining a bearer token); this file only covers registering the App itself.

## Minimum permissions, and why each one is there

| Permission | Level | Used by |
|---|---|---|
| `metadata` | Read | Mandatory baseline for every GitHub App — cannot be omitted. |
| `pull_requests` | Read | `gh_checks.rs`'s `fetch_head_sha` (`GET /repos/{repo}/pulls/{pr_number}`) — needs the PR's head commit SHA to attach a check run to. |
| `issues` | Write | `gh_comment.rs`'s deny-comment poster (`POST /repos/{repo}/issues/{pr_number}/comments`) — GitHub's issue-comment endpoint also serves pull requests, since a PR is an issue under the hood; no separate "pull request write" scope exists for commenting. |
| `checks` | Write | `gh_checks.rs`'s check-run create/update (`POST`/`PATCH /repos/{repo}/check-runs`) — the "Aegis Security Gate" check surfaced on every PR. |

Deliberately **not** requested: `contents` (AegisAgent never reads file contents or diffs — the trust-provenance gate is a Cedar policy decision, not a code scan) and `pull_requests: write` (Aegis never merges, closes, or edits a PR directly; the check-run conclusion is what blocks a merge, via the repo's own branch-protection rule requiring it to pass).

## Subscribed events

`pull_request`, `issues`, `issue_comment` — exactly the three event types `lib/soc/src/ingest.rs::normalize_github_native_event` recognizes (see `docs/github-integration.md` §3.1). `push` is deliberately not subscribed: nothing in the ingestion pipeline handles it today, and requesting an event the App can't act on just adds unnecessary access for no behavior.

## Registering the App

AegisAgent does not implement the manifest-flow *server-side* callback (the `code` → App credentials exchange) — you complete that step yourself, once, outside the gateway:

1. **Submit the manifest.** POST the contents of `aegis-app-manifest.json` as the `manifest` field of an HTML form to GitHub's manifest-flow URL — the simplest way is to open a browser, paste this into the console on `https://github.com/settings/apps/new` (or `https://github.com/organizations/<org>/settings/apps/new` for an org-owned App):

   ```js
   const form = document.createElement("form");
   form.method = "POST";
   form.action = "https://github.com/settings/apps/new";
   const input = document.createElement("input");
   input.name = "manifest";
   input.value = JSON.stringify(/* paste aegis-app-manifest.json here */);
   form.appendChild(input);
   document.body.appendChild(form);
   form.submit();
   ```

   Update `hook_attributes.url` in the manifest to your real gateway host first (`https://<your-gateway-host>/v1/webhooks/github`).

2. **Confirm creation.** GitHub redirects back with a one-time `code` query parameter (to `url` in the manifest, since no `redirect_url` is set here — GitHub falls back to showing it on the page itself).

3. **Exchange the code for credentials** (once, not part of any AegisAgent server):

   ```bash
   curl -X POST "https://api.github.com/app-manifests/<code>/conversions" \
     -H "Accept: application/vnd.github+json"
   ```

   The response includes `id` (App ID), `pem` (private key), and `webhook_secret`. `webhook_secret` maps directly to `AEGIS_GITHUB_WEBHOOK_SECRET`. `id` + `pem` are what you use to mint the short-lived installation access token (`AEGIS_GITHUB_APP_TOKEN`) per `docs/github-integration.md` §2 — AegisAgent expects that token handed to it as a plain string; it does not perform the JWT signing or token-refresh itself.

4. **Install the App** on the repos it should protect, then follow `docs/github-integration.md` from §1 onward.
