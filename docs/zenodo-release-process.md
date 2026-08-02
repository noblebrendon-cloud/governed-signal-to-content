# Zenodo release process

The initial public repository push is intentionally not a GitHub Release. Complete these steps in order:

1. Push the public repository.
2. Sign in to Zenodo.
3. Connect the GitHub account if necessary.
4. Open the Zenodo GitHub integration.
5. Sync repositories.
6. Enable `governed-signal-to-content`.
7. Confirm `.zenodo.json` metadata.
8. Only then create GitHub Release `v0.1.0`.
9. Wait for Zenodo to process the release.
10. Add the real DOI and badge in a later commit.

Do not invent a DOI or use a placeholder that resembles one. Do not claim archival status until Zenodo has processed the enabled repository's actual GitHub Release.
