# Zenodo release process

## Verified v0.1.0 outcome

Zenodo was enabled for `governed-signal-to-content` before GitHub Release `v0.1.0` was created. Zenodo archived that Release successfully and issued the verified **version DOI** [10.5281/zenodo.21762787](https://doi.org/10.5281/zenodo.21762787).

The repository records only that verified version DOI. A Zenodo concept DOI has not been recorded or inferred; add one only if it is separately verified from the public Zenodo record.

## Procedure for future substantive releases

1. Complete a substantive version and its validation gates.
2. Push the reviewed commit to the public repository.
3. Confirm that the Zenodo GitHub integration remains connected and the repository remains enabled.
4. Confirm `.zenodo.json` metadata for the upcoming version without injecting a DOI from a prior version record.
5. Create one GitHub tag and Release only when the substantive version is ready.
6. Wait for Zenodo to process that specific Release.
7. Verify the new version record and its version DOI on the public Zenodo page.
8. Add only the actually issued DOI and badge in a later documentation commit.

Each future Zenodo release record receives its own version DOI. Do not reuse `10.5281/zenodo.21762787` as another version's DOI, invent a placeholder DOI, or claim archival completion before the new record is publicly verifiable.
