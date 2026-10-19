# Releasing

se-check is published to PyPI through GitHub's trusted publishing: no PyPI token is stored
anywhere. Pushing a version tag runs [`.github/workflows/release.yml`](.github/workflows/release.yml),
which builds the package and publishes it.

## One-time setup

1. **PyPI.** Account settings → Publishing → *Add a new pending publisher*: project `se-check`,
   owner `devhardesian`, repository `se-check`, workflow `release.yml`, environment `pypi`.
2. **GitHub environment.** Repository settings → Environments → create `pypi`. Requiring a
   reviewer there means nothing is published without a click.

## Each release

1. In `CHANGELOG.md`, move the entries under `## [Unreleased]` to a new
   `## [0.2.0] - YYYY-MM-DD` section.
2. Bump the version and refresh the lock file:

   ```bash
   uv version --bump minor   # or patch / major
   uv lock
   ```

3. Commit, push, and wait for CI to be green.
4. Tag and push the tag:

   ```bash
   git tag v0.2.0
   git push origin v0.2.0
   ```

   The *Release* workflow checks that the tag matches the version in `pyproject.toml`, builds
   the package and publishes it.
5. Move the major tag the GitHub Action is used by (`uses: devhardesian/se-check@v0`):

   ```bash
   git tag -f v0
   git push -f origin v0
   ```
