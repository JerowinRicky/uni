# CI and Workflow Automation Setup

## Personal Access Token (PAT) Scope Notice
When pushing workflow changes in `.github/workflows/`, GitHub enforces that the Personal Access Token (PAT) must have the `workflow` scope.
If your token was created without the `workflow` scope:
- Pushes containing `.github/workflows/*.yml` will be rejected by GitHub with:
  `refusing to allow a Personal Access Token to create or update workflow without 'workflow' scope`.
- The production CI configuration is maintained at `ci/github-actions-ci.yml`.

### Enabling GitHub Actions CI:
1. Generate a GitHub PAT with `repo` and `workflow` scopes.
2. Copy `ci/github-actions-ci.yml` to `.github/workflows/ci.yml`.
3. Commit and push:
   ```bash
   mkdir -p .github/workflows
   cp ci/github-actions-ci.yml .github/workflows/ci.yml
   git add .github/workflows/ci.yml
   git commit -m "ci: enable github actions workflow"
   git push origin main
   ```

### Release Mode Dev-Key Invariant
The CI workflow executes `cargo test --release` to verify that release builds strictly reject development keys (`ur-dev-key`).

