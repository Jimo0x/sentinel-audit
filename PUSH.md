# Pushing this to a private GitHub repo

The project is already a git repository with an initial commit. To publish it as a
**private** repo on your own account, run these from inside the extracted folder:

## Option A — with the GitHub CLI (easiest)

```bash
gh repo create sentinel-audit --private --source=. --remote=origin --push
```

## Option B — plain git

1. Create an empty **private** repo named `sentinel-audit` on GitHub
   (https://github.com/new — do not add a README/license, the repo already has them).
2. Then:

```bash
git remote add origin git@github.com:<your-username>/sentinel-audit.git
# or https: git remote add origin https://github.com/<your-username>/sentinel-audit.git
git push -u origin main
```

That's it. The commit history and authorship are already in place.
