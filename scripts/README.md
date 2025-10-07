# Scripts

Simple scripts for development and release.

## dev.sh - Development Tools

```bash
./scripts/dev.sh test      # Run tests
./scripts/dev.sh format    # Format code
./scripts/dev.sh analyze   # Analyze code
./scripts/dev.sh check     # All at once (format + analyze + test)
./scripts/dev.sh deps      # Update dependencies
./scripts/dev.sh changelog # Preview changelog
./scripts/dev.sh coverage  # Tests with coverage
```

## release.sh - Package Release

```bash
./scripts/release.sh 1.0.1          # Prepare release
./scripts/release.sh 1.0.1 --publish # Prepare and publish
```

What it does:

1. Checks tests, formatting, analysis
2. Updates version in pubspec.yaml
3. Creates git tag
4. Generates changelog
5. Commits changes
6. Validates package
7. Publishes (if --publish)
