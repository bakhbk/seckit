#!/bin/bash
# Simple release script for seckit
set -e

# Check version argument
if [ -z "$1" ]; then
	echo "Usage: $0 <version> [--publish]"
	echo "Example: $0 1.0.1"
	exit 1
fi

VERSION="$1"
echo "🚀 Releasing version $VERSION"

# Run checks
echo "Running tests..."
dart test

echo "Checking format..."
dart format .

echo "Running analysis..."
dart analyze

# Update version
echo "Updating version in pubspec.yaml..."
sed -i.bak "s/^version: .*/version: $VERSION/" pubspec.yaml
rm pubspec.yaml.bak

# Git operations
echo "Creating git tag..."
git tag "v$VERSION" 2>/dev/null || echo "Tag already exists"

echo "Generating changelog..."
git cliff --output CHANGELOG.md

echo "Committing changes..."
git add pubspec.yaml CHANGELOG.md
git commit -m "release: v$VERSION" || echo "Nothing to commit"

# Validate
echo "Validating package..."
dart pub publish --dry-run

# Publish if requested
if [ "$2" = "--publish" ]; then
	echo "Publishing to pub.dev..."
	dart pub publish
	echo "✅ Published!"
else
	echo "✅ Ready to publish! Run: dart pub publish"
fi
