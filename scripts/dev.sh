#!/bin/bash
# Dev tools for seckit

case "$1" in
"test")
	dart test
	;;
"format")
	dart format .
	;;
"analyze")
	dart analyze
	;;
"check")
	echo "Running format + analyze + test..."
	dart format .
	dart analyze
	dart test
	echo "✅ All checks passed!"
	;;
"deps")
	dart pub get
	;;
"changelog")
	git cliff --unreleased
	;;
"coverage")
	dart test --coverage=coverage
	;;
*)
	echo "Usage: $0 <command>"
	echo "Commands: test, format, analyze, check, deps, changelog, coverage"
	;;
esac
