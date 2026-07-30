#!/usr/bin/env bash
#
# Enforce mailkey's dependency contract.
#
# The protocol packages — the root, manifest, discovery, envelope, resolver,
# peer and wellknown — MUST depend on nothing but the standard library, the
# canonical MessagePack codec (go.arpabet.com/value) and xerrors. Dependency
# injection lives ONLY in component/, which is the one package allowed to import
# glue and zap.
#
# This is not tidiness. The whole reason a host application can adopt MKDP1 is
# that the protocol does not drag a framework or a logger in with it: a project
# using a different container, or none, imports the same packages and gets the
# same bytes. One import added in the wrong package silently ends that, and the
# only symptom would be someone else's build.
#
set -euo pipefail

cd "$(dirname "$0")/.."

# Packages that carry the protocol. component/ is deliberately absent.
core_pkgs=(. ./manifest ./discovery ./envelope ./resolver ./peer ./wellknown ./message)

# Modules the protocol must never reach. glue is the DI container, zap the
# logger; both belong to the host application's choices, not to the format.
forbidden='go\.arpabet\.com/glue|go\.uber\.org/zap|go\.uber\.org/multierr'

violations=""
for pkg in "${core_pkgs[@]}"; do
  deps="$(GOWORK=off go list -deps "$pkg" 2>/dev/null || true)"
  hit="$(printf '%s\n' "$deps" | grep -E "$forbidden" || true)"
  if [ -n "$hit" ]; then
    violations+="$(printf '%s -> %s\n' "$pkg" "$(printf '%s' "$hit" | sort -u | tr '\n' ' ')")"$'\n'
  fi
done

if [ -n "$violations" ]; then
  {
    echo "✗ mailkey dependency violation — the protocol packages must stay framework-free:"
    printf '%s' "$violations" | sed 's/^/    /'
    echo
    echo "glue and zap belong in component/ only. A host application using another"
    echo "container — or none — must be able to import the protocol without them."
  } >&2
  exit 1
fi

echo "✓ mailkey core is framework-free — glue/zap confined to component/"
