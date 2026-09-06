#!/usr/bin/env bash
#
# Prove the Docker build context excludes credentials and .git, by building the
# image and reading the layers rather than by reading .dockerignore.
#
# The build stage does a bare `COPY . .`, so whatever is in the context ends up
# in a layer. A developer with a .env, a TLS key or a service-account file
# beside the source is the normal case, not the exotic one, and .dockerignore is
# the only thing standing between that file and a layer that gets cached,
# exported and sometimes pushed. Deleting a line from .dockerignore is a silent
# change; this makes it a failing build.
#
# The check plants credential-shaped fixtures - never a real credential - then
# builds the BUILD stage, because that is the stage the context lands in. The
# final image discards it, so scanning only the published image would pass no
# matter what .dockerignore said.
#
# Usage: scripts/check-build-context.sh
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

sentinel="build-context-check-sentinel-$$"
tmp="$(mktemp -d)"
planted=()

cleanup() {
	for f in "${planted[@]:-}"; do rm -f "$f"; done
	rm -rf "$tmp"
	docker image rm -f tollgate-build-context-check >/dev/null 2>&1 || true
}
trap cleanup EXIT

plant() {
	if [ -e "$1" ]; then
		echo "refusing to overwrite an existing $1; move it and re-run" >&2
		exit 1
	fi
	printf '%s\n' "$2" > "$1"
	planted+=("$1")
}

plant .env "ANTHROPIC_API_KEY=$sentinel"
plant .env.production "OPENAI_API_KEY=$sentinel"
plant tls.key "-----BEGIN PRIVATE KEY-----
$sentinel
-----END PRIVATE KEY-----"
plant service-account.pem "-----BEGIN RSA PRIVATE KEY-----
$sentinel
-----END RSA PRIVATE KEY-----"

echo "building the build stage with credential fixtures in the working tree"
DOCKER_BUILDKIT=1 docker build --target build -t tollgate-build-context-check . >/dev/null
docker save tollgate-build-context-check -o "$tmp/image.tar"

python3 - "$tmp/image.tar" "$sentinel" <<'PY'
import io, re, sys, tarfile

path, sentinel = sys.argv[1], sys.argv[2].encode()
# The build stage copies the context to /src, so only that subtree is this
# repository's doing. Everything else in these layers is the golang base image,
# whose own crypto test data is full of .pem files that are not ours.
OURS = re.compile(r"^src/")
GIT = re.compile(r"(^|/)\.git(/|$)")
CREDENTIAL_NAME = re.compile(r"(^|/)(\.env(\..*)?|.*\.(pem|key|p12|pfx))$")

problems, scanned, layers = [], 0, 0
with tarfile.open(path) as top:
    for member in top.getmembers():
        if not member.isfile():
            continue
        raw = top.extractfile(member).read()
        try:
            inner = tarfile.open(fileobj=io.BytesIO(raw))
        except tarfile.TarError:
            continue
        layers += 1
        for entry in inner:
            scanned += 1
            name = entry.name.lstrip("./")
            if not OURS.match(name):
                continue
            if GIT.search(name):
                problems.append(f"{name}: .git reached a build layer")
            if CREDENTIAL_NAME.search(name):
                problems.append(f"{name}: a credential-shaped file reached a build layer")
            if entry.isfile() and entry.size < (8 << 20):
                if sentinel in inner.extractfile(entry).read():
                    problems.append(f"{name}: carries the planted credential")

print(f"scanned {scanned} entries across {layers} layers")
if not problems:
    print("no .git and no credential material under /src in any layer")
    sys.exit(0)
for p in sorted(set(problems)):
    print("FAIL", p)
sys.exit(1)
PY
