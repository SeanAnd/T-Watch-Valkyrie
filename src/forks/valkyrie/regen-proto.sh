#!/usr/bin/env bash
#
# Fork-local nanopb regenerator for the Valkyrie threat-event protobuf.
#
# IMPORTANT: this script writes only into firmware/src/forks/valkyrie/proto/generated/
# and never touches firmware/src/mesh/generated/. That is the entire reason it is
# separate from the upstream firmware/bin/regen-protos.sh script.
#
# Requires nanopb 0.4.9 (same major version as upstream firmware uses).
# If you don't have it installed, grab the prebuilt binary from
# https://jpa.kapsi.fi/nanopb/download/ and drop it under
# firmware/nanopb-0.4.9/ (same convention as bin/regen-protos.sh).

set -euo pipefail

THIS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIRMWARE_ROOT="$(cd "$THIS_DIR/../../.." && pwd)"

PROTOC="${FIRMWARE_ROOT}/nanopb-0.4.9/generator-bin/protoc"
if [[ ! -x "$PROTOC" ]]; then
    PROTOC="$(command -v protoc-nanopb || command -v nanopb_generator || true)"
fi
if [[ -z "${PROTOC:-}" || ! -x "$PROTOC" ]]; then
    echo "regen-proto.sh: nanopb protoc not found." >&2
    echo "  expected: ${FIRMWARE_ROOT}/nanopb-0.4.9/generator-bin/protoc" >&2
    echo "  download from https://jpa.kapsi.fi/nanopb/download/" >&2
    exit 1
fi

cd "$THIS_DIR/proto"

mkdir -p generated

"$PROTOC" \
    --experimental_allow_proto3_optional \
    "--nanopb_out=-S.cpp -v:./generated" \
    -I="$THIS_DIR/proto" \
    threat_event.proto

echo "Regenerated $(ls generated/threat_event.pb.* 2>/dev/null | tr '\n' ' ')"
