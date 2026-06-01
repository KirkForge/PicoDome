#!/usr/bin/env bash
# Compile PicoDome gRPC protobuf stubs
# Requires: pip install grpcio-tools
set -euo pipefail

PROTO_DIR="$(dirname "$0")/../src/picodome/grpc_transport/proto"
OUT_DIR="$PROTO_DIR"

echo "Compiling picodome.proto → pb2/pb2_grpc stubs..."
python -m grpc_tools.protoc \
  -I "$PROTO_DIR" \
  --python_out="$OUT_DIR" \
  --grpc_python_out="$OUT_DIR" \
  "$PROTO_DIR/picodome.proto"

# Fix relative imports in generated _grpc.py
sed -i 's/import picodome/from . import picodome/' "$OUT_DIR/picodome_pb2_grpc.py" 2>/dev/null || true

echo "Done. Generated:"
ls -la "$OUT_DIR"/picodome_pb2*.py 2>/dev/null
