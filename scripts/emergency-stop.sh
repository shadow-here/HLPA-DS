#!/usr/bin/env bash
# EMERGENCY kill switch: stop all decoy containers immediately.
echo "Stopping all HLPA-DS decoy containers..."
docker stop hlpa-cowrie hlpa-opencanary hlpa-http-decoy || true
echo "Decoys stopped. The dashboard and API keep running for review."
