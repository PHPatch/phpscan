#!/usr/bin/env bash
# Regenerate phpscan's advisory DB + public feeds.
#
# Cron-ready. Suggested wiring next to the phpatch threat swarm
# (which already polls the NVD API every 2h; services.nvd.nist.gov
# and www.php.net are the only hosts this touches):
#
#   17 */6 * * *  cd ~/workspace/phpscan-public && \
#       tools/refresh_advisory_db.sh && \
#       git add phpscan/data/cves.json feeds && \
#       git commit -m "advisory db refresh" && git push
#
# (Commit/push stays a reviewed step — CODEOWNERS requires review
# of cves.json because it changes scanner verdicts — so the git
# part above is an example for the maintainer's own cron, and the
# swarm itself should only run this script and surface the diff.)
set -euo pipefail
cd "$(dirname "$0")/.."
python3 tools/build_core_db.py "$@"
python3 tools/build_feed.py
