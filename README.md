# SSRF testing framework - fixed/staged rewrite of the user's second script.
# Intended for authorized security testing / bug bounty scope only.
# Ensure you place this script in a folder with a targets.txt file.
#
# Usage:
#   ./ssrf-framework.sh [mode] [request_delay_seconds]
#
# The second argument is the delay between EVERY request (not between targets).
#
# Modes:
#   discover   OOB GET/POST/JSON/header discovery across HTTP/HTTPS and alternate schemes (default)
#   bypass     URL parser/filter bypass tests
#   protocols  Focused non-HTTP scheme capability re-test against your canary
#   internal   Internal reachability checks (requires ACTIVE_PARAM or ACTIVE_HEADER,
#              unless FORCE_BROAD_INTERNAL=1)
#   rebind     Send requests to a DNS rebinding domain you control
#   timing     Baseline-vs-candidate timing comparison
#   payloads   Run the embedded 429-line payload library against a confirmed input
#   all        discover + bypass + timing, plus internal/payloads/rebind only
#              when explicitly configured
#
# Examples:
#   COLLABORATOR="abc123.oastify.com" ./ssrf-framework.sh discover
#   COLLABORATOR="abc123.oastify.com" ACTIVE_PARAM="url" ./ssrf-framework.sh internal
#   ACTIVE_HEADER="X-Callback-URL" ./ssrf-framework.sh internal
#   REBIND_DOMAIN="rebind.example.com" ACTIVE_PARAM="url" ./ssrf-framework.sh rebind
#   PROXY="" ./ssrf-framework.sh discover 1   # 1 second between every request
#   QUERY_MODE=replace COLLABORATOR="abc123.oastify.com" ./ssrf-framework.sh discover
#   QUERY_MODE=duplicate ACTIVE_PARAM="url" ./ssrf-framework.sh discover
#   QUERY_MODE=both ACTIVE_PARAM="url" ./ssrf-framework.sh discover
#   QUERY_MODE=both COLLABORATOR="abc123.oastify.com" ./ssrf-framework.sh discover
#   CUSTOM_HEADER="X-HackerOne-Researcher: dreamsoftragedy" COLLABORATOR="abc123.oastify.com" ./ssrf-framework.sh discover
#   CUSTOM_HEADER_FILE="client-headers.txt" COLLABORATOR="abc123.oastify.com" ./ssrf-framework.sh discover
#
# Notes:
# - Redirects are NOT followed. This avoids false OOB positives caused by local curl.
# - GET query handling supports replacement and HTTP parameter pollution via QUERY_MODE.
# - Form values are URL encoded with --data-urlencode.
# - Every OOB request gets a unique subdomain label for correlation.
# - Discovery automatically tests http, https, ftp, ldap, dict, gopher, redis, smtp and smtps by default.
# - Automated metadata tests in internal mode use non-secret identification endpoints only.
# - payloads mode contains the full user-supplied payload library, including sensitive metadata paths;
#   use it only where the program rules authorize that validation depth.
