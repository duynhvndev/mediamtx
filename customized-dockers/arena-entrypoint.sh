#!/bin/sh
# Entrypoint of the Arena mediamtx image.
#
# /pvc/live is one RWX PVC shared by every pod of the StatefulSet, so each pod
# logs under its own server id: /pvc/live/logs/<server>/{mediamtx,send-kafka}.log
# (go-rest writes go-rest.log in the same dir). Records already go to
# /pvc/live/recordings/<server>/<key>/ through recordPath %path.
#
# Server id = go-rest rule (service/server_id.go): pod hostname live-<region>-<n>
# -> live-<region>-NN. The mounted PVC starts empty and the mediamtx file logger
# does not create its directory, hence the mkdir.
#
# Config on the shared PVC (PVC dir config/, mounted at /pvc/live/config; ops
# edit it from the management pod, then restart the pod):
# - mediamtx.env: KEY=VALUE lines (MTX_* overrides, KAFKA_BROKERS for
#   send-kafka.sh, ...), exported to mediamtx and its hook scripts. Its values
#   win over the pod env, except HOSTNAME.
# - mediamtx.yml: used instead of the image's /mediamtx.yml when present and no
#   config path is given as argument.
set -e

host="${HOSTNAME:-$(hostname)}"
config_dir="${ARENA_CONFIG_DIR:-/pvc/live/config}"

env_file="${ARENA_ENV_FILE:-$config_dir/mediamtx.env}"
if [ -f "$env_file" ]; then
  set -a
  . "$env_file"
  set +a
  export HOSTNAME="$host"
  echo "arena-entrypoint: loaded $env_file" >&2
fi

if [ "$#" -eq 0 ] && [ -f "$config_dir/mediamtx.yml" ]; then
  set -- "$config_dir/mediamtx.yml"
fi
echo "arena-entrypoint: config ${1:-/mediamtx.yml}" >&2
server=$(printf '%s\n' "$host" | awk -F- '
  NF == 3 && $1 == "live" && $2 ~ /^[a-z]+$/ && $3 ~ /^[0-9]+$/ { printf "live-%s-%02d", $2, $3; found = 1 }
  END { exit !found }') || {
  echo "arena-entrypoint: hostname '$host' is not live-<region>-<n>" >&2
  exit 1
}

export ARENA_LOG_DIR="/pvc/live/logs/$server"
mkdir -p "$ARENA_LOG_DIR" /pvc/live/recordings
# Env overrides mediamtx.yml logFile; keep an explicit MTX_LOGFILE if set.
export MTX_LOGFILE="${MTX_LOGFILE:-$ARENA_LOG_DIR/mediamtx.log}"

exec /mediamtx "$@"
