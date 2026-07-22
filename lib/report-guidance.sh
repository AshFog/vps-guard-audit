#!/usr/bin/env bash
# shellcheck shell=bash

finding_bucket() {
  local id="$1"
  case "$id" in
    port.*|docker.published|login.*|proxy.*) printf '%s' confirm ;;
    *) printf '%s' improve ;;
  esac
}

finding_plain_text() {
  local id="$1" rec="$2"
  PLAIN_MEANING=""
  PLAIN_ACTION="$rec"
  PLAIN_CAUTION=""
  if [[ "$LANGUAGE" == zh ]]; then
    finding_plain_text_zh "$id"
  else
    finding_plain_text_en "$id"
  fi
}
