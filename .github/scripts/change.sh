#!/usr/bin/env bash
# Finds the change request a release run is for:
#
#     GH_TOKEN=... SOURCE_SHA=<commit> [CHANGE=<7|#7|CHG-7>] [REQUIRE=true] bash .github/scripts/change.sh
#
# In order: CHANGE if given; else the open `change` issue an approver picked
# with a `/release <sha|run-url>` comment; else the one open `change` issue
# whose Release field (.github/ISSUE_TEMPLATE/change-request.yml) names
# SOURCE_SHA (the full SHA or a prefix of at least 7) or this run's URL.
# Writes id=CHG-<n>, number=, url=, state=, labels= (JSON array) and
# chosen_by= to $GITHUB_OUTPUT. Finding none, or more than one, leaves id
# empty; with REQUIRE=true it's an error.
#
# The comment is the explicit choice, and it comes first: a change request
# opened before the Release field existed has no heading to fill, and nobody
# can pass a number to a run the pipeline started — commenting on the request
# the release belongs to is how an approver says which one it is, before
# approving prod.
set -euo pipefail

run_url="${GITHUB_SERVER_URL}/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}"
issue_url="https://github.com/${GITHUB_REPOSITORY}/issues"
none() {
  if [ "${REQUIRE:-}" = true ]; then echo "::error::$1"; exit 1; fi
  echo "::notice::$1"; exit 0
}
names_this_release() {  # a Release value / `/release` argument naming this release
  local v=${1%/}
  [ "$v" = "$run_url" ] && return 0
  case "$v" in *[!0-9a-f]*) return 1 ;; esac
  [ "${#v}" -ge 7 ] && [ "${#v}" -le 40 ] && [ "${SOURCE_SHA#"$v"}" != "$SOURCE_SHA" ]
}
if [ -n "${CHANGE:-}" ]; then
  n=$(sed -E 's/^[[:space:]]*(#|[Cc][Hh][Gg]-)?//; s/[[:space:]]*$//' <<<"$CHANGE")
  [[ "$n" =~ ^[0-9]+$ ]] || none "'${CHANGE}' isn't a change request number (7, #7 or CHG-7)"
  issue=$(gh api "repos/${GITHUB_REPOSITORY}/issues/${n}" 2>/dev/null) \
    || none "CHG-${n}: issue #${n} doesn't exist — open one with the Change request form"
  jq -e '.pull_request == null' <<<"$issue" > /dev/null || none "#${n} is a pull request, not a change request"
  chosen_by="the change input"
else
  # The Release field's value is the first line after the "### Release"
  # heading that isn't another heading: GitHub renders a form's answer as
  # "### Release\n\n<value>", and an unanswered field as "### Release\n\n\n### Next".
  all=$(gh api --paginate "repos/${GITHUB_REPOSITORY}/issues?labels=change&state=open&per_page=100" \
    | jq -s 'add // [] | [.[] | select(.pull_request == null)]')
  matches=$(jq -c --arg sha "$SOURCE_SHA" --arg run "$run_url" '[
        .[] | ((.body // "") | (try (capture("### Release[ \t]*[\r\n]+[ \t]*[\r\n]*(?<v>[^#\r\n][^\r\n]*)").v) catch "") | gsub("^\\s+|\\s+$"; "") | rtrimstr("/")) as $r
        | select($r == $run or (($r | test("^[0-9a-f]{7,40}$")) and ($sha | startswith($r))))]' <<<"$all")
  count=$(jq length <<<"$matches")

  # What each open change request offers: its Release value and any
  # `/release <value>` comment. Only a comment's *first line* counts, so
  # ordinary prose that mentions a sha is never read as a choice.
  open_list="" ; chosen="" ; chosen_by=""
  for n in $(jq -r '.[].number' <<<"$all"); do
    t=$(jq -r --argjson n "$n" '.[] | select(.number == $n) | (.title) | sub("^CHG: *"; "")' <<<"$all")
    r=$(jq -r --argjson n "$n" '.[] | select(.number == $n) | (.body // "")
          | [match("### Release[ \t]*[\r\n]+[ \t]*[\r\n]*(?<v>[^#\r\n][^\r\n]*)")]
          | (.[0].captures[0].string? // "") | gsub("^\\s+|\\s+$"; "")' <<<"$all")
    # GitHub renders an unanswered optional field as "_No response_".
    case "$r" in ""|"_No response_") r="no Release value" ;; esac
    picked=$(gh api --paginate "repos/${GITHUB_REPOSITORY}/issues/${n}/comments?per_page=100" 2>/dev/null \
      | jq -s -r '[add // [] | .[] | ((.body // "") | split("\n")[]) | (try (capture("^/release[ \t]+(?<v>\\S+)[ \t]*$").v) catch empty)] | .[]' || true)
    picked_list=""
    for v in $picked; do
      picked_list="${picked_list}${picked_list:+, }${v}"
      if names_this_release "$v"; then
        if [ -z "$chosen" ]; then chosen=$n; chosen_by="/release ${v}"; else
          none "/release on more than one open change request names this release (CHG-${chosen} and CHG-${n}) — delete the one that isn't meant"
        fi
      fi
    done
    labels=$(jq -r --argjson n "$n" '.[] | select(.number == $n) | [.labels[].name] | join(", ")' <<<"$all")
    open_list="${open_list}${open_list:+; }CHG-${n} (${t}) [${labels:-no labels}]: Release = ${r}${picked_list:+; /release comments: ${picked_list}} — ${issue_url}/${n}"
  done
  [ -n "$open_list" ] || open_list="no open issue carries the change label"

  if [ -n "$chosen" ]; then
    issue=$(jq -c --argjson n "$chosen" '.[] | select(.number == $n)' <<<"$all")
    if [ "$count" -gt 0 ] && [ "$(jq -r '.[0].number' <<<"$matches")" != "$chosen" ]; then
      echo "::notice::/release chose CHG-${chosen}; the Release field of CHG-$(jq -r '.[0].number' <<<"$matches") also names this release"
    fi
  elif [ "$count" = 1 ]; then
    issue=$(jq '.[0]' <<<"$matches")
    chosen_by="its Release field"
  else
    if [ "$count" = 0 ]; then
      none "no open change request names ${SOURCE_SHA:0:7} or this run — neither in its Release field nor by a /release comment. Open ones: ${open_list}. Pick one by commenting '/release ${SOURCE_SHA:0:7}' on it, by running the 'Pick the change request for a release' workflow with its number, or by filling its Release field"
    else
      none "${count} open change requests name ${SOURCE_SHA:0:7} or this run; comment '/release ${SOURCE_SHA:0:7}' on the one meant, or pass its number as the change input on a manual run. Open ones: ${open_list}"
    fi
  fi
fi
n=$(jq -r .number <<<"$issue")
# GITHUB_OUTPUT is set by Actions; a maintainer running this by hand gets the
# printed line instead of an unbound-variable error.
out_file=${GITHUB_OUTPUT:-/dev/null}
{ echo "id=CHG-${n}"; echo "number=${n}"; echo "url=$(jq -r .html_url <<<"$issue")"
  echo "state=$(jq -r .state <<<"$issue")"; echo "labels=$(jq -c '[.labels[].name]' <<<"$issue")"
  echo "author=$(jq -r '.user.login // empty' <<<"$issue")"
  echo "chosen_by=${chosen_by:-its Release field}"; } >> "$out_file"
echo "Change request: CHG-${n} ($(jq -r .title <<<"$issue")) — chosen by ${chosen_by:-its Release field}"
