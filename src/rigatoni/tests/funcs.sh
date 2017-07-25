# vim:ft=sh

fixtures="$top_srcdir/tests/fixtures"

do_at_exit="echo Have a nice day"
at_exit() {
  do_at_exit="$1; $do_at_exit"
}

add_temp_file() {
  at_exit "rm -f '$temp_files'"
}

kill_recurs() {
  local pid="$1"
  pgrep -P "$pid" | while read child ; do
    kill_recurs "$child" ;
  done
  kill "$pid" || true # may have died already
}

add_temp_pid() {
  at_exit "kill_recurs '$1'"
}

file_with() {
  f=$(tempfile)
  add_temp_file "$f"
  cat > "$f"
}

# RANDOM returns a number between 0 and 32767
RAMEN_HTTP_PORT=$(shuf -i 1024-65536 -n 1)
export RAMEN_HTTP_PORT

RAMEN_URL="http://127.0.0.1:$RAMEN_HTTP_PORT"
export RAMEN_URL

rigatoni="$top_srcdir/rigatoni"

init() {
  $rigatoni start &
  add_temp_pid $!
  sleep 0.5
}

add_node() {
  $rigatoni add-node "$1" "$2"
  while test -n "$3" ; do
    $rigatoni add-link "$3" "$1"
    shift
  done
}

run() {
  $rigatoni compile &&
  $rigatoni run
}

tail_() {
  $rigatoni tail --cont --last "$1" --as-csv "$2"
}

check_equal() {
  if test "$1" != "$2" ; then
    echo "Not equals: '$1' and '$2'"
    exit 1
  fi
}

stop() {
  eval "$do_at_exit"
}

trap stop EXIT
trap stop 2