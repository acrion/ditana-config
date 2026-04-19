# XDG Base Directory Specification defaults for interactive login shells
# (TTY, SSH). See https://specifications.freedesktop.org/basedir-spec/
# Conditional assignments respect values the user may have set earlier.
: "${XDG_DATA_HOME:=$HOME/.local/share}"
: "${XDG_CONFIG_HOME:=$HOME/.config}"
: "${XDG_STATE_HOME:=$HOME/.local/state}"
: "${XDG_CACHE_HOME:=$HOME/.cache}"
export XDG_DATA_HOME XDG_CONFIG_HOME XDG_STATE_HOME XDG_CACHE_HOME
