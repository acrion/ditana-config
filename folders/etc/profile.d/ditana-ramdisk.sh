# Expose the RAM-backed scratch directory to interactive login shells
# (TTY, SSH). The directory itself is created by systemd-tmpfiles (see
# ~/.config/user-tmpfiles.d/ditana-ramdisk.conf).
export RAMDISK="$XDG_RUNTIME_DIR/ramdisk"
