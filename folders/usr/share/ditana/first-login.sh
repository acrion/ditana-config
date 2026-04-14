#!/usr/bin/env bash

# Copyright (c) 2024, 2025 acrion innovations GmbH
# Authors: Stefan Zipproth, s.zipproth@acrion.ch
#
# This file is part of Ditana Installer, see
# https://github.com/acrion/ditana-installer and https://ditana.org/installer.
#
# Ditana Installer is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ditana Installer is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ditana Installer. If not, see <https://www.gnu.org/licenses/>.

# This script is executed once after the first desktop environment login of each user via
# /etc/xdg/autostart/ditana-first-login.desktop.
# After execution, it disables itself for the current user using the XDG
# autostart override mechanism (Hidden=true in ~/.config/autostart/).

shopt -s dotglob
mkdir -p "$HOME/.ditana"
LOG_PATH="$HOME/.ditana/first-login.log"

{
    # Creating a file in /etc/dconf/db/local.d/ does not work, presumably due to how XFCE emulates dconf.
    # Example settings that would be configured there:
    # [org/gnome/desktop/interface]
    # monospace-font-name='JetBrainsMono Nerd Font 9'
    gsettings set org.gnome.desktop.interface monospace-font-name 'JetBrainsMono Nerd Font 9'
    gsettings set org.gnome.desktop.interface color-scheme prefer-dark
    gsettings set org.gnome.desktop.interface gtk-theme 'Dracula'
    gsettings set org.gnome.desktop.interface icon-theme 'kora-yellow'

    # DEPRECATED: The following two settings are maintained for backwards compatibility
    # with XFCE's dconf compatibility mode. While no longer actively used in modern GNOME
    # environments, retaining these settings ensures system stability and doesn't
    # introduce any adverse effects.
    # The primary configuration for the default terminal is now managed through
    # the '/etc/xdg/xdg-terminals.list' file.
    # For more information, refer to: https://github.com/Vladimir-csp/xdg-terminal-exec
    gsettings set org.gnome.desktop.default-applications.terminal exec 'xdg-terminal-exec'
    gsettings set org.gnome.desktop.default-applications.terminal exec-arg '-e'

    # Workaround for gnome-keyring initialization issue on first login
    # This restarts the gnome-keyring-daemon to ensure proper initialization
    # The user will still need to unlock the keyring via a dialog, but this prevents
    # tools like secret-tool from freezing and allows the browser to start properly
    # For more information, see: https://gitlab.gnome.org/GNOME/gnome-keyring/-/issues/116
    systemctl --user restart gnome-keyring-daemon.service

    # Audio is muted by default for new users (especially post-installation), requiring an adjustment.
    # Adding a delay to avoid setting volume during xfce4-pulseaudio-plugin initialization,
    # as this seems to cause sporadic crashes.
    sleep 2
    pactl set-sink-mute @DEFAULT_SINK@ 0
    pactl set-sink-volume @DEFAULT_SINK@ 50%

    # Disable this autostart entry for the current user using the XDG override mechanism
    AUTOSTART_NAME="ditana-first-login.desktop"
    mkdir -p "$HOME/.config/autostart"
    cp "/etc/xdg/autostart/$AUTOSTART_NAME" "$HOME/.config/autostart/$AUTOSTART_NAME"
    sed -i 's/^Hidden=false/Hidden=true/' "$HOME/.config/autostart/$AUTOSTART_NAME"
} 2>&1 | tee -a "$LOG_PATH"
