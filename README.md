# Ditana Configuration

The "brain" of the [Ditana GNU/Linux](https://ditana.org) installer — a structured knowledge base that drives the entire installation process.

## What is this?

This repository encodes everything the [Ditana installer](https://github.com/acrion/ditana-installer) needs to know about how a Ditana system is built, on top of vanilla Arch Linux:

- **Hardware properties** — auto-detected at installer start (GPU vendor, CPU vendor, virtualization, vulnerabilities, RAM, …)
- **Installation steps** — the sequence of dialogs and procedures the user walks through
- **Settings** — every package selection, every desktop tweak, every kernel flag, every system-hardening option
- **Configuration files** — default dotfiles, system configs, scripts, and templates deployed during installation
- **Scripts** — what runs during chroot, after first reboot, and at first or subsequent logins

All of this is expressed in [KDL v2](https://kdl.dev), a human-friendly document language. The installer code itself stays small; the real complexity lives here as data with logical relationships between settings.

The installer reads this repository at runtime — both at ISO build time and at installation time — so improvements ship to users without re-spinning an ISO.

## How the installer uses this repo

At a high level, the installer goes through these phases. Knowing this is essential before you can reason about *where* a snippet of code from this repo runs.

```
1. Hardware detection         ── settings with `detect=...` are evaluated
2. Settings load              ── all other settings get their default values
3. Dialog flow                ── installation-steps drive the user through dialogs
4. (real install only) Disk partitioning, mounting, pacstrap into /mnt
5. files/ → /mnt              ── files referenced by enabled settings are copied
6. arch-chroot /mnt:
     a. early-chroot-script   ── runs BEFORE user creation (patch /etc/skel here)
     b. user creation         ── /etc/skel becomes the new user's home
     c. chroot-script         ── system-level config in chroot
7. Reboot
8. ditana-initialize-system.service runs ONCE:
     a. root-script           ── post-install actions as root
9. User logs in, session-setup runs:
     a. first-login-{scripts,commands}  ── once per user, then deletes a marker
     b. login-{scripts,commands}        ── on every login
10. XDG autostart entries fire (per-DE handling)
```

Each setting can contribute snippets to any of these phases. The order of execution **within** a single phase is undefined — never write code that assumes "setting A's chroot-script runs before setting B's."

## Repository structure

```
ditana-config/
├── ditana-schema.json         # JSON schema; the contract for every KDL field
├── installation-steps.kdl     # Dialog sequence and UI structure
├── settings/
│   ├── hardware-detection.kdl # Auto-detected hardware properties
│   ├── base-packages.kdl      # Core packages always or conditionally installed
│   ├── installer-state.kdl    # User-entered state: disk, locale, user, …
│   └── dialogs/               # Settings corresponding to installer dialogs
│       ├── ai-tools.kdl
│       ├── browser.kdl
│       ├── desktop-appearance.kdl
│       ├── desktop-applications.kdl
│       ├── multimedia.kdl
│       ├── office.kdl
│       ├── user-profile.kdl
│       ├── desktop-environment/  # Compositor-specific settings
│       │   ├── cosmic.kdl
│       │   ├── niri.kdl
│       │   ├── wayfire.kdl
│       │   ├── xfce.kdl
│       │   └── wayland*.kdl       # Settings shared across Wayland DEs
│       ├── advanced/              # "Advanced Settings" submenu
│       │   ├── filesystem.kdl
│       │   ├── hardware-support.kdl
│       │   ├── kernel-selection.kdl
│       │   ├── network-security.kdl
│       │   ├── terminal-emulator.kdl
│       │   ├── terminal-tools.kdl
│       │   └── …
│       └── expert/                # "Expert Settings" submenu
│           ├── cpu-mitigations.kdl
│           ├── kernel-configuration.kdl
│           ├── system-allocator.kdl
│           ├── system-hardening.kdl
│           └── umask.kdl
├── folders/                   # Configuration files deployed during installation
│   ├── etc/
│   └── usr/
├── json-kdl-converter/        # Rust tool: converts KDL → JSON for the installer
├── validate-logic.py          # Pre-commit logic + shellcheck validator
└── .pre-commit-config.yaml    # Hooks: kdlfmt, schema, logic, shellcheck
```

## KDL essentials

We use [KDL v2](https://kdl.dev). The features you'll meet in this repo:

| Feature | Syntax | Notes |
| --- | --- | --- |
| Comments | `// line`, `/* block */` | |
| Node comment | `/-` | Comments out the *next* node — useful to disable a setting temporarily |
| Strings | `"..."` | Standard double-quoted |
| Raw strings | `#"..."#` | Embed bash, sed, awk without escaping `"` and `\` |
| Higher raw levels | `##"..."##`, `###"..."###` | Use when content contains `"#` itself |
| Booleans | `#true`, `#false` | The `#` sigil is mandatory in KDL v2 |
| Null | `#null` | |
| Line continuation | `\` at end of line | Newline becomes whitespace |
| Children | `{ ... }` | Nested nodes |
| Properties | `name=value` | On the same node |

### Why every node starts with `-`

Every setting and every installation step starts with a literal hyphen as its node name:

```kdl
- name="install-audio" default-value=#true { ... }
```

The dash is just a node name. Our `json-kdl-converter` translates `- ...` nodes into JSON array elements; properties become object fields; children become nested arrays/objects. This convention keeps the KDL diff-friendly and lets us preserve insertion order.

### Strings vs raw strings — when to use which

Use a regular string `"..."` when the content has no embedded double quotes or backslashes that confuse you. Use a raw string `#"..."#` for any non-trivial bash, sed, or regex:

```kdl
chroot-script #"sed -i 's|@@KEYBOARD_DELAY@@|'"$KEYBOARD_DELAY"'|' /etc/foo"#
```

Without raw strings you'd be drowning in escapes. If the content itself contains `"#`, bump the level: `##"..."##`.

## Anatomy of a setting

```kdl
- name="install-audio" \
  dialog-name="Hardware Support Options" \
  short-description="Install Audio support" \
  long-description="Install PipeWire with PulseAudio and ALSA layers, …" \
  spdx-identifiers="MIT LGPL-2.1-or-later" \
  license-category="FOSS" \
  available="`some-precondition`" \
  default-value=#true {
    arch-packages "pipewire" "pipewire-alsa" "pipewire-pulse" "wireplumber"
    files "/etc/foo.conf"
    chroot-script "`usermod -aG audio {Settings.instance.get('user-name')}`"
}
```

The full field list is in `ditana-schema.json`. The most common ones:

| Field | Meaning |
| --- | --- |
| `name` | Unique identifier. Required. Used to reference this setting from other settings. Use `kebab-case`. |
| `dialog-name` | If present, the setting appears in the named dialog (must match a `name` in `installation-steps.kdl`). If absent, the setting is internal — invisible to the user. |
| `short-description` | One-line summary shown in the dialog. |
| `long-description` | Multi-paragraph help shown when the user presses `<Help>`. Triple-quoted strings (`"""…"""`) preserve newlines. The placeholders `$packages` and `$user-name` are substituted (see *Templated descriptions*). |
| `spdx-identifiers` | Space-separated SPDX license IDs. `""` for internal settings. |
| `license-category` | `FOSS` (default) or `CLOSED`, `CLOSED/FOSS` for mixed. |
| `default-value` | Initial value. Literal (`#true`, `#false`, `"..."`, integer) or a backtick logical expression. See *Logical expressions*. |
| `available` | Backtick logical expression. If it evaluates to false the dialog row is hidden. Defaults to true. |
| `detect` | Raku expression evaluated once at startup. Used in `hardware-detection.kdl`. Mutually exclusive with `default-value`. |
| `required-by-chroot` | If true, the setting's value is exported as a bash environment variable into the chroot installation script. The variable name is the setting name uppercased with `-` → `_`. |
| `arch-packages`, `aur-packages`, `flatpak-packages` | Packages to install if the setting is enabled. |
| `files` | Files from `folders/` to copy into the target system if the setting is enabled. |
| `early-chroot-script`, `chroot-script`, `root-script` | Script lines for the various lifecycle phases (see *Scripts*). |
| `first-login-scripts`, `login-scripts` | Paths to executable files (in `folders/`) sourced at first/every login. |
| `first-login-commands`, `login-commands` | Inline shell commands, executed at first/every login. |
| `autostart` | XDG autostart entries — `[only-show-in, script-path]` pairs. |
| `mime-defaults` | MIME associations — `[desktop-file, mime1, mime2, …]` arrays. |

### Templated descriptions

The installer substitutes a few magic tokens in `long-description`:

- `$packages` — expands to the comma-separated list of native + AUR + Flatpak packages this setting installs.
- `$user-name` — expands to the user's chosen login name.

This lets you write `"Installs $packages"` instead of duplicating the package list.

## Logical expressions in `default-value` and `available`

In `default-value` and `available`, a string wrapped in backticks is a **logical expression** over other settings:

```kdl
default-value="`install-cosmic AND virtual-environment`"
available="`NOT (install-hardened-stable-kernel OR install-hardened-lts-kernel)`"
default-value="`total-ram-gib >= 24`"
```

The expression language:

- **Operators**: `AND`, `OR`, `NOT`, parentheses
- **Comparisons**: `==`, `!=`, `<`, `<=`, `>`, `>=` (on numeric or string values)
- **References**: any `name=` of another setting in this repo
- **Result**: `True`, `False`, or `Unknown` (tristate logic)

### Tristate logic

When the expression refers to a setting whose value is undefined or undetermined (e.g. a hardware probe that found nothing conclusive), the outcome is `Unknown`. The operators handle this gracefully:

| `A` | `B` | `A AND B` | `A OR B` | `NOT A` |
| --- | --- | --- | --- | --- |
| True | Unknown | Unknown | True | False |
| False | Unknown | False | Unknown | True |
| Unknown | Unknown | Unknown | Unknown | Unknown |

In effect: a setting whose `default-value` evaluates to `Unknown` keeps its current value (often nothing); a dialog row with `available` evaluating to `Unknown` is hidden.

### Pitfalls

- **Boolean and numeric literals must NOT be backticked.** Write `default-value=#true`, not `` default-value="`true`" ``. Same for integers: `default-value=42`. The validator catches this with a clear error message.
- **Setting names must exist.** If you reference a typo'd name like `install-cosmik`, you'll get an exception at install time. Cross-check spellings.
- **No string interpolation here.** Backticks in `default-value` and `available` are *only* for the logical expression language above. The Raku interpolation rules described next do **not** apply.

## Backticks: Raku snippets

A backtick-wrapped string is a Raku snippet. Where the snippet appears determines what *kind of value* it should produce:

| Where | Produces | Example |
| --- | --- | --- |
| `default-value`, `available` | A boolean (or `Unknown`) — the snippet is a logical expression over other settings | `` `install-cosmic AND virtual-environment` `` |
| `chroot-script`, `early-chroot-script`, `root-script`, `first-login-commands`, `login-commands` | A shell line — the snippet is a Raku qq-string with `{...}` interpolations | `` `USER_NAME={Settings.instance.get('user-name')}` `` |

In the first case, the installer first substitutes every setting name with its current value, then evaluates the resulting boolean expression. In the second, the snippet goes through Raku's qq-string interpolation directly. Both forms accept arbitrary Raku — only the expected type of the result differs.

Setting names are referenced differently in the two contexts: as bare names in logical expressions (the substitution layer translates them to Raku-valid values before evaluation), and via `Settings.instance.get('name')` inside qq-string interpolations. Look at neighbouring entries in the same field if you're unsure.

## Hardware detection

Settings in `settings/hardware-detection.kdl` use `detect=` instead of `default-value=`. The string is a Raku expression evaluated **once** at installer startup:

```kdl
- name="intel-cpu" \
  detect="'/proc/cpuinfo'.IO.lines.first(* ~~ /vendor_id/).contains('GenuineIntel')"

- name="virtual-environment" \
  detect="run('systemd-detect-virt', '-q').exitcode eq 0"

- name="total-ram-gib" \
  detect="('/proc/meminfo'.IO.lines.grep(/MemTotal/).first.words[1] / 1024 / 1024).ceiling"
```

Other settings then reference these by name in their `default-value` logic:

```kdl
- name="intel-microcode" default-value="`intel-cpu`" {
    arch-packages "intel-ucode"
}
```

Detected values are **immutable** for the rest of the session. They're observed once, then frozen.

## Dialogs and installation steps

`installation-steps.kdl` defines the user-facing dialog flow. Each step has a `type`:

| Type | Behaviour |
| --- | --- |
| `procedure` | Calls a Raku function in the installer. The function name matches the step `name`. Use sparingly — most logic should live as data here. |
| `ask-for-setting` | Text-input prompt for a single setting. `validation` (e.g. `name`, `integer`, `number`) and `extra-validation` (a Raku predicate on `$_`) constrain input. |
| `ask-for-yes-no` | Yes/No prompt. Result becomes 0 (yes) / 1 (no). |
| `radiolist` | Mutually exclusive choice. The contained settings (those whose `dialog-name` matches the step's `name`) become rows. |
| `checklist` | Multi-select. Same matching rule as `radiolist`. |
| `categories` | Submenu: lists nested steps inside `categories { … }`. |

A `dialog-name` in a setting must match a step's `name` for the setting to appear in that dialog. Settings without `dialog-name` are *internal* — no UI, no help, but full power to install packages and contribute scripts. Use them whenever a setting is computed from others, never user-chosen.

### Common idioms

A **purely conditional package install**, no UI:

```kdl
- name="install-virtualbox-guest-extras" \
  default-value="`virtualbox`" {
    arch-packages "virtualbox-guest-utils"
}
```

A **user-visible toggle** that defaults from a profile:

```kdl
- name="install-cpp-dev" \
  dialog-name="Development Tools and Libraries" \
  short-description="Install C++ development packages" \
  long-description="Install $packages." \
  spdx-identifiers="" \
  default-value="`profile-developer`" {
    arch-packages "cmake" "gcc" "clang" "gdb"
}
```

A **dependent fix-up** triggered by a combination:

```kdl
- name="fix-cosmic-for-vms" \
  default-value="`install-cosmic AND virtual-environment`" {
    login-commands \
      #"if [[ "$DESKTOP_SESSION" == "cosmic-ditana" ]]; then"# \
      "    export LIBGL_ALWAYS_SOFTWARE=1" \
      "fi"
}
```

## Files: deploying configs

The `files` array maps target-system absolute paths to source paths under `folders/`:

```kdl
files "/etc/foo.conf"  →  copies folders/etc/foo.conf to /mnt/etc/foo.conf
```

Rules:

1. **The path must point to a single file**, not a directory. The installer uses `cp` without `-R`. The validator rejects directory references.
2. **Every file under `folders/` must be referenced by at least one setting.** Unreferenced files are flagged as errors. (Add the file to a setting's `files`, or remove it.)
3. **Files are only copied when the setting is enabled** (i.e. `current-value` is truthy). A setting with `default-value=#false` ships nothing unless the user enables it.
4. **Special targets:**
   - Anything under `/etc/skel/...` becomes part of every new user's home directory at user creation time. **Modify these via `early-chroot-script`, never `chroot-script`** (the user is created between those two phases). The validator enforces this.
   - Files at compositor-specific paths (e.g. `/usr/share/cosmic/...`, `/etc/xdg/...`) are global, applied at chroot stage.

## Files pacman never extracts

A setting prevents pacman from extracting specific files from a package, both currently and in all future transactions, by calling `/usr/lib/ditana/no-extract` inside its `chroot-script`, supplying the reason and the patterns as arguments. It ships the helper in its own `files` as well, because the installer copies only the files associated with enabled settings:

```kdl
files "/usr/lib/ditana/no-extract"
chroot-script #"/usr/lib/ditana/no-extract "Why pacman leaves these files out, and how to get them back." 'usr/share/foo/bar*'"#
```

The helper inserts each pattern that `/etc/pacman.conf` has not yet included as a `NoExtract` entry immediately below `#NoExtract` within the `[options]` section, or directly below `[options]` if that line is missing, with the justification given as a comment line positioned above them. Every pattern thus appears exactly once, regardless of how many settings refer to it or the order in which they do. The reason must not follow the patterns on the same line: pacman does not recognize comments at the end of a line and would interpret them as further patterns. `pacstrap` and the following transactions execute before any `chroot-script`, hence the helper also deletes the matching files that installed packages had already written to disk; later upgrades then omit them automatically.

A pattern adheres to pacman’s rules: `fnmatch` compares it without flags, so `*` also matches `/`, using the path inside the package, which has no leading slash; the list is read from the end, the first pattern that matches determines the outcome, and a leading `!` converts it into an exception. An exception has no effect on a pattern that was already entered by an earlier call: each call inserts its lines above the existing ones, so pacman, reading from the end, reaches the earlier pattern first; within a single call, an exception must come after the pattern it exempts from. Each pattern must match files from exactly one package, which the validator checks against the current repositories.

### localsearch never runs

GNOME’s file indexer localsearch (formerly Tracker) constitutes a hard dependency for nautilus, gnome-music, and gnome-photos, and nautilus aborts without its GSettings schema, so the package stays installed. `block-localsearch` keeps it from ever executing, even after updates: pacman refrains from extracting its D-Bus services, its systemd user units, or its autostart entry. Consequently, nautilus performs file name searches exclusively, and GTK file dialogs revert to their own search mechanism.

To allow localsearch on an installed system, delete the comment line regarding it from `/etc/pacman.conf` together with the `NoExtract` lines that come after it, and run `sudo pacman -S localsearch`, which extracts the files again.

## Portals under niri

niri gets the ScreenCast and Screenshot portals exclusively via `xdg-desktop-portal-gnome`: its own `niri-portals.conf` lists `gnome` as the primary choice, and `xdg-desktop-portal-gtk` provides neither. Absent `xdg-desktop-portal-gnome`, browsers (for Meet, Teams, or Jitsi), OBS, and every other application locate neither portal, causing screen sharing to fail. `install-niri` therefore installs `xdg-desktop-portal-gnome` alongside `wireplumber`: ScreenCast requires an active PipeWire session managed by a session manager, and `wireplumber` is otherwise accessible solely through the `install-audio` option, which can be deselected in the installer.

`xdg-desktop-portal-gnome` depends on nautilus and delegates its file chooser to it, despite the file manager selected during installation being Thunar, COSMIC Files, or none at all. Ditana consequently configures two aspects differently than the packages do:

- `install-niri` ships `/etc/xdg/xdg-desktop-portal/niri-portals.conf`, where the `[preferred]` section contains only `org.freedesktop.impl.portal.FileChooser=gtk;`. xdg-desktop-portal 1.22 reads it on top of niri’s own file in `/usr/share/xdg-desktop-portal/`, ensuring the file chooser comes from `xdg-desktop-portal-gtk`, while every other interface is directed to wherever niri sends it.
- pacman never extracts the D-Bus service of nautilus for `org.freedesktop.FileManager1`, located at `usr/share/dbus-1/services/org.freedesktop.FileManager1.service`, nor its launcher, `usr/share/applications/org.gnome.Nautilus.desktop`. With the service, Nautilus would take over "Show in folder" under niri and Wayfire, in place of Thunar or COSMIC Files: its file sorts before Thunar’s, and dbus-broker takes the first. The launcher would otherwise introduce a second file manager into the menus.

nautilus carries localsearch with it, which `block-localsearch` prevents from executing (refer to *localsearch never runs*).

To enable `xdg-desktop-portal-gnome` to supply the file chooser within niri once more, remove `/etc/xdg/xdg-desktop-portal/niri-portals.conf`. To get the two files of nautilus back, eliminate the comment line regarding them in `/etc/pacman.conf` together with the `NoExtract` lines that follow, then execute `sudo pacman -S nautilus`.

## Scripts: lifecycle and interpolation

Each setting can contribute lines to any of the lifecycle phases. They're concatenated in undefined order from all enabled settings, then executed.

### early-chroot-script

Runs in the chroot **before** the user is created. The only place that can modify `/etc/skel/` and have those changes propagate to the user's home directory.

```kdl
early-chroot-script \
  #"sed -i 's|@@KEYBOARD_DELAY@@|'"$KEYBOARD_DELAY"'|' /etc/skel/.config/foo/bar.xml"#
```

### chroot-script

Runs in the chroot **after** the user is created. Use for system-level configuration (services, sysctl, /etc files outside /etc/skel).

```kdl
chroot-script "systemctl enable foo.service" \
              "echo 'kernel.foo=1' >> /etc/sysctl.d/ditana.conf"
```

The validator rejects `/etc/skel/` references in this field — that's almost always a bug.

### root-script

Runs **once after first reboot** as root, via `ditana-initialize-system.service`. Use for actions that need a fully-booted system.

```kdl
root-script #"echo "Setting up X..."# \
            "do-something-that-needs-running-services"
```

### first-login-commands / first-login-scripts

`first-login-commands` are inline shell lines, run once, on the user's first desktop login. `first-login-scripts` are paths to executables (under `folders/`) sourced once. Both are deleted-after-success via a marker file.

```kdl
first-login-commands "git config --global init.defaultBranch main"
first-login-scripts  "/usr/lib/ditana/some-onetime-setup"
```

### login-commands / login-scripts

Same shape as the first-login variants but run on **every** login.

```kdl
login-commands "if command -v diffuse &> /dev/null; then" \
               "    export DIFFPROG=diffuse" \
               "fi"
```

### Raku interpolation in script entries

Inside `chroot-script`, `early-chroot-script`, `root-script`, `first-login-commands`, and `login-commands`, a line wrapped end-to-end in backticks is **Raku-evaluated at script generation time**:

```kdl
chroot-script "`USER_NAME={Settings.instance.get('user-name')}`"
```

The mechanism: the wrapping `\`...\`` strips the backticks; the inner string is wrapped in `qq«...»` and `EVAL`d. So:

- `{ … }` runs Raku code and inserts its result. `{Settings.instance.get('keymap-layout')}` becomes the keyboard layout string.
- `$variable` and `@array` interpolate Raku variables (rarely used here).
- The line is the **entire** Raku expression — backticks must wrap the *whole* line.

A line **without** wrapping backticks is passed verbatim to the bash script.

### `first-login-scripts` / `login-scripts` are NOT interpolated

These two fields contain **paths**, not commands. No Raku interpolation is performed on them. If you need parameterization in a script, write it inside the script and use bash variables.

### Two ways to inject a setting's value

There are two equivalent paths to get a setting into a chroot script:

**Method A — Raku interpolation at generation time** (preferred for one-off, local use):

```kdl
chroot-script "`sed -i 's|@@DELAY@@|{Settings.instance.get('keyboard-delay')}|' /etc/foo`"
```

The script that ends up executing in the chroot is already substituted. No env-var setup needed.

**Method B — Bash environment variable at execution time** (preferred when the value is also used by other code in the chroot):

```kdl
- name="keyboard-delay" required-by-chroot=#true ...
```

```kdl
chroot-script #"sed -i 's|@@DELAY@@|'"$KEYBOARD_DELAY"'|' /etc/foo"#
```

The setting must declare `required-by-chroot=#true`. The installer writes `KEYBOARD_DELAY="..."` into a settings file that the chroot script sources. Variable name = setting name, uppercased, dashes → underscores.

Use Method B when the value appears in many scripts or when the chroot install script also needs it. Use Method A for local, focused substitutions where coupling to a global env is unwarranted.

## Autostart entries

```kdl
autostart {
    - "XFCE;" "/usr/lib/ditana/xfce-first-login"
    - "" "/usr/bin/some-tool"
}
```

Each entry is a `[OnlyShowIn, ExecPath]` pair. The first item becomes the `OnlyShowIn=` field of the generated `.desktop` file (empty = show in all DEs); the second is the executable path. The installer generates `ditana-<basename>.desktop` files in `/etc/xdg/autostart/`.

## MIME defaults

```kdl
mime-defaults {
    - "thunar.desktop" "inode/directory"
    - "vlc.desktop" "audio/mpeg" "audio/ogg" "video/mp4"
}
```

Each entry is `[desktop-file, mime-type, mime-type, …]`. The installer aggregates these across all enabled settings and writes a system-wide `mimeapps.list`.

## Quoting reference

Putting all the layers together:

```kdl
chroot-script "`sed -i 's|@@FOO@@|{Settings.instance.get('user-name')}|' /etc/x`"
```

Layers, outermost to innermost:

1. **KDL string** `"…"` — what the parser sees as the value of one `chroot-script` line.
2. **Raku interpolation** `\`…\`` — the line is `EVAL`d as Raku code at script-generation time.
3. **Raku qq-string** — `{ … }` interpolates Raku, `$x`/`@x` interpolate variables.
4. **sed** `s|…|…|` — note the pipe separator chosen because `/` would clash with paths.
5. **sed quoting** `'…'` — single quotes prevent the bash script from expanding `$` inside the sed argument.
6. **Bash** — receives the fully-substituted line as an instruction.

If you find yourself fighting quotes, switch to a raw KDL string `#"..."#` to avoid escaping `"` and `\`. If the line is meant for **bash variable substitution at runtime** rather than Raku-substitution at generation time, drop the outer backticks and use the `required-by-chroot` mechanism instead.

## Pitfalls and gotchas

A condensed list of things the validator catches — or that bite you the first time you contribute:

1. **`/etc/skel/` in `chroot-script`** — Use `early-chroot-script`. The validator enforces this.
2. **Boolean / numeric literals in backticks** — `default-value="\`true\`"` is wrong; write `default-value=#true`. Same for integers.
3. **Misspelled setting reference** — Caught at commit time by `validate-logic.py`'s setting-existence check.
4. **Backticks where you wanted bash variables (or vice versa)** — Backticks = Raku interpolation at generation time; `$VAR` = bash variable at runtime, requires `required-by-chroot=#true` on the source setting.
5. **Order assumptions across settings** — Within a phase, scripts run in undefined order. Never write `setting A's chroot-script line foo before setting B's chroot-script line bar`.
6. **Unreferenced files in `folders/`** — Every file must be in some setting's `files` array. The validator lists orphans.
7. **Directory in `files`** — The installer copies single files; directory entries are rejected.
8. **`first-login-scripts` are paths, not commands** — Don't put inline shell here; that's `first-login-commands`.
9. **No interpolation in script paths** — Raku interpolation is only applied to *-commands and *-script (chroot/early-chroot/root) fields.
10. **Tilde / `$HOME` in chroot phases** — There's no logged-in user yet. Refer to absolute paths or `/root`.
11. **Forgetting the closing backtick** — Caught at commit time by `validate-logic.py`'s backtick-balance check across `default-value`, `available`, and the script-list fields.
12. **The `.[0]` indexing pattern** — Some accessors index `[0]` into nested arrays (e.g. `setting.arch-packages[0]`). This is an artifact of the JSON shape. You generally won't write this code, but if you do, look at neighbouring code for the pattern.

## Validation

Three pre-commit hooks guard quality:

1. **kdlfmt** — KDL syntax check. Locally optional (skipped when `kdlfmt` is not installed); in CI, skipping it constitutes an error (refer to *Checks that cannot run everywhere*).
2. **JSON Schema validation** — The KDL is converted to JSON via `json-kdl-converter`, then validated against `ditana-schema.json`. This catches misspelled field names, wrong types, and unknown properties.
3. **`validate-logic.py`** — Cross-cuts the data:
   - Files referenced by settings must exist and not be directories.
   - All files in `folders/` must be referenced by some setting.
   - `chroot-script` lines must not touch `/etc/skel/`.
   - Every shell snippet (in any `*-script` or `*-commands` field, plus standalone scripts in `first-login-scripts`/`login-scripts`) must pass `bash -n` and `shellcheck`.
   - Every backtick-wrapped string is balanced — across `default-value`, `available`, and all script-list fields.
   - Every setting name referenced from a logical expression in `default-value` or `available` exists. Catches typos that would otherwise crash at install time.
   - Every program located under `/usr/lib/ditana/` that gets referenced by a waybar module through `exec` or `exec-if` is shipped by `install-waybar`. waybar hides a custom module when its associated helper is absent, so no other component would notice it.
   - Every program located under `/usr/lib/ditana/` that the niri config within the skel calls is shipped by some setting. A key bound to a missing program has no visible effect: niri writes the error to the journal when it fails to start the program, and no indication appears on screen.
   - The RAM disk rules for `install-ramdisk` and `install-ramdisk-thunar-bookmark` lie in the skeleton, under `/etc/skel/.config/user-tmpfiles.d/`, ensuring they reach only accounts created from it. The real `systemd-tmpfiles` executes them within a stand-in root, just as `systemd-tmpfiles-setup.service` does in a user manager: for an account with a home directory of `/`, such as greetd's `greeter`, it creates nothing and issues no report, whereas a user created from the skeleton gets the directory `ramdisk` with mode 0700 in the runtime directory, a symbolic link `~/RAMDisk` pointing to it, and a bookmark titled `RAM Disk` in Thunar's side pane. Placed under `/usr/share/user-tmpfiles.d/`, the rules would run in the user manager of every account, causing the greeter to log the error `Failed to create symlink '/RAMDisk': Permission denied` at each boot. `systemd-tmpfiles` disallows the combination of `--root` with `--user`, hence `XDG_CONFIG_DIRS` and `XDG_DATA_DIRS` point its search path into the stand-in root. `TMPDIR` could point to a symbolic link directed at a different disk, and `systemd-tmpfiles` refuses to follow an absolute link unless it is owned by root; the `-` behind the type of each rule causes it to decline silently, returning exit status 0. The checks therefore resolve the path to the stand-in root, and both continue to pass even when that path runs through such a link.
   - Each setting that ships a Python script also installs `python`. Today, `uwsm` brings `python` into every Wayland session, but solely as a dependency of its own, which an update to `uwsm` might remove, and a script whose interpreter is absent then fails without a word on screen.
   - The `waybar-io-pressure` helper operates inside a simulated `/proc` directory structure and must adhere to waybar’s output contract: a single line of JSON only, the warm and hot classes activated exactly at their specified limits, the percentage value rounded half up instead of being cut off, no output generated when no data is available, `/proc/pressure/io` accessed exactly once per invocation, and identical output regardless of the German locale being in use. Locale validation is performed exclusively when a German locale is present; the CI’s container lacks such a locale, so its workflows expect the skip `german-locale`.
   - `waybar-niri-workspaces` reads the event stream from a stand-in for niri’s socket that mimics niri’s behaviour, and each line it produces must conform to waybar’s output contract: the text shows the index of the active workspace on the bar’s output and the index of the last workspace in use there (3/7 with an empty workspace at the top and at the bottom and windows on 2 to 7; the empty one at the top as 1; the one at the bottom only while active; an empty workspace with a name included), per output independently and, without a usable `WAYBAR_OUTPUT_NAME`, for the output currently focused; a name comes after a middle dot, shortened to 24 characters and escaped for Pango; the whole text stands in bold dark grey (`#262626`) on Ditana’s orange (`#ffbb00`), the colour of niri’s focus ring on the active monitor, with a space inside before and after it, as a field within the module’s grey box, whereas the `?` of a failed connection refers to no workspace and stays plain; a backslash in a name or a window title is transmitted verbatim even if followed by an `x`, although waybar 0.15 turns every `\x` in a line into `\u00`; the tooltip presents, for each output, the workspaces that hold windows or carry a name and the active one, each with its windows, in a fixed order and format; the classes `focused` and `urgent` are assigned solely to the bar’s own output; unknown events in the first burst are skipped; nothing is printed before the windows are known, and thereafter only when the line differs; subsequent events update individual entries as niri-ipc’s `EventStreamState` does; `WorkspaceActivated`, `WorkspaceActiveWindowChanged`, and `WorkspaceUrgencyChanged` events naming an unknown workspace have no effect, and neither do `WindowClosed`, `WindowFocusChanged`, `WindowUrgencyChanged`, or `WindowLayoutsChanged` events referencing an unknown window; the module does not display `active_window_id` nor the focus or urgency of a window, so for `WorkspaceActiveWindowChanged`, `WindowFocusChanged`, and `WindowUrgencyChanged` the checks read the helper’s state rather than its output; after a failed or ended connection, the helper displays `?` and attempts reconnection after 1, 2, 4, then every 8 seconds, restarting the sequence at 1 once niri has acknowledged the event stream with `{"Ok":"Handled"}`, while a refusal does not reset the sequence; without `NIRI_SOCKET`, it hides the module and keeps running; and it ends quietly with exit status 0 when waybar closes the pipe.
   - `rename-niri-workspace` operates using stand-ins for niri and rofi on its `PATH` that mimic the actual programs where it matters: the field holds the current name unless the name begins with `-`, which rofi would interpret as an option; emptying the field removes the name, regardless of whether it previously held the current name or user-entered text, whereas an empty field that the dialog could not fill – because its text starts with `-` – retains the name, and the note indicates this; Escape and rofi’s custom keys have no effect, and an unchanged name is not re-sent; a case-only change removes the name before setting it, as niri discards a name already assigned to any workspace, comparing ASCII letters regardless of case; a name already assigned to another workspace triggers the dialog again with the input text and a note naming that workspace and its output; the dialog performs no action if another workspace holds the focus when the user confirms, since niri continues processing its key bindings while rofi is open; and `--` precedes every name sent to niri. A click on the module opens the dialog for the focused workspace, which is the active one of the bar’s output, because niri focuses the output beneath the pointer upon a click; the module does not respond to scrolling, since with `warp-mouse-to-focus` niri places the pointer on the newly focused window after each switch, and the next mouse wheel step would then fall within that window; Mod+mouse wheel and the keyboard shortcuts instead switch workspaces.
   - `waybar-display-scale` operates on stubs and copies of the skel waybar files, never on a live waybar instance: the bar height, taskbar icon dimensions, launcher icon sizes, and the font size within the first `* {` rule adjust according to the DPI and the width of the first display listed in `display-info` (pinned for four displays, including a laptop panel 1920 pixels wide, where DPI alone proved insufficient to fit one taskbar icon); tray icon sizes, the `font-size: 0;` setting for launchers, and font sizes in other rules stay untouched, a later `* {` rule of the user’s own included, even with comments in the way or several rules on one line; waybar is restarted only when a file undergoes modification, and a waybar started by hand is restarted through the `launch` command designated by `DITANA_LAUNCH_BIN`; a second execution triggers no further alterations; an empty or unusable `display-info` leaves the files alone, and one lacking a width definition depends entirely on DPI for sizing; `--once` ends with exit code 1 if it cannot write the files.
   - `/usr/lib/ditana/no-extract` operates within a temporary root, on a duplicate of the `[options]` section from Arch’s `pacman.conf` and on another that lacks its `#NoExtract` line, with all settings’ invocations and two of the check’s own calls (one repeating a pattern from each settings call, one with an exception) executed in multiple sequences and each sequence run twice: each pattern appears precisely once in the file, located directly under the reason for the call that entered it, and under `[options]` where `#NoExtract` is missing; the files already placed on disk by an installed package and blocked by the list are gone, while every other file remains, including one that no package installed; before the second run, the packages’ files are restored to disk, and the helper must delete them even though every pattern is already listed by then; and `pacman-conf` reads precisely these patterns back (omitted where `pacman-conf` is absent). Every setting that invokes the helper includes it in its `files`. Every script line of a setting that names `NoExtract` or the helper is reported, regardless of its action, unless it is a `chroot-script` line calling the helper: the checks determine a setting’s patterns solely from such calls.
   - Every file via which localsearch starts, that is, every file the package installs under `usr/lib/systemd/user/`, `usr/share/dbus-1/services/`, or `etc/xdg/autostart/`, conforms to a pattern listed in `block-localsearch`, ensuring that a rename upstream or a new entry point does not allow it to run again without detection. No pattern in `block-localsearch` matches any other file of localsearch, so that no pattern can block the GSettings schema required for nautilus to function, which would otherwise cause nautilus to abort.
   - Every NoExtract pattern introduced by a setting matches files from exactly one package in the current repositories: a pattern with no match is inactive, and one matching files from multiple packages interferes with something it was not intended to block. The repositories are core, extra, and multilib, along with the Ditana repository wherever `/etc/pacman.d/ditana-mirrorlist` is installed. These checks read the file lists from a private copy that `fakeroot` and `pacman -Fy` update on each run, as only root can refresh the system’s databases. The copy stays in `$XDG_CACHE_HOME/ditana-config` (`~/.cache/ditana-config` by default) between runs, so pacman fetches only the lists that changed on the mirror. The checks skip if `pacman` or `fakeroot` is missing, if no network connection is available, or if pacman fails to interpret the mirror’s response, such as the login page from a hotel network, which is then discarded. No process of theirs survives beyond them, not even after a timeout or a failure. Stand-ins for a mirror pin this down: one that serves a list, one that answers with a login page, one that answers nothing, and one that answers 404.
   - `xdg-desktop-portal-gnome` continues to rely on nautilus, and nautilus on localsearch, within the current repositories. The NoExtract patterns for `install-niri` regarding nautilus rest on the first dependency, while those for `block-localsearch` depend on the second, meaning that if either is removed, a second look becomes necessary. The check reads the dependencies from the same private copy of the file lists, which holds the description of each package beside its files, and skips in tandem with the checks against the repositories. Stand-in repositories pin down that only `%DEPENDS%` counts, not the optional, build, or check dependencies listed beside it, that a version constraint is dropped, and that a package present in two repositories is treated as it appears in the first.
   - The actual `/usr/lib/xdg-desktop-portal -v` executes with `XDG_CURRENT_DESKTOP` set to `niri`, `COSMIC`, and `XFCE` in sequence, and with `XDG_CONFIG_DIRS` directed at a directory containing the files from `folders/etc/xdg/xdg-desktop-portal/`; the lines `Using X.portal for Y`, and `Choosing X.portal for Y as a last-resort fallback`, up to the moment it acquires its bus name, say where each interface is routed. It operates on a private bus that does not reference any directory of service files, preventing any backend from launching, with the system bus pointing there as well, and in an environment built from scratch with its own home and runtime directory, ensuring that nothing from the session running the checks interferes. `XDG_DESKTOP_PORTAL_DIR` would directly name the files, but it disables the layering of configuration files and shows a different routing from that of an installed system. Under niri, ScreenCast and Screenshot are directed to gnome, FileChooser to gtk, and Ditana’s files move FileChooser alone: every other interface follows the same path as a run without them. Under COSMIC and XFCE, gnome.portal has no effect: ScreenCast and Screenshot go to cosmic under COSMIC, FileChooser goes to gtk under XFCE, and no interface goes to gnome under either. No process from a run persists beyond it, even though `dbus-run-session` leaves the bus and xdg-desktop-portal running when it is itself stopped. The checks use the portal packages installed on the machine and skip when one is missing; the workflows install them, so that the daily run notices an Arch update altering the routing. They install `niri` from extra, so CI checks the `niri-portals.conf` in extra rather than the one in `niri-git`, which Ditana installs: a change in `niri-git` becomes visible only after it reaches extra.
   - `install-niri` continues to install `xdg-desktop-portal-gnome` and `wireplumber`, and calls `/usr/lib/ditana/no-extract` for the D-Bus service of nautilus for `org.freedesktop.FileManager1` and for its launcher. The routing checks take the portal packages from the machine, not from `install-niri`, so they would not notice if one of these were absent from `niri.kdl`.

Run them all locally:

```bash
pre-commit run --all-files
```

Install pre-commit if you don't have it:

```bash
pacman -Syu pre-commit
```

The CI runs the identical hooks within an `archlinux:base-devel` container, where a skip constitutes an error unless the workflow expects it (see below).

### Checks that cannot run everywhere

Some checks require something that is not present on every machine. When it is missing, the check skips, emitting a line starting with ℹ️ that identifies the skip, while the remaining checks proceed. `pre-commit` displays the lines from `validate-logic.py` solely when using `--verbose` or if the hook fails; the line from the kdlfmt hook always appears, as that hook is `verbose`. Each skip is processed via `skip()` in `validate-logic.py`, and a check fails if any other code in that script prints ℹ️. The kdlfmt hook also skips via `skip()`, by calling `validate-logic.py --skip NAME MESSAGE`, which treats any other arguments as a usage error:

| Skip | Missing | Not checked |
| --- | --- | --- |
| `kdlfmt` | `kdlfmt` | the KDL syntax |
| `user-manager` | a systemd user manager | `launch` within a transient scope |
| `block-device` | a block device node in `/dev` | `open-disks` on a block device |
| `german-locale` | a German locale | `waybar-io-pressure` when operating under a German locale |
| `systemd-tmpfiles` | `systemd-tmpfiles` | the content generated by the RAM disk rules for an account with a home directory of `/` and for a user created from the skeleton |
| `other-account` | a uid different from 0 capable of owning a symbolic link, where the checks run as root | the RAM disk checks below a symbolic link that is not owned by root |
| `pacman-conf` | `pacman-conf` | whether pacman reads back what `no-extract` enters |
| `pacman-fakeroot` | `pacman` or `fakeroot` | the private copy of the file lists, and the NoExtract patterns and the dependencies they rest on, applied to the repositories |
| `ditana-mirrorlist` | `/etc/pacman.d/ditana-mirrorlist` | the NoExtract patterns applied to the Ditana repository |
| `file-lists` | usable file lists: no network, a failing mirror, a timeout, a response that pacman cannot read, or a cache directory that cannot be written to | the NoExtract patterns and the dependencies they rest on, applied to the repositories |
| `portal-packages` | `dbus-run-session`, one of the portal packages `xdg-desktop-portal`, `xdg-desktop-portal-gnome`, `xdg-desktop-portal-gtk`, or `xdg-desktop-portal-cosmic`, or the `*-portals.conf` of niri (`niri` or `niri-git`) or XFCE (`xfce4-session`) | where xdg-desktop-portal routes each interface under niri, COSMIC, and XFCE |

In CI, a skip constitutes an error unless the environment variable `DITANA_EXPECTED_SKIPS` names it in its blank-separated list. A missing prerequisite or absent network then fails the run rather than allowing it to pass with fewer checks, ensuring CI coverage does not diminish without notice. Conversely, a name listed whose corresponding check does not skip is also an error, as such a stale entry could allow the skip to pass unnoticed upon recurrence; `kdlfmt` is exempt, since its own hook decides whether it skips. `validate-logic.py` treats a run as CI when `CI` is set, as GitHub Actions sets it to `true`, unless it is empty, `false`, or `0`, regardless of case or surrounding whitespace. The workflows expect `user-manager` and `german-locale`, as their container lacks a systemd user session and a German locale. They run `pre-commit` with `--verbose` so that each log shows which checks were skipped and confirms the list expects them. To run the checks locally with the same strictness as CI, include in `DITANA_EXPECTED_SKIPS` the skips this machine cannot avoid, if any:

```bash
CI=true DITANA_EXPECTED_SKIPS="" pre-commit run --all-files --verbose
```

## How to contribute

1. **Find the relevant file.** Compositor-specific tweaks go in `settings/dialogs/desktop-environment/<de>.kdl`. Hardware support in `advanced/hardware-support.kdl`. New dev-tool packages in `advanced/development-tools.kdl`. And so on. The directory layout mirrors the dialog hierarchy.
2. **Add a setting** following the *Anatomy of a setting* template. Don't expose every internal toggle as a dialog — internal settings (no `dialog-name`) are perfectly fine and usually preferred for derived behaviour.
3. **Comment the *why*, not the *what*.** Anyone can see what `chroot-script` does; explain why the setting exists, what edge case prompted it, what alternative was rejected.
4. **Keep package lists in `arch-packages` alphabetical** when there's no logical grouping, and use comment-grouped lists otherwise (see `xfce.kdl` for the pattern).
5. **Run `pre-commit run --all-files`** before pushing.
6. **Open a PR** with a description of the user-visible effect and any compatibility concern.

You don't need to understand the whole installer to contribute meaningfully. If you know a hardware quirk, a compositor caveat, or a sensible default for a class of users — that knowledge fits cleanly into a single setting in a single file.

### Example: adding a GPU compatibility note

In `settings/dialogs/advanced/hardware-support.kdl`:

```kdl
- name="some-gpu-workaround" \
  available="`some-gpu-detected`" \
  default-value=#true {
    chroot-script "echo 'options foo bar=1' >> /etc/modprobe.d/foo.conf"
}
```

That's a complete contribution. No installer changes needed.

## Format

This repository uses [KDL v2](https://kdl.dev) — a document language with native comments, raw strings, and a clean tree shape. Both the schema (`ditana-schema.json`) and the converter (`json-kdl-converter`) are versioned with the configuration so that any commit is reproducibly buildable.

## Integration

On every push to `main`, a GitHub Action runs the hooks inside an `archlinux:base-devel` container, packages the configuration into `ditana-config.tar.gz`, and uploads it to the `latest` release. The Ditana installer downloads this archive both at ISO build time and at installation time (with the ISO-bundled version as fallback). This means an improvement merged here ships to users on their next install, without re-spinning an ISO.

The `develop` branch ships to the corresponding `develop-latest` release tag, which is what the Ditana development ISO consumes.

A third workflow runs the identical hooks within the same container on `main` once daily and publishes nothing, ensuring that a change in the Arch or Ditana repositories which disrupts a NoExtract pattern, or changes where xdg-desktop-portal routes an interface, becomes evident without requiring a commit. It may also be started by hand. GitHub disables a scheduled workflow in a public repository after 60 days of inactivity within the repository. Its alerts are sent to the person who created the workflow; after a change to the `cron` line, to the author of that change; and after the workflow has been disabled and re-enabled – such as after those 60 days – to the person who enabled it.

Since the checks compare the NoExtract patterns against the current repositories, a mirror that is offline or a missing network also fails the two release workflows; `latest` or `develop-latest` is then updated through a re-run or the next push. The workflows write `/etc/pacman.d/ditana-mirrorlist` directly, using the two servers from the package `ditana-mirrorlist`; when the Ditana mirrors change, the workflows must be updated accordingly. A container lacks a block device under `/dev`, so they create the node `/dev/ditana-validate-block`, enabling the block-device case of `open-disks` to execute.
