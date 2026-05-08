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

1. **kdlfmt** — KDL syntax check. Optional locally (skipped if `kdlfmt` is not installed); always enforced in CI.
2. **JSON Schema validation** — The KDL is converted to JSON via `json-kdl-converter`, then validated against `ditana-schema.json`. This catches misspelled field names, wrong types, and unknown properties.
3. **`validate-logic.py`** — Cross-cuts the data:
   - Files referenced by settings must exist and not be directories.
   - All files in `folders/` must be referenced by some setting.
   - `chroot-script` lines must not touch `/etc/skel/`.
   - Every shell snippet (in any `*-script` or `*-commands` field, plus standalone scripts in `first-login-scripts`/`login-scripts`) must pass `bash -n` and `shellcheck`.
   - Every backtick-wrapped string is balanced — across `default-value`, `available`, and all script-list fields.
   - Every setting name referenced from a logical expression in `default-value` or `available` exists. Catches typos that would otherwise crash at install time.

Run them all locally:

```bash
pre-commit run --all-files
```

Install pre-commit if you don't have it:

```bash
pacman -Syu pre-commit
```

The CI runs the same hooks — local green = CI green.

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

On every push to `main`, a GitHub Action packages the configuration into `ditana-config.tar.gz` and uploads it to the `latest` release. The Ditana installer downloads this archive both at ISO build time and at installation time (with the ISO-bundled version as fallback). This means an improvement merged here ships to users on their next install, without re-spinning an ISO.

The `develop` branch ships to the corresponding `develop-latest` release tag, which is what the Ditana development ISO consumes.
