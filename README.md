# Ditana Configuration

The "brain" of the [Ditana GNU/Linux](https://ditana.org) installer — a structured knowledge base that drives the entire installation process.

## What is this?

This repository contains the configuration data that controls the Ditana installer. It encodes:

- **Installation steps** — the sequence of dialogs and procedures the user walks through
- **Settings** — hardware detection rules, package selections, system hardening options, compositor/terminal compatibility knowledge, and much more
- **Configuration files** — default dotfiles, system configs, and scripts deployed during installation

All of this is expressed in [KDL](https://kdl.dev), a human-friendly document language. No script chaos — everything is driven by logical relationships between settings.

## Repository structure

```
├── installation-steps.kdl     # Dialog sequence and UI structure
├── settings/                  # Settings organized by topic
│   ├── hardware-detection.kdl # Auto-detected hardware properties
│   ├── base-packages.kdl      # Core packages derived from install logic
│   ├── installer-state.kdl    # Runtime state (disk, locale, user, ...)
│   └── dialogs/               # Settings corresponding to installer dialogs
│       ├── desktop-environment.kdl
│       ├── ai-tools.kdl
│       ├── advanced/
│       │   ├── filesystem.kdl
│       │   ├── kernel-selection.kdl
│       │   └── ...
│       └── expert/
│           ├── system-hardening.kdl
│           ├── cpu-mitigations.kdl
│           └── ...
└── folders/                   # Configuration files deployed during installation
    ├── etc/
    └── usr/
```

## How to contribute

Each `.kdl` file is self-contained and documents a specific topic. To contribute your knowledge:

1. Find the relevant file (e.g., `settings/dialogs/desktop-environment.kdl` for compositor issues)
2. Add or modify settings with appropriate comments explaining the *why*
3. Submit a pull request

You don't need to understand the entire installer — just the topic you're contributing to.

### Example: Adding a GPU compatibility note

In `settings/dialogs/advanced/hardware-support.kdl`, you might add a caveat for a specific GPU:

```kdl
// Ghostty crashes on Nvidia 470.x legacy drivers under Wayland compositors
- name="ghostty-nvidia-470-workaround" \
  available="`nvidia-legacy-470xx`" \
  default-value=#true {
    // Falls back to kitty when Ghostty is incompatible
}
```

## Format

This repository uses [KDL v2](https://kdl.dev) — a document language with:
- Native comments (`//`, `/* */`, and `/-` to comment out entire nodes)
- Raw strings (`#"..."#`) for embedding Bash/Raku code without escaping
- Natural nesting with `{ }` blocks
- Human-readable, diff-friendly syntax

## Integration

On every push to `main`, a GitHub Action packages the configuration into an archive. The [Ditana installer](https://github.com/acrion/ditana-installer) downloads this archive both at ISO build time and at installation time (with the ISO-bundled version as fallback).
