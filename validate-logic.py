#!/usr/bin/env python3
import json
import os
import re
import subprocess
import sys
import shutil

config_path = '/tmp/ditana-config.json'
try:
    with open(config_path) as f:
        config = json.load(f)
except FileNotFoundError:
    print(f"❌ Could not find {config_path}. Ensure 'validate-kdl-via-json' runs first.")
    sys.exit(1)

settings = config.get('settings',[])
errors = False

def run_check(cmd, stdin_str=""):
    try:
        res = subprocess.run(cmd, input=stdin_str, text=True, capture_output=True)
        if res.returncode != 0:
            return False, res.stderr if res.stderr else res.stdout
        return True, ""
    except FileNotFoundError:
        return False, f"Command not found: {cmd[0]}"

if not shutil.which("shellcheck"):
    print("❌ shellcheck is not installed or not found in PATH.")
    sys.exit(1)

referenced_files = set()

print("🔍 Checking referenced files...")
for s in settings:
    name = s.get('name', 'unknown')
    for f in s.get('files',[]):
        path = os.path.join("folders", f.lstrip("/"))
        if not os.path.exists(path):
            print(f"❌ Setting '{name}' references missing file: {path}")
            errors = True
        elif os.path.isdir(path):
            print(f"❌ Setting '{name}' references a directory: {path}. The installer uses 'cp' without '-R', so 'files' must only contain paths to individual files.")
            errors = True
        else:
            referenced_files.add(path)

scripts_to_check =[]

print("🔍 Validating chroot scripts and shell code...")
for s in settings:
    name = s.get('name', 'unknown')

    for line in s.get('chroot-script',[]):
        if '/etc/skel/' in line:
            print(f"❌ Setting '{name}' uses '/etc/skel/' in 'chroot-script'. Use 'early-chroot-script' instead. Line: {line}")
            errors = True

    for key in['first-login-commands', 'login-commands', 'chroot-script', 'early-chroot-script', 'root-script']:
        lines = s.get(key, [])
        if lines:
            filtered_lines =[]
            for line in lines:
                if line.strip().startswith('`') and line.strip().endswith('`'):
                    continue
                filtered_lines.append(line)

            if not filtered_lines:
                continue

            script_content = "#!/bin/bash\n" + "\n".join(filtered_lines) + "\n"

            ok, msg = run_check(["bash", "-n"], script_content)
            if not ok:
                print(f"❌ Syntax error in '{name}' -> {key}:\n{msg.strip()}")
                errors = True

            shellcheck_cmd =[
                "shellcheck",
                "--norc",
                "-s", "bash",
                "--enable=require-double-brackets",
                "-e", "SC2129,SC1091,SC2219,SC2207,SC2145",
                "-"
            ]

            ok, msg = run_check(shellcheck_cmd, script_content)
            if not ok:
                print(f"❌ Shellcheck failed in '{name}' -> {key}:\n{msg.strip()}")
                errors = True

    for key in['first-login-scripts', 'login-scripts']:
        for p in s.get(key,[]):
            full_path = os.path.join("folders", p.lstrip("/"))
            if os.path.isfile(full_path):
                scripts_to_check.append((name, key, full_path))

for name, key, path in scripts_to_check:
    ok, msg = run_check(["bash", "-n", path])
    if not ok:
        print(f"❌ Syntax error in '{name}' -> {key} file '{path}':\n{msg.strip()}")
        errors = True

    shellcheck_cmd_file =[
        "shellcheck",
        "--norc",
        "-s", "bash",
        "--enable=require-double-brackets",
        "-e", "SC2129,SC1091,SC2219,SC2207,SC2145",
        path
    ]
    ok, msg = run_check(shellcheck_cmd_file)
    if not ok:
        print(f"❌ Shellcheck failed in '{name}' -> {key} file '{path}':\n{msg.strip()}")
        errors = True

# ---------------------------------------------------------------------------
# Backtick balance + setting-existence validation
#
# Mirrors the tokenizer in Settings.rakumod (!evaluate-logical-dependency-internal):
#   - Variable identifiers match  [a-zA-Z_][a-zA-Z0-9_-]*
#   - Reserved words OR / AND / NOT / True / False are not variables
# Numeric literals like "24" do not match because the regex requires the
# first character to be alphabetic or underscore.
# ---------------------------------------------------------------------------

VALID_KEYWORDS = {'AND', 'OR', 'NOT', 'True', 'False'}
SETTING_NAME_RE = re.compile(r'[a-zA-Z_][a-zA-Z0-9_-]*')

# Logical-expression fields: backtick-wrapped string is a tristate boolean
# expression over other settings.
LOGIC_FIELDS = ('default-value', 'available')

# Script-list fields: a fully-backtick-wrapped line is Raku-interpolated at
# script generation time; otherwise the line is passed verbatim to bash.
INTERP_LIST_FIELDS = (
    'chroot-script',
    'early-chroot-script',
    'root-script',
    'first-login-commands',
    'login-commands',
)

def collect_setting_names(cfg):
    return {s['name'] for s in cfg.get('settings', []) if 'name' in s}

def is_backtick_code(value):
    return isinstance(value, str) and len(value) >= 2 and value[0] == '`' and value[-1] == '`'

def has_unbalanced_backticks(value):
    if not isinstance(value, str) or not value:
        return False
    if len(value) == 1:
        return value == '`'
    return value.startswith('`') != value.endswith('`')

def referenced_names(expr):
    """Identifiers in a logical expression, minus reserved words."""
    return {m.group(0) for m in SETTING_NAME_RE.finditer(expr) if m.group(0) not in VALID_KEYWORDS}

def check_logic_value(value, owner_label, field, valid_names, out_errors):
    if not isinstance(value, str):
        return  # plain booleans / integers are fine
    if has_unbalanced_backticks(value):
        which = "missing closing" if value.startswith('`') else "missing opening"
        out_errors.append(
            f"❌ {owner_label} field '{field}' has unbalanced backticks "
            f"({which}): {value!r}"
        )
        return  # don't try to parse a malformed expression
    if is_backtick_code(value):
        for ref in referenced_names(value[1:-1]):
            if ref not in valid_names:
                out_errors.append(
                    f"❌ {owner_label} field '{field}' references unknown setting "
                    f"'{ref}': {value!r}"
                )

def check_script_lines(setting, owner_label, out_errors):
    for field in INTERP_LIST_FIELDS:
        for line in setting.get(field, []):
            if has_unbalanced_backticks(line):
                which = "missing closing" if line.startswith('`') else "missing opening"
                out_errors.append(
                    f"❌ {owner_label} field '{field}' has line with unbalanced backticks "
                    f"({which}): {line!r}"
                )

def walk_installation_step(step, valid_names, out_errors, path=""):
    name = step.get('name', '<unnamed>')
    full_path = f"{path}{name}"
    label = f"Step '{full_path}'"
    for field in LOGIC_FIELDS:
        if field in step:
            check_logic_value(step[field], label, field, valid_names, out_errors)
    for child in step.get('categories', []):
        walk_installation_step(child, valid_names, out_errors, path=f"{full_path} → ")

print("🔍 Validating backtick balance and setting references...")

valid_setting_names = collect_setting_names(config)
logic_errors = []

for s in settings:
    label = f"Setting '{s.get('name', '<unnamed>')}'"
    for field in LOGIC_FIELDS:
        if field in s:
            check_logic_value(s[field], label, field, valid_setting_names, logic_errors)
    check_script_lines(s, label, logic_errors)

for step in config.get('installation-steps', []):
    walk_installation_step(step, valid_setting_names, logic_errors)

for line in logic_errors:
    print(line)
if logic_errors:
    errors = True

# ---------------------------------------------------------------------------

print("🔍 Checking for unreferenced files in 'folders/'...")
all_files_in_folders = set()
if os.path.isdir("folders"):
    for root, dirs, files in os.walk("folders"):
        for file in files:
            all_files_in_folders.add(os.path.join(root, file))

unreferenced = all_files_in_folders - referenced_files
if unreferenced:
    unreferenced =[f for f in unreferenced if not f.endswith('.gitkeep')]
    if unreferenced:
        print("❌ Found unreferenced files in 'folders/':")
        for f in sorted(unreferenced):
            print(f"   - {f}")
        errors = True

if errors:
    print("❌ Validation failed!")
    sys.exit(1)
else:
    print("✅ All checks passed successfully!")
