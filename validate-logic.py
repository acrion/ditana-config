#!/usr/bin/env python3
import json
import os
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
