#!/usr/bin/env python3
import ast
import contextlib
import ctypes
import difflib
import fcntl
import http.server
import io
import json
import os
import re
import secrets
import select
import shlex
import signal
import socket
import stat
import subprocess
import sys
import shutil
import tarfile
import tempfile
import threading
import time
import xml.etree.ElementTree as ET

# ---------------------------------------------------------------------------
# Checks that cannot run on every machine.
#
# A check that is missing something it needs skips with a line starting with
# ℹ️ rather than failing, enabling the checks to execute on any machine. Each
# skip goes through skip() under a distinct name. In CI, a skip counts as an
# error unless DITANA_EXPECTED_SKIPS names it, ensuring that what CI verifies
# cannot diminish without notice. An expected skip that fails to occur is also
# an error in CI, so that the list keeps no stale entry.
# ---------------------------------------------------------------------------

EXPECTED_SKIPS = 'DITANA_EXPECTED_SKIPS'

# Skips determined by another hook and communicated via
# validate-logic.py --skip: a run of the checks cannot tell whether
# they occurred.
SKIPS_DECIDED_ELSEWHERE = ('kdlfmt',)

# The names with which skip() was invoked during this run of the checks.
skipped_names = set()


def in_ci():
    """Whether the checks run in CI: CI is set, as GitHub Actions sets it to true, and neither empty nor false nor 0.

    Neither the case of the letters nor blanks around the value count.
    """
    return os.environ.get('CI', '').strip().lower() not in ('', 'false', '0')


def skip(name, message, out_errors, skipped=skipped_names):
    """Reports that a check does not run here: MESSAGE says what is missing and what is skipped, NAME names the skip.

    Outside CI it prints an ℹ️ line, and the checks go on. In CI it is an
    error, unless NAME is one of the names, separated by blanks, in
    DITANA_EXPECTED_SKIPS. The checks of the NoExtract patterns against the
    repositories used to skip in CI without anybody noticing: the runner had
    no pacman and no fakeroot, and nobody reads the ℹ️ lines of a run that
    passes. A workflow names the skips that its container cannot avoid, and
    any other one fails the run.

    Whatever it makes of the skip, NAME goes into SKIPPED, by default the
    names of this run, which stale_expected_skips() compares with
    DITANA_EXPECTED_SKIPS once all checks are done.
    """
    skipped.add(name)
    if not in_ci():
        print(f"ℹ️  {message} (skip {name})")
    elif name in os.environ.get(EXPECTED_SKIPS, '').split():
        print(f"ℹ️  {message} (skip {name}, which {EXPECTED_SKIPS} expects)")
    else:
        out_errors.append(f"❌ {message} In CI a skip is an error unless {EXPECTED_SKIPS} names it: {name}.")


def skip_command(argv):
    """validate-logic.py --skip NAME MESSAGE: skip() for a check outside this script, as an exit status.

    Returns 1 where skip() makes the skip an error and 0 where it lets it
    pass. Any other arguments end in the usage and 2, a mistyped switch and
    an argument too many included, so that a caller who gets the call wrong
    fails rather than passing as a skip. The skip belongs to the hook that
    calls the command, not to a run of the checks, so it stays out of
    skipped_names, which check_skip_command would otherwise fill in the
    middle of a run.
    """
    if len(argv) != 4 or argv[1] != '--skip':
        print("usage: validate-logic.py [--skip NAME MESSAGE]", file=sys.stderr)
        return 2
    found = []
    skip(argv[2], argv[3], found, set())
    for line in found:
        print(line)
    return 1 if found else 0


def stale_expected_skips(skipped):
    """The names in DITANA_EXPECTED_SKIPS that are neither in SKIPPED nor decided elsewhere, in CI; outside CI none.

    An entry whose check no longer skips, say because the container has
    gained a German locale, would otherwise stay in the list, and should the
    check skip again one day, CI would let it pass without anybody noticing.
    kdlfmt skips in a hook of its own, so a run of the checks cannot tell
    whether it did.
    """
    if not in_ci():
        return []
    return [name for name in os.environ.get(EXPECTED_SKIPS, '').split()
            if name not in skipped and name not in SKIPS_DECIDED_ELSEWHERE]


@contextlib.contextmanager
def environment(values):
    """Sets the variables in VALUES, unsetting one whose value is None, and restores them all afterwards."""
    saved = {name: os.environ.get(name) for name in values}

    def put(assignments):
        for name, value in assignments.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value

    put(values)
    try:
        yield
    finally:
        put(saved)


SKIP_PROBE = "No probe here: skipping the probe."


def check_skip(out_errors):
    """A skip is an ℹ️ line outside CI, in CI an error unless DITANA_EXPECTED_SKIPS names it, and recorded either way.

    CI counts as set where the variable is set, as GitHub Actions sets it to
    true, but not where it is empty, false or 0, whatever the case of the
    letters and with blanks around it: FALSE and " false " are no CI either.
    DITANA_EXPECTED_SKIPS separates the names by blanks, and only a whole
    name counts: neither user nor systemd-user-manager covers user-manager.
    In every case the name goes into the record that stale_expected_skips()
    reads. Each case gives CI and DITANA_EXPECTED_SKIPS, None where the
    variable is unset, and whether the skip is an error.
    """
    name = "user-manager"
    cases = [
        (None, None, False), ("", None, False), ("false", None, False), ("FALSE", None, False),
        (" false ", None, False), ("0", None, False), (None, name, False),
        ("true", None, True), ("1", None, True), ("true", "", True), ("true", "user", True),
        ("true", f"systemd-{name}", True), ("true", f"german-locale {name}", False), ("TRUE", f"\t{name}\n", False),
    ]
    for ci, expected, error in cases:
        found, recorded, stdout = [], set(), io.StringIO()
        with environment({"CI": ci, EXPECTED_SKIPS: expected}), contextlib.redirect_stdout(stdout):
            skip(name, SKIP_PROBE, found, recorded)
        printed = stdout.getvalue()
        if error:
            ok = not printed and len(found) == 1 and found[0].startswith(f"❌ {SKIP_PROBE}") and name in found[0]
        else:
            ok = not found and printed.startswith(f"ℹ️  {SKIP_PROBE}") and name in printed
        if not ok or recorded != {name}:
            out_errors.append(f"❌ skip() with CI={ci!r} and {EXPECTED_SKIPS}={expected!r} printed {printed!r}, "
                              f"reported {found!r} and recorded {sorted(recorded)!r}; expected "
                              f"{'an error' if error else 'an ℹ️ line'} naming {name}, and {name} recorded.")


def check_skip_command(out_errors):
    """validate-logic.py --skip NAME MESSAGE exits with 1 where skip() makes the skip an error, and with 0 otherwise.

    The KDL syntax validation is a hook of its own in .pre-commit-config.yaml
    that runs before this script. Where kdlfmt is missing it skips through
    this command, so that the rule of skip() holds for it as well. The
    command takes exactly this form: an argument too few or too many, or a
    mistyped switch, is a usage error with exit status 2, so that a hook
    that gets the call wrong fails instead of passing as a skip. This check
    calls skip_command() in this process, case by case; whether the script
    itself ends there is the business of check_skip_command_runs_no_check.
    """
    cases = [
        (None, None, ["--skip", "kdlfmt", SKIP_PROBE], 0, f"ℹ️  {SKIP_PROBE}"),
        ("true", None, ["--skip", "kdlfmt", SKIP_PROBE], 1, f"❌ {SKIP_PROBE}"),
        ("true", "kdlfmt", ["--skip", "kdlfmt", SKIP_PROBE], 0, f"ℹ️  {SKIP_PROBE}"),
        (None, None, ["--skip", "kdlfmt"], 2, None),
        (None, None, ["--skip", "kdlfmt", SKIP_PROBE, SKIP_PROBE], 2, None),
        (None, None, ["--skp", "kdlfmt", SKIP_PROBE], 2, None),
    ]
    for ci, expected, args, status, start in cases:
        stdout, stderr = io.StringIO(), io.StringIO()
        with (environment({"CI": ci, EXPECTED_SKIPS: expected}), contextlib.redirect_stdout(stdout),
              contextlib.redirect_stderr(stderr)):
            got = skip_command(["validate-logic.py"] + args)
        if start is None:
            ok = got == status and not stdout.getvalue() and "usage:" in stderr.getvalue()
        else:
            ok = got == status and stdout.getvalue().startswith(start) and not stderr.getvalue()
        if not ok:
            out_errors.append(f"❌ validate-logic.py {shlex.join(args)} with CI={ci!r} and {EXPECTED_SKIPS}="
                              f"{expected!r}: exit status {got}, printed {stdout.getvalue()!r} and "
                              f"{stderr.getvalue()!r}; expected {status}.")


SKIP_COPY = 'DITANA_VALIDATE_SKIP_COPY'


def check_skip_command_runs_no_check(out_errors):
    """validate-logic.py --skip NAME MESSAGE ends with skip_command(), before the first check.

    check_skip_command calls skip_command() in this process, so it cannot
    see whether the script gets there. Should the branch at the top of the
    checks break, --skip would run all of them and end with 0 where they
    pass, and the KDL syntax validation would pass in CI where kdlfmt is
    missing. So this check runs the script itself, in CI with no skip
    expected, and wants the one error line of skip_command() and exit status
    1. A copy that got past the branch would come to this check as well, and
    DITANA_VALIDATE_SKIP_COPY in its environment keeps it from starting a
    copy of its own, and that one another, without end.
    """
    if os.environ.get(SKIP_COPY) is not None:
        return
    args = ["--skip", "kdlfmt", SKIP_PROBE]
    env = {name: value for name, value in os.environ.items() if name != EXPECTED_SKIPS}
    env.update({"CI": "true", SKIP_COPY: "1"})
    run = subprocess.run([sys.executable, os.path.abspath(__file__)] + args, env=env, stdin=subprocess.DEVNULL,
                         capture_output=True, text=True)
    lines = run.stdout.splitlines()
    if (run.returncode != 1 or len(lines) != 1 or not lines[0].startswith(f"❌ {SKIP_PROBE}")
            or "kdlfmt" not in lines[0]):
        out_errors.append(f"❌ validate-logic.py {shlex.join(args)} in CI with no skip expected: exit status "
                          f"{run.returncode}, printed {lines[:3]!r} and {run.stderr.splitlines()[:3]!r}; expected "
                          f"exit status 1 and only the error line of the skip.")


def check_stale_expected_skips(out_errors):
    """In CI, a name in DITANA_EXPECTED_SKIPS whose check did not skip is stale, unless another hook decides it.

    A stale entry would let its skip pass in CI without notice once the
    check skips again. kdlfmt skips in the KDL syntax validation, a hook of
    its own, so this run cannot tell whether it did. Outside CI the list
    means nothing, and only a whole name counts. Each case gives CI and
    DITANA_EXPECTED_SKIPS, None where the variable is unset, the names that
    skipped and the stale ones.
    """
    cases = [
        (None, "user-manager", set(), []),
        ("false", "user-manager", set(), []),
        ("true", None, {"user-manager"}, []),
        ("true", "user-manager german-locale", {"user-manager", "german-locale"}, []),
        ("true", "user-manager german-locale", {"user-manager"}, ["german-locale"]),
        ("true", "german-locale user-manager", set(), ["german-locale", "user-manager"]),
        ("true", "kdlfmt user-manager", {"user-manager"}, []),
        ("true", "user", {"user-manager"}, ["user"]),
    ]
    for ci, expected, skipped, stale in cases:
        with environment({"CI": ci, EXPECTED_SKIPS: expected}):
            got = stale_expected_skips(skipped)
        if got != stale:
            out_errors.append(f"❌ stale_expected_skips() with CI={ci!r}, {EXPECTED_SKIPS}={expected!r} and the "
                              f"skips {sorted(skipped)!r} returned {got!r}; expected {stale!r}.")


def check_skips_go_through_skip(out_errors):
    """No code in this script but skip() prints ℹ️, the mark of a skip.

    A check that printed its own skip line would go past the rule of skip():
    in CI it would pass where DITANA_EXPECTED_SKIPS does not name it, the
    way the checks against the repositories went missing in CI before, and
    stale_expected_skips() would never hear of it. So the source of this
    script is parsed, and every call of print outside skip() whose
    arguments hold a string with ℹ️ in it is reported with its line.
    """
    with open(__file__, encoding="utf-8") as f:
        tree = ast.parse(f.read())
    inside = {id(node) for definition in ast.walk(tree)
              if isinstance(definition, ast.FunctionDef) and definition.name == "skip"
              for node in ast.walk(definition)}
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "print"
                and id(node) not in inside
                and any(isinstance(part, ast.Constant) and isinstance(part.value, str) and "ℹ" in part.value
                        for part in ast.walk(node))):
            out_errors.append(f"❌ validate-logic.py, line {node.lineno}: a check prints ℹ️ itself instead of "
                              f"skipping through skip().")


if len(sys.argv) > 1:
    sys.exit(skip_command(sys.argv))

config_path = '/tmp/ditana-config.json'
try:
    with open(config_path) as f:
        config = json.load(f)
except FileNotFoundError:
    print(f"❌ Could not find {config_path}. Ensure 'validate-kdl-via-json' runs first.")
    sys.exit(1)

settings = config.get('settings',[])
errors = False

print("🔍 Checking how a check skips where something is missing...")
skip_errors = []
check_skip(skip_errors)
check_skip_command(skip_errors)
check_skip_command_runs_no_check(skip_errors)
check_stale_expected_skips(skip_errors)
check_skips_go_through_skip(skip_errors)
for line in skip_errors:
    print(line)
if skip_errors:
    errors = True

# ---------------------------------------------------------------------------
# The GitHub workflows responsible for executing these checks.
# ---------------------------------------------------------------------------

WORKFLOWS = ('.github/workflows/release.yml', '.github/workflows/release-develop.yml',
             '.github/workflows/daily-check.yml')
DAILY_WORKFLOW = '.github/workflows/daily-check.yml'


def check_workflows_verbose(out_errors):
    """Every workflow runs pre-commit with --verbose, so that its log shows the skips of a run that passes.

    pre-commit shows the output of a hook that passes only with --verbose.
    Without it, nothing in the log of a passing run would show which checks
    skipped, nor that DITANA_EXPECTED_SKIPS expects them, and so nothing
    would show that the rule of skip() is in force at all.
    """
    for path in WORKFLOWS:
        with open(path) as f:
            calls = [line.split() for line in f if "pre-commit run" in line and not line.lstrip().startswith("#")]
        if not calls or any(not {"--verbose", "-v"} & set(call) for call in calls):
            out_errors.append(f"❌ {path} does not run pre-commit with --verbose, so a log of it that passes "
                              f"would not show the skips.")


def check_daily_workflow_by_hand(out_errors):
    """The daily workflow can be started by hand: workflow_dispatch is one of the events under its on:.

    Otherwise a change to the workflow, or a fix for what it found in the
    repositories, could only be tried out by waiting for its next scheduled
    run.
    """
    with open(DAILY_WORKFLOW) as f:
        text = f.read()
    if not re.search(r'^on:[ \t]*\n(?:(?:[ \t]+.*|[ \t]*)\n)*?[ \t]+workflow_dispatch:', text, re.M):
        out_errors.append(f"❌ {DAILY_WORKFLOW} cannot be started by hand: workflow_dispatch is missing under its on:.")


print("🔍 Checking the GitHub workflows...")
workflow_errors = []
check_workflows_verbose(workflow_errors)
check_daily_workflow_by_hand(workflow_errors)
for line in workflow_errors:
    print(line)
if workflow_errors:
    errors = True

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

print("🔍 Checking uniqueness of settings...")
all_names = [s['name'] for s in settings if 'name' in s]
duplicates = {n for n in all_names if all_names.count(n) > 1}
if duplicates:
    print(f"❌ Duplicate setting names: {sorted(duplicates)}")
    errors = True

SYSCTL_KEY_RE = re.compile(r'[a-z][a-z0-9_]*(\.[a-z0-9_*-]+)+')

scripts_to_check =[]

print("🔍 Validating chroot scripts and shell code...")
for s in settings:
    name = s.get('name', 'unknown')

    for line in s.get('chroot-script',[]):
        if '/etc/skel/' in line:
            print(f"❌ Setting '{name}' uses '/etc/skel/' in 'chroot-script'. Use 'early-chroot-script' instead. Line: {line}")
            errors = True

    # The guard matches an executable by the file it finds at this path, so a
    # relative path would be resolved against whatever directory the loader
    # happens to run in. There is no sensible reading of one here.
    for path in s.get('userns-allow',[]):
        if not path.startswith('/'):
            print(f"❌ Setting '{name}' declares 'userns-allow' with a relative path: {path}")
            errors = True

    for entry in s.get('sysctl',[]):
        key, value = entry[0], entry[1]
        if not SYSCTL_KEY_RE.fullmatch(key):
            print(f"❌ Setting '{name}' declares a sysctl key that is not one: {key}")
            errors = True
        # The value ends up to the right of '=' on a line of its own, so a value
        # carrying a newline or a '#' would silently write something else.
        if value == '' or any(c in value for c in '#\n\r'):
            print(f"❌ Setting '{name}' declares an unusable sysctl value for '{key}': {value!r}")
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
# Applications launched from waybar are required to persist beyond its
# lifespan.
#
# waybar 0.15 sends SIGTERM to the process group associated with each click
# command upon module removal, while any application launched via the bar
# remains within waybar's cgroup by default. The script at
# `/usr/lib/ditana/launch` relocates the application out of both.
# ---------------------------------------------------------------------------

WAYBAR_CONFIG = '/etc/skel/.config/waybar/config.jsonc'
LAUNCH = '/usr/lib/ditana/launch'
OPEN_DISKS = '/usr/lib/ditana/open-disks'
WAYBAR_DISPLAY_SCALE = '/usr/lib/ditana/waybar-display-scale'
WAYBAR_DISPLAY_SCALE_UNIT = '/usr/lib/systemd/user/waybar-display-scale.service'

# Within these modules, the on-click value names one of the module's own
# actions (minimize-raise, close, ...), rather than representing a command.
ACTION_MODULES = {'wlr/taskbar', 'ext/workspaces'}
USER_EVENT_KEY_RE = re.compile(r'on-(click|double-click|triple-click|scroll)')

# The stand-in program, once launched: it reports its pid, then simply remains
# active.
MARKER_SCRIPT = 'echo $$ > "$0"; exec sleep 300'


def repo_path(path):
    return os.path.join("folders", path.lstrip("/"))


def jsonc_loads(text):
    """Parses JSON with // and /* */ comments and trailing commas, as waybar does."""
    out = []
    i, n = 0, len(text)
    in_string = False
    while i < n:
        c = text[i]
        if in_string:
            out.append(c)
            if c == '\\':
                out.append(text[i + 1])
                i += 1
            elif c == '"':
                in_string = False
            i += 1
        elif c == '"':
            in_string = True
            out.append(c)
            i += 1
        elif text.startswith('//', i):
            end = text.find('\n', i)
            i = n if end < 0 else end
        elif text.startswith('/*', i):
            end = text.find('*/', i + 2)
            i = n if end < 0 else end + 2
        else:
            if c in '}]':
                k = len(out) - 1
                while k >= 0 and out[k].isspace():
                    k -= 1
                if k >= 0 and out[k] == ',':
                    del out[k]
            out.append(c)
            i += 1
    return json.loads(''.join(out))


def installed_waybar_config(all_settings, workdir):
    """config.jsonc as the installer leaves it.

    Settings may edit the file in their early-chroot-script: the Ditana Assistant
    button is inserted by sed. Those scripts run here against a copy below
    workdir, so the checks see their result, and a script that breaks the JSON
    fails here rather than on a user's machine.
    """
    target = os.path.join(workdir, WAYBAR_CONFIG.lstrip("/"))
    os.makedirs(os.path.dirname(target))
    shutil.copy(repo_path(WAYBAR_CONFIG), target)
    for s in all_settings:
        lines = [l for l in s.get('early-chroot-script', []) if not is_backtick_code(l.strip())]
        if not any(WAYBAR_CONFIG in l for l in lines):
            continue
        script = "\n".join(lines).replace("/etc/skel/", workdir + "/etc/skel/")
        res = subprocess.run(["bash", "-e", "-c", script], capture_output=True, text=True)
        if res.returncode != 0:
            raise RuntimeError(f"early-chroot-script of '{s.get('name')}' failed on {WAYBAR_CONFIG}: {res.stderr.strip()}")
    with open(target) as f:
        return jsonc_loads(f.read())


def waybar_user_commands(bar_config):
    """(module, key, command) for every command the bar runs on a click or scroll."""
    bars = bar_config if isinstance(bar_config, list) else [bar_config]
    for bar in bars:
        for module, conf in bar.items():
            if not isinstance(conf, dict) or module.split('#')[0] in ACTION_MODULES:
                continue
            for key, value in conf.items():
                if USER_EVENT_KEY_RE.match(key) and isinstance(value, str):
                    yield module, key, value


def check_waybar_launchers(bar_config, shipped_files, out_errors):
    """Every click or scroll command starts its program through launch.

    Without it, a reload of waybar (SIGUSR2, which is also what the waybar.service
    of the package sends on reload), a SIGINT, or the bar's monitor going away
    kills the program; so does stopping the unit waybar runs in. Every absolute
    program path a command names must be shipped by the setting that installs
    the config, so that it exists wherever the button does. That includes a
    Ditana helper named further on in the command, such as one that a command
    starts through "sh -c" after another program.
    """
    for module, key, command in waybar_user_commands(bar_config):
        argv = shlex.split(command)
        if argv[0] != LAUNCH or len(argv) < 2:
            out_errors.append(
                f"❌ waybar '{module}' {key} runs {command!r} directly. Start it through "
                f"'{LAUNCH} ...' so that it survives a reload or restart of waybar.")
            continue
        programs = [p for p in argv[:2] if p.startswith("/")]
        programs += [p for p in DITANA_PROGRAM_RE.findall(command) if p not in programs]
        for program in programs:
            if program not in shipped_files:
                out_errors.append(
                    f"❌ waybar '{module}' {key} runs {program}, which the setting installing "
                    f"{WAYBAR_CONFIG} does not ship.")


DITANA_PROGRAM_RE = re.compile(r"(?<![\w./-])/usr/lib/ditana/[\w.+-]+")


def check_waybar_module_programs(bar_config, shipped_files, out_errors):
    """Every Ditana helper that a module runs for its content is shipped with the config.

    check_waybar_launchers looks at click and scroll commands only, so a helper
    named in "exec" or "exec-if" alone was never checked. A missing one fails
    silently: waybar hides a custom module whose exec-if fails or whose exec
    prints nothing, so the module would never appear on an installed system,
    and nothing would report why.
    """
    bars = bar_config if isinstance(bar_config, list) else [bar_config]
    for bar in bars:
        for module, conf in bar.items():
            if not isinstance(conf, dict):
                continue
            for key in ('exec', 'exec-if'):
                if not isinstance(conf.get(key), str):
                    continue
                for program in DITANA_PROGRAM_RE.findall(conf[key]):
                    if program not in shipped_files:
                        out_errors.append(
                            f"❌ waybar '{module}' {key} names {program}, which the setting installing "
                            f"{WAYBAR_CONFIG} does not ship.")


def check_disk_opens_what_it_shows(bar_config, out_errors):
    """The disk module shows the free space of its "path" (waybar's default is "/").

    Its click has to hand exactly that path to open-disks; otherwise the button
    opens another filesystem than the one its number belongs to.
    """
    bars = bar_config if isinstance(bar_config, list) else [bar_config]
    for bar in bars:
        for module, conf in bar.items():
            if module.split('#')[0] != 'disk' or not isinstance(conf, dict) or 'on-click' not in conf:
                continue
            expected = [LAUNCH, OPEN_DISKS, conf.get('path', '/')]
            if shlex.split(conf['on-click']) != expected:
                out_errors.append(
                    f"❌ waybar '{module}' on-click should be {shlex.join(expected)!r}, the path "
                    f"whose free space it shows, but is {conf['on-click']!r}.")


def check_io_pressure_label_width(bar_config, out_errors):
    """The second line of custom/io-pressure is no longer than that of the disk module beside it.

    A two-line box is as wide as its longer line. The value line of the I/O
    pressure module holds at most "100%", so its label alone sets the width:
    "IO pressure" made the box wider than the "disk space" box next to it,
    although its value needs less room, which is why the label became "IO
    wait". Characters stand in for the rendered width, which depends on the
    font; in Noto Sans, DejaVu Sans, Cantarell and Roboto alike, "IO wait"
    renders narrower than "disk space" and "IO pressure" wider.
    """
    bars = bar_config if isinstance(bar_config, list) else [bar_config]
    for bar in bars:
        io = bar.get('custom/io-pressure')
        disk = bar.get('disk')
        if not isinstance(io, dict) or not isinstance(disk, dict):
            continue
        io_format, disk_format = io.get('format', ''), disk.get('format', '')
        if '\n' not in io_format or '\n' not in disk_format:
            continue
        io_label = io_format.rpartition('\n')[2]
        disk_label = disk_format.rpartition('\n')[2]
        if len(io_label) > len(disk_label):
            out_errors.append(
                f"❌ waybar 'custom/io-pressure' label {io_label!r} is longer than the label {disk_label!r} "
                f"of 'disk' beside it, which makes its box wider than the disk box.")


def wait_for_file(path, timeout=10.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with open(path) as f:
                content = f.read()
            if content.strip():
                return content
        except FileNotFoundError:
            pass
        time.sleep(0.05)
    return None


def process_alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    with open(f"/proc/{pid}/stat") as f:
        return f.read().rsplit(')', 1)[1].split()[0] != 'Z'


def marker_pid(content):
    """The pid the stand-in program wrote, or None if its script arrived altered."""
    try:
        return int(content)
    except (TypeError, ValueError):
        return None


def stop_marker(pid):
    if pid is not None:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


def check_launch_passes_arguments(workdir, env, mode, out_errors):
    """launch hands its arguments to the program unchanged.

    Blanks, quotes, glob characters, an empty argument and a literal $ have to
    arrive as given, whether launch goes through systemd-run or not.
    """
    result = os.path.join(workdir, f"arguments-{mode}")
    args = ["a b", "", 'c"d', "*", "$HOME"]
    subprocess.run([repo_path(LAUNCH), "sh", "-c", 'printf "%s|" "$@" > "$0.tmp" && mv "$0.tmp" "$0"', result] + args,
                   env=env, check=True)
    got = wait_for_file(result)
    if got != "|".join(args) + "|":
        out_errors.append(f"❌ launch ({mode}) passed the arguments {args!r} on as {got!r}.")


def check_launch_leaves_process_group(workdir, env, mode, out_errors):
    """What waybar's module teardown does to a click command.

    waybar runs the command with /bin/sh in a process group of its own and later
    sends SIGTERM to that group. The group is kept alive here by the shell that
    ran launch, so the SIGTERM has something to hit; the launched program has to
    be in a session of its own and survive it.
    """
    pidfile = os.path.join(workdir, f"marker-pgid-{mode}")
    on_click = f"{shlex.quote(repo_path(LAUNCH))} sh -c {shlex.quote(MARKER_SCRIPT)} {shlex.quote(pidfile)}; exec sleep 300"
    bar = subprocess.Popen(["/bin/sh", "-c", on_click], env=env, process_group=0)
    pid = None
    try:
        content = wait_for_file(pidfile)
        if content is None:
            out_errors.append(f"❌ launch ({mode}) did not start the program within 10 s.")
            return
        pid = marker_pid(content)
        if pid is None:
            out_errors.append(f"❌ launch ({mode}) altered the program's script: it wrote {content!r}, not its pid.")
            return
        if os.getsid(pid) != pid:
            out_errors.append(f"❌ launch ({mode}) left the program in session {os.getsid(pid)} instead of its own.")
        os.killpg(bar.pid, signal.SIGTERM)
        bar.wait(timeout=10)
        time.sleep(0.2)
        if not process_alive(pid):
            out_errors.append(f"❌ launch ({mode}): the program died with the process group of its caller.")
    finally:
        stop_marker(pid)
        if bar.poll() is None:
            bar.kill()
            bar.wait()


def check_launch_leaves_cgroup(workdir, out_errors):
    """What stopping the unit that holds waybar does: systemd kills its whole cgroup.

    Here the caller runs in a transient scope of its own, which is then stopped.
    The launched program has to keep running, in an app-ditana-<program>-<random>
    scope that ends with the graphical session.
    """
    pidfile = os.path.join(workdir, "marker-cgroup")
    unit = f"ditana-validate-bar-{os.getpid()}-{secrets.token_hex(4)}.scope"
    on_click = f"{shlex.quote(repo_path(LAUNCH))} sh -c {shlex.quote(MARKER_SCRIPT)} {shlex.quote(pidfile)}; exec sleep 300"
    bar = subprocess.Popen(["systemd-run", "--user", "--scope", "--quiet", "--collect", "--expand-environment=no",
                            f"--unit={unit}", "--", "/bin/sh", "-c", on_click], process_group=0)
    pid = None
    try:
        content = wait_for_file(pidfile)
        if content is None:
            out_errors.append("❌ launch (scope) did not start the program within 10 s.")
            return
        pid = marker_pid(content)
        if pid is None:
            out_errors.append(f"❌ launch (scope) altered the program's script: it wrote {content!r}, not its pid.")
            return
        subprocess.run(["systemctl", "--user", "stop", unit], check=True)
        bar.wait(timeout=10)
        time.sleep(0.2)
        if not process_alive(pid):
            out_errors.append("❌ launch (scope): the program died when the unit of its caller was stopped.")
            return
        with open(f"/proc/{pid}/cgroup") as f:
            scope = f.read().strip().rsplit("/", 1)[1]
        if not re.fullmatch(r"app-ditana-sh-[0-9a-f]{8}\.scope", scope):
            out_errors.append(f"❌ launch (scope) put the program into {scope!r}, not app-ditana-sh-<random>.scope.")
            return
        part_of = subprocess.run(["systemctl", "--user", "show", "-p", "PartOf", "--value", scope],
                                 capture_output=True, text=True).stdout.split()
        if "graphical-session.target" not in part_of:
            out_errors.append(f"❌ launch (scope): {scope} is not PartOf=graphical-session.target.")
    finally:
        stop_marker(pid)
        if bar.poll() is None:
            bar.kill()
            bar.wait()
        subprocess.run(["systemctl", "--user", "stop", unit], capture_output=True)


def user_manager_reachable():
    runtime_dir = os.environ.get("XDG_RUNTIME_DIR") or f"/run/user/{os.getuid()}"
    return os.path.exists(os.path.join(runtime_dir, "systemd", "private")) and shutil.which("systemd-run")


OPEN_DISKS_STUBS = {
    "findmnt": '#!/bin/sh\nprintf "%s\\n" "$*" >> "$STUB_LOG_FINDMNT"\n'
               '[ "$STUB_FINDMNT_STATUS" = 0 ] || exit "$STUB_FINDMNT_STATUS"\n'
               'case "$*" in *FSTYPE*) echo "$STUB_FSTYPE" ;; *SOURCE*) echo "$STUB_SOURCE" ;; esac\n',
    "gnome-disks": '#!/bin/sh\nprintf "%s\\0" gnome-disks "$@"\nexit "$STUB_GNOME_DISKS_STATUS"\n',
    "xdg-terminal-exec": '#!/bin/sh\nprintf "%s\\0" xdg-terminal-exec "$@"\n',
    "notify-send": '#!/bin/sh\nprintf "%s\\n" "$*" >> "$STUB_LOG_NOTIFY"\n',
    "systemd-cat": '#!/bin/sh\nprio=info\n'
                   'while [ $# -gt 0 ]; do [ "$1" = -p ] && prio=$2; shift; done\n'
                   'while IFS= read -r line; do printf "%s %s\\n" "$prio" "$line" >> "$STUB_LOG_JOURNAL"; done\n',
}


def read_lines(path):
    try:
        with open(path) as f:
            return f.read().splitlines()
    except FileNotFoundError:
        return []


def open_disks_run(workdir, path, fstype="", source="", findmnt_status=0, gnome_disks_status=0, without=()):
    """Runs open-disks against stubs, with nothing but the stubs and bash on its PATH.

    The closed PATH keeps the checks from ever opening GNOME Disks, a terminal or
    a notification on the machine that runs them, and makes a program missing
    from the stubs (`without`) really missing. Returns the findmnt targets it
    asked about, the argv of the program it started, its exit status, the
    notifications it sent and the journal lines it wrote as "priority message".
    """
    stubs = tempfile.mkdtemp(dir=workdir)
    for name, body in OPEN_DISKS_STUBS.items():
        if name in without:
            continue
        with open(os.path.join(stubs, name), "w") as f:
            f.write(body)
        os.chmod(os.path.join(stubs, name), 0o755)
    os.symlink(shutil.which("bash"), os.path.join(stubs, "bash"))
    logs = {name: os.path.join(stubs, f"{name}.log") for name in ("findmnt", "notify", "journal")}
    env = dict(os.environ, PATH=stubs,
               STUB_LOG_FINDMNT=logs["findmnt"], STUB_LOG_NOTIFY=logs["notify"], STUB_LOG_JOURNAL=logs["journal"],
               STUB_FSTYPE=fstype, STUB_SOURCE=source,
               STUB_FINDMNT_STATUS=str(findmnt_status), STUB_GNOME_DISKS_STATUS=str(gnome_disks_status))
    res = subprocess.run([repo_path(OPEN_DISKS), path], env=env, capture_output=True, text=True)
    return {
        "targets": {line.split("-T ", 1)[1].strip() for line in read_lines(logs["findmnt"]) if "-T " in line},
        "argv": res.stdout.split("\0")[:-1],
        "status": res.returncode,
        "notifications": read_lines(logs["notify"]),
        "journal": read_lines(logs["journal"]),
    }


def some_block_device():
    """A block device node of the machine running the checks, or None."""
    for name in sorted(os.listdir("/dev")):
        path = os.path.join("/dev", name)
        try:
            if stat.S_ISBLK(os.stat(path).st_mode):
                return path
        except OSError:
            pass
    return None


def check_open_disks(workdir, out_errors):
    """open-disks opens the storage behind a path: waybar's disk button, Thunar's disk action.

    On ZFS the mount source is a dataset, which GNOME Disks cannot show; the
    terminal lists that dataset (its AVAIL is the free space in the bar) and its
    pool, which is the first component of the dataset name. The file system type
    decides, not whether the source looks like a device path: the root of the
    live ISO is an overlay whose source is a bare word, and that is no pool.
    A path that is itself a block device goes to GNOME Disks as it is, as it did
    in open-disk-manager, which open-disks replaced.
    """
    cases = [
        ("/", "zfs", "ditana-root/ROOT/default", ["sh", "ditana-root/ROOT/default", "ditana-root"]),
        ("/", "zfs", "tank", ["sh", "tank", "tank"]),
        ("/home", "btrfs", "/dev/nvme0n1p2", ["gnome-disks", "--block-device=/dev/nvme0n1p2"]),
        ("/", "overlay", "airootfs", ["gnome-disks"]),
    ]
    for path, fstype, source, expected in cases:
        run = open_disks_run(workdir, path, fstype, source)
        label = f"open-disks {path} on {fstype} ({source})"
        argv = run["argv"]
        if run["targets"] != {path}:
            out_errors.append(f"❌ {label} asked findmnt about {sorted(run['targets'])} instead of {path!r}.")
        if fstype == "zfs":
            if argv[:3] != ["xdg-terminal-exec", "sh", "-c"] or argv[4:] != expected:
                out_errors.append(f"❌ {label} ran {argv!r}; expected a terminal for {expected[1:]}.")
            elif 'zfs list -o name,used,avail,refer,mountpoint "$1"' not in argv[3]:
                out_errors.append(f"❌ {label} does not list the AVAIL of the dataset itself.")
        elif argv != expected:
            out_errors.append(f"❌ {label} ran {argv!r} instead of {expected!r}.")
        if run["status"] != 0 or run["notifications"] or any(l.startswith("err ") for l in run["journal"]):
            out_errors.append(f"❌ {label} reported a failure: exit {run['status']}, "
                              f"notifications {run['notifications']!r}, journal {run['journal']!r}.")

    device = some_block_device()
    if device is None:
        skip("block-device", "No block device node in /dev here: skipping the block-device case of open-disks.",
             out_errors)
    else:
        run = open_disks_run(workdir, device)
        if run["argv"] != ["gnome-disks", f"--block-device={device}"] or run["targets"]:
            out_errors.append(f"❌ open-disks {device} (a block device) ran {run['argv']!r} after asking findmnt "
                              f"about {sorted(run['targets'])}; expected GNOME Disks on the device itself.")


def check_open_disks_reports_failures(workdir, out_errors):
    """A failure of open-disks shows up as a notification and in the journal.

    waybar and Thunar both start open-disks without a terminal, so an error on
    stderr goes unseen and the click seems to do nothing. open-disk-manager, which
    open-disks replaced, showed a zenity dialog in these cases; zenity comes only
    with XFCE, while libnotify comes with every Ditana desktop. GNOME Disks
    prints a device it cannot look up only on stderr and exits with 1.
    """
    cases = [
        ("no filesystem holds the path",
         dict(path="/gone", findmnt_status=1), []),
        ("GNOME Disks fails",
         dict(path="/home", fstype="btrfs", source="/dev/nvme0n1p2", gnome_disks_status=1),
         ["gnome-disks", "--block-device=/dev/nvme0n1p2"]),
        ("no terminal for a ZFS dataset",
         dict(path="/", fstype="zfs", source="tank", without=("xdg-terminal-exec",)), []),
    ]
    for label, kwargs, expected_argv in cases:
        run = open_disks_run(workdir, **kwargs)
        if run["argv"] != expected_argv:
            out_errors.append(f"❌ open-disks, {label}: ran {run['argv']!r}, expected {expected_argv!r}.")
        if run["status"] != 1:
            out_errors.append(f"❌ open-disks, {label}: exit status {run['status']}, expected 1.")
        if len(run["notifications"]) != 1:
            out_errors.append(f"❌ open-disks, {label}: sent {run['notifications']!r} instead of one notification.")
        if not any(l.startswith("err ") for l in run["journal"]):
            out_errors.append(f"❌ open-disks, {label}: wrote no error to the journal ({run['journal']!r}).")


THUNAR_ACTIONS = '/etc/skel/.config/Thunar/uca.xml'


def check_thunar_actions(all_settings, out_errors):
    """Every program that a Thunar custom action calls by its path is shipped with the actions.

    To the other checks uca.xml is only data: none of them would notice an action
    that keeps calling a script after the script is gone, as open-disk-manager
    went when the disk action moved to open-disks.
    """
    owner = next((s for s in all_settings if THUNAR_ACTIONS in s.get('files', [])), None)
    if owner is None:
        out_errors.append(f"❌ No setting ships {THUNAR_ACTIONS}.")
        return
    for action in ET.parse(repo_path(THUNAR_ACTIONS)).getroot().iter("action"):
        argv = shlex.split(action.findtext("command") or "")
        if argv and argv[0].startswith("/") and argv[0] not in owner['files']:
            out_errors.append(f"❌ Thunar action '{action.findtext('name')}' runs {argv[0]}, "
                              f"which '{owner['name']}' does not ship.")


def restart_waybar_calls(uwsm_session):
    """Runs restart_waybar from waybar-display-scale against stubs that record each call.

    The script's own LAUNCH assignment comes along, with DITANA_LAUNCH_BIN
    unset, so that the stub answers only to the default path of launch.
    """
    with open(repo_path(WAYBAR_DISPLAY_SCALE)) as f:
        script = f.read()
    match = re.search(r"^restart_waybar\(\) \{$.*?^\}$", script, re.M | re.S)
    launch = re.search(r"^LAUNCH=.*$", script, re.M)
    if match is None or launch is None:
        return None
    stubs = """
calls=()
record() { calls+=("$*"); }
log() { :; }
systemctl() { return 1; }
running=1
pgrep() { (( running )); }
pkill() { record pkill "$@"; running=0; }
sleep() { :; }
setsid() { record setsid "$@"; }
uwsm() { if [[ $1 == check ]]; then return UWSM_CHECK; fi; record uwsm "$@"; }
/usr/lib/ditana/launch() { record launch "$@"; }
""".replace("UWSM_CHECK", "0" if uwsm_session else "1")
    env = {k: v for k, v in os.environ.items() if k != "DITANA_LAUNCH_BIN"}
    res = subprocess.run(["bash", "-c", stubs + launch.group(0) + "\n" + match.group(0)
                          + '\nrestart_waybar\nprintf "%s\\n" "${calls[@]}"'],
                         env=env, capture_output=True, text=True)
    return res.stdout.splitlines()


def check_display_scale_respawn(out_errors):
    """waybar-display-scale respawns waybar outside its own service.

    Without a uwsm session it used to run `setsid -f waybar`. That left waybar,
    and everything later started from its bar, inside waybar-display-scale.service;
    `pkill waybar` also matches the script, whose process name is
    "waybar-display-", so systemd stopped the service and killed the whole cgroup
    with it. With a uwsm session, `uwsm app -t service` already gave waybar a unit
    of its own.
    """
    expectations = {
        False: ["pkill -x waybar", "launch waybar"],
        True: ["pkill -x waybar", "uwsm app -t service -- waybar"],
    }
    for uwsm_session, expected in expectations.items():
        calls = restart_waybar_calls(uwsm_session)
        if calls is None:
            out_errors.append(f"❌ {WAYBAR_DISPLAY_SCALE} has no restart_waybar() or no LAUNCH= to check.")
            return
        if calls != expected:
            out_errors.append(f"❌ {WAYBAR_DISPLAY_SCALE} restarts waybar ({'with' if uwsm_session else 'without'} "
                              f"a uwsm session) by {calls!r}, expected {expected!r}.")


def check_display_scale_restarts(out_errors):
    """waybar-display-scale.service comes back after a SIGTERM.

    `pkill waybar` kills the script as well (its process name is
    "waybar-display-"). systemd counts SIGTERM as a clean exit, so with
    Restart=on-failure the scaling stayed off until the next login.
    """
    with open(repo_path(WAYBAR_DISPLAY_SCALE_UNIT)) as f:
        restart = [l.split("=", 1)[1].strip() for l in f if l.startswith("Restart=")]
    if restart != ["always"]:
        out_errors.append(f"❌ {WAYBAR_DISPLAY_SCALE_UNIT} has Restart={restart}, expected always.")


print("🔍 Checking that programs started from waybar outlive it...")
waybar_errors = []
waybar_setting = next((s for s in settings if WAYBAR_CONFIG in s.get('files', [])), None)
with tempfile.TemporaryDirectory() as workdir:
    if waybar_setting is None:
        waybar_errors.append(f"❌ No setting ships {WAYBAR_CONFIG}.")
    else:
        try:
            bar_config = installed_waybar_config(settings, workdir)
        except (RuntimeError, ValueError) as e:
            waybar_errors.append(f"❌ {WAYBAR_CONFIG} as installed cannot be read: {e}")
        else:
            check_waybar_launchers(bar_config, set(waybar_setting['files']), waybar_errors)
            check_waybar_module_programs(bar_config, set(waybar_setting['files']), waybar_errors)
            check_disk_opens_what_it_shows(bar_config, waybar_errors)
            check_io_pressure_label_width(bar_config, waybar_errors)

    no_user_manager = os.path.join(workdir, "no-user-manager")
    os.mkdir(no_user_manager)
    setsid_env = dict(os.environ, XDG_RUNTIME_DIR=no_user_manager)
    check_launch_passes_arguments(workdir, setsid_env, "setsid", waybar_errors)
    check_launch_leaves_process_group(workdir, setsid_env, "setsid", waybar_errors)
    if user_manager_reachable():
        check_launch_passes_arguments(workdir, os.environ, "scope", waybar_errors)
        check_launch_leaves_process_group(workdir, os.environ, "scope", waybar_errors)
        check_launch_leaves_cgroup(workdir, waybar_errors)
    else:
        skip("user-manager", "No systemd user manager here: skipping the scope checks of launch.", waybar_errors)

    check_open_disks(workdir, waybar_errors)
    check_open_disks_reports_failures(workdir, waybar_errors)

check_display_scale_respawn(waybar_errors)
check_display_scale_restarts(waybar_errors)

for line in waybar_errors:
    print(line)
if waybar_errors:
    errors = True

# ---------------------------------------------------------------------------
# The waybar helper responsible for I/O pressure ensures compliance with the
# output contract required by waybar.
#
# waybar 0.15 handles only the first line output by a custom module, retains the
# module's previous visual state if that line is not valid JSON, and hides the
# module when no output appears or when the exit status is not 0. The helper
# produces one line formatted as {"text", "tooltip", "class"}, where class is
# given as a list: nothing beneath WARM, ["warm", "warm-N"] for N ranging from 1
# to 5 up to HOT, and ["hot"] from HOT onward.
# ---------------------------------------------------------------------------

IO_PRESSURE = '/usr/lib/ditana/waybar-io-pressure'

# The duration a helper is allowed to take before a check considers it
# stalled. Checks put a FIFO in place of a file that a helper may open
# just once; attempting to open it a second time results in a block, and
# this timeout converts that block into a failure.
HELPER_TIMEOUT = 5


def write_file(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(content)


def make_fifo(path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    os.mkfifo(path)


def serve_once(fifo, content):
    """Hands CONTENT to the first reader of FIFO and then stops.

    A second open of the FIFO finds no writer and blocks until the helper's
    timeout, which is how the checks notice a file that was read twice.
    """
    def serve():
        try:
            with open(fifo, "w") as f:
                f.write(content)
        except OSError:
            pass
    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return thread


def release_fifo(fifo):
    """Lets a writer that is still waiting for a reader of FIFO finish."""
    try:
        os.close(os.open(fifo, os.O_RDONLY | os.O_NONBLOCK))
    except OSError:
        pass


def run_helper(path, args, env):
    """Runs a helper; returns its CompletedProcess, or None when it got stuck.

    A helper that cannot be started at all, because it is missing or lacks its
    executable bit, ends as it would under a shell: exit status 127 or 126,
    with the reason on stderr. Every check then reports it as a failure of its
    own, and the checks after it still run.
    """
    command = [repo_path(path)] + args
    try:
        return subprocess.run(command, env=dict(os.environ, **env),
                              capture_output=True, timeout=HELPER_TIMEOUT)
    except subprocess.TimeoutExpired:
        return None
    except OSError as e:
        status = 127 if isinstance(e, FileNotFoundError) else 126
        return subprocess.CompletedProcess(command, status, b"", f"cannot be run: {e}".encode())


HIDDEN = "hidden"


def module_output(label, res, out_errors):
    """What waybar makes of a helper's run.

    Returns the parsed JSON object, HIDDEN when waybar would hide the module
    (no output and exit status 0), or None after reporting a broken contract.
    """
    if res is None:
        out_errors.append(f"❌ {label}: did not finish within {HELPER_TIMEOUT} s.")
        return None
    if res.returncode != 0:
        out_errors.append(f"❌ {label}: exit status {res.returncode}, which hides the module "
                          f"(stderr {res.stderr!r}).")
        return None
    if res.stdout == b"":
        return HIDDEN
    try:
        stdout = res.stdout.decode("utf-8")
    except UnicodeDecodeError:
        out_errors.append(f"❌ {label}: output is not UTF-8: {res.stdout!r}.")
        return None
    if not stdout.endswith("\n") or "\n" in stdout[:-1]:
        out_errors.append(f"❌ {label}: output is not exactly one line: {stdout!r}.")
        return None
    try:
        out = json.loads(stdout)
    except ValueError as e:
        out_errors.append(f"❌ {label}: output is not valid JSON ({e}): {stdout!r}.")
        return None
    if (not isinstance(out, dict) or set(out) != {"text", "tooltip", "class"}
            or not isinstance(out["text"], str) or not isinstance(out["tooltip"], str)
            or not isinstance(out["class"], list) or not all(isinstance(c, str) for c in out["class"])):
        out_errors.append(f"❌ {label}: output is not {{text, tooltip, class: [...]}}: {stdout!r}.")
        return None
    return out


def expect_module(label, res, text, classes, out_errors):
    """The module shows TEXT with CLASSES; returns the output for further checks, or None."""
    out = module_output(label, res, out_errors)
    if out is None:
        return None
    if out == HIDDEN:
        out_errors.append(f"❌ {label}: printed nothing, which hides the module; expected {text!r}.")
        return None
    if out["text"] != text or out["class"] != classes:
        out_errors.append(f"❌ {label}: shows {out['text']!r} with class {out['class']!r}, "
                          f"expected {text!r} with {classes!r}.")
    return out


def expect_hidden(label, res, out_errors):
    out = module_output(label, res, out_errors)
    if out is not None and out != HIDDEN:
        out_errors.append(f"❌ {label}: shows {out!r}, expected nothing (module hidden).")


# -- waybar-io-pressure -----------------------------------------------------

def psi_content(some_avg10="0.00", full_avg10="0.00"):
    """The two lines of /proc/pressure/io in the kernel's format."""
    return (f"some avg10={some_avg10} avg60=0.72 avg300=0.36 total=12186311315\n"
            f"full avg10={full_avg10} avg60=0.50 avg300=0.20 total=11073845828\n")


def io_root(workdir, content):
    root = tempfile.mkdtemp(dir=workdir)
    if content is not None:
        write_file(os.path.join(root, "proc/pressure/io"), content)
    return root


def io_run(root, args=("--warm", "20", "--hot", "50"), env=None):
    return run_helper(IO_PRESSURE, list(args), dict(env or {}, DITANA_PROC_ROOT=root))


def check_io_thresholds(workdir, out_errors):
    """The tint starts at WARM, climbs to warm-5 just below HOT, and turns red at HOT.

    The thresholds apply to the rounded percentage that is shown, so 19.50 is
    already WARM and 49.50 already HOT.
    """
    cases = [
        ("19.49", "19%", []),
        ("19.50", "20%", ["warm", "warm-1"]),
        ("35.00", "35%", ["warm", "warm-3"]),     # 1 + 15 * 5 / 30
        ("49.49", "49%", ["warm", "warm-5"]),
        ("49.50", "50%", ["hot"]),
        ("100.00", "100%", ["hot"]),
    ]
    for avg10, text, classes in cases:
        expect_module(f"waybar-io-pressure at some avg10={avg10}",
                      io_run(io_root(workdir, psi_content(avg10))), text, classes, out_errors)


def check_io_rounding(workdir, out_errors):
    """some avg10 is rounded half up to a whole percent, from its two decimals."""
    cases = [("19.49", "19%"), ("19.50", "20%"), ("0.00", "0%"), ("0.49", "0%"), ("0.50", "1%"),
             ("7.05", "7%"), ("99.50", "100%")]
    for avg10, text in cases:
        out = module_output(f"waybar-io-pressure rounding {avg10}",
                            io_run(io_root(workdir, psi_content(avg10)), ("--warm", "200", "--hot", "300")),
                            out_errors)
        if out not in (None, HIDDEN) and out["text"] != text:
            out_errors.append(f"❌ waybar-io-pressure shows some avg10={avg10} as {out['text']!r}, expected {text!r}.")


def check_io_tooltip(workdir, out_errors):
    """The tooltip shows all six averages as the kernel gives them, what the value means, its source, and the thresholds.

    The label in the bar says "IO wait", which a reader may take for the iowait
    share that top shows as "wa", a different measure; the tooltip names the
    kernel interface the value comes from, whose documentation explains the
    "some" and "full" rows.
    """
    out = expect_module("waybar-io-pressure tooltip", io_run(io_root(workdir, psi_content("0.01", "0.00"))),
                        "0%", [], out_errors)
    if out is None:
        return
    lines = out["tooltip"].split("\n")
    expected = [(0, "some  0.01 %  0.72 %  0.36 %   (10 s / 60 s / 5 min)"),
                (1, "full  0.00 %  0.50 %  0.20 %"),
                (len(lines) - 1, "tint from 20 %, red from 50 %")]
    for index, line in expected:
        if len(lines) < 3 or lines[index] != line:
            out_errors.append(f"❌ waybar-io-pressure tooltip {lines!r} lacks line {index} {line!r}.")
            break
    if "at least one task waited for I/O" not in out["tooltip"]:
        out_errors.append(f"❌ waybar-io-pressure tooltip does not say what the value means: {out['tooltip']!r}.")
    if "Source: pressure stall information (PSI) in /proc/pressure/io" not in lines:
        out_errors.append(f"❌ waybar-io-pressure tooltip does not name its source: {out['tooltip']!r}.")


def check_io_hidden(workdir, out_errors):
    """Without usable pressure stall information, the helper prints nothing and the module is hidden.

    A kernel built without PSI, or booted with psi=0, has no /proc/pressure. The
    directory in place of the file makes read() fail, which is what a file that
    cannot be read does.
    """
    unreadable = io_root(workdir, None)
    os.makedirs(os.path.join(unreadable, "proc/pressure/io"))
    cases = [
        ("no PSI", io_root(workdir, None)),
        ("unreadable", unreadable),
        ("empty", io_root(workdir, "")),
        ("garbage", io_root(workdir, "garbage\n")),
        ("no full line", io_root(workdir, psi_content().split("\n")[0] + "\n")),
        ("decimal comma", io_root(workdir, psi_content("19,24"))),
        ("one decimal", io_root(workdir, psi_content("19.2"))),
    ]
    for label, root in cases:
        expect_hidden(f"waybar-io-pressure, {label}", io_run(root), out_errors)


def check_io_reads_once(workdir, out_errors):
    """/proc/pressure/io is opened once per call.

    Every read makes the kernel collect the stall times of all CPUs. The file is
    a FIFO here that serves one reader: a second open blocks until the timeout.
    """
    root = io_root(workdir, None)
    fifo = os.path.join(root, "proc/pressure/io")
    make_fifo(fifo)
    serve_once(fifo, psi_content("21.00"))
    try:
        expect_module("waybar-io-pressure reading the file once", io_run(root), "21%", ["warm", "warm-1"], out_errors)
    finally:
        release_fifo(fifo)


def check_io_arguments(workdir, out_errors):
    """A wrong argument ends with the usage and exit status 2.

    The thresholds must be whole numbers with WARM below HOT. The checks run on
    a machine that has something to show, so that the exit status is not
    mistaken for a hidden module.
    """
    root = io_root(workdir, psi_content())
    bad = [
        ["--warm"],
        ["--hot"],
        ["--warm", ""],
        ["--warm", "x", "--hot", "70"],
        ["--warm", "6.5", "--hot", "70"],
        ["--warm", "6,5", "--hot", "70"],
        ["--warm", "-5", "--hot", "70"],
        ["--warm", "70", "--hot", "65"],
        ["--warm", "70", "--hot", "70"],
        ["--warm", "90"],                      # beyond the default HOT
        ["--cold", "5"],
        ["65", "70"],
        ["--warm", "65", "--hot", "70", "extra"],
    ]
    for args in bad:
        res = io_run(root, args)
        if res is None or res.returncode != 2 or res.stdout or b"usage:" not in res.stderr:
            out_errors.append(f"❌ waybar-io-pressure {args!r}: expected the usage and exit status 2, got "
                              f"{None if res is None else (res.returncode, res.stdout, res.stderr)!r}.")
    if module_output("waybar-io-pressure without arguments", io_run(root, []), out_errors) in (None, HIDDEN):
        out_errors.append("❌ waybar-io-pressure without arguments does not show the module with its default thresholds.")


def german_locales():
    """The German locales installed here, as {character set: locale name}.

    `locale charmap` names the character set a locale really uses; for a locale
    that is not installed it complains on stderr and falls back to ASCII.
    """
    found = {}
    for name in ("de_DE.UTF-8", "de_DE.ISO-8859-1", "de_DE", "de_DE@euro"):
        try:
            res = subprocess.run(["locale", "charmap"], env=dict(os.environ, LC_ALL=name),
                                 capture_output=True, text=True)
        except FileNotFoundError:
            return {}
        charmap = res.stdout.strip()
        if res.returncode == 0 and not res.stderr and charmap in ("UTF-8", "ISO-8859-1", "ISO-8859-15"):
            found.setdefault(charmap, name)
    return found


def check_io_locale(workdir, out_errors):
    """A German locale does not change the output.

    In a German locale the decimal separator is a comma: bash's printf %.1f then
    rejects "19.24", prints 19,0 and exits with 1, which hides the module. The
    helper uses integer arithmetic only; this pins that down in every German
    locale installed here.
    """
    wanted = german_locales()
    if not wanted:
        skip("german-locale", "No German locale here: skipping the locale checks of waybar-io-pressure.", out_errors)
        return
    root = io_root(workdir, psi_content("29.72"))
    reference = io_run(root, env={"LC_ALL": "C"})
    if module_output("waybar-io-pressure in the C locale", reference, out_errors) in (None, HIDDEN):
        return
    for locale_name in wanted.values():
        res = io_run(root, env={"LC_ALL": locale_name})
        if res is None or res.returncode != 0 or res.stdout != reference.stdout:
            out_errors.append(f"❌ waybar-io-pressure with LC_ALL={locale_name} printed "
                              f"{None if res is None else (res.returncode, res.stdout)!r}, "
                              f"in the C locale {reference.stdout!r}.")


def check_io_locale_arguments(workdir, out_errors):
    """A German locale does not let a character that is no ASCII digit through as a threshold.

    In a German locale the range [0-9] of a bash regular expression also matches
    characters such as ², while the arithmetic that follows accepts only ASCII
    digits. Its error does not stop the script: the threshold kept its default
    and the module was shown, where a wrong argument must end in the usage.
    Each argument is passed in the character set of the locale under test, as a
    shell running in it would pass it.
    """
    wanted = german_locales()
    if not wanted:
        skip("german-locale", "No German locale here: skipping the locale checks of the arguments of "
             "waybar-io-pressure.", out_errors)
        return
    root = io_root(workdir, psi_content())
    for charmap, locale_name in wanted.items():
        for args in (["--warm", "²"], ["--hot", "7²"]):
            res = io_run(root, [a.encode(charmap) for a in args], {"LC_ALL": locale_name})
            if res is None or res.returncode != 2 or res.stdout or b"usage:" not in res.stderr:
                out_errors.append(f"❌ waybar-io-pressure {args!r} with LC_ALL={locale_name}: expected the usage "
                                  f"and exit status 2, got "
                                  f"{None if res is None else (res.returncode, res.stdout, res.stderr)!r}.")


def check_waybar_helpers(out_errors):
    with tempfile.TemporaryDirectory() as workdir:
        check_io_thresholds(workdir, out_errors)
        check_io_rounding(workdir, out_errors)
        check_io_tooltip(workdir, out_errors)
        check_io_hidden(workdir, out_errors)
        check_io_reads_once(workdir, out_errors)
        check_io_arguments(workdir, out_errors)
        check_io_locale(workdir, out_errors)
        check_io_locale_arguments(workdir, out_errors)


print("🔍 Checking the waybar helper for I/O pressure...")
helper_errors = []
check_waybar_helpers(helper_errors)
for line in helper_errors:
    print(line)
if helper_errors:
    errors = True

# ---------------------------------------------------------------------------
# The waybar module responsible for niri's workspaces and its associated
# rename dialog.
#
# waybar-niri-workspaces runs the way waybar runs a custom module and reads
# the event stream from a stand-in representing niri's socket, which mimics
# niri's behaviour. Every line it produces must comply with waybar's contract
# for a custom module, which module_output above checks. rename-niri-workspace
# runs with stand-ins for niri and rofi on a PATH containing only those,
# python3, and sh, guaranteeing that no check can rename a workspace or open a
# dialog on the machine where it runs.
# ---------------------------------------------------------------------------

NIRI_WORKSPACES = '/usr/lib/ditana/waybar-niri-workspaces'
RENAME_WORKSPACE = '/usr/lib/ditana/rename-niri-workspace'
WORKSPACES_MODULE = 'custom/workspaces'
RENAME_HINT = "An empty name removes the name."
RENAME_KEEP_HINT = "An empty field keeps the name."

# The duration a check waits for a line that the helper must not print. A line
# printed by mistake follows its event within milliseconds.
QUIET_PERIOD = 0.3

TIMED_OUT = "timed out"


def niri_workspace(workspace_id, idx, output="DP-1", name=None, active=False, focused=False, urgent=False):
    """A workspace as niri reports it."""
    return {"id": workspace_id, "idx": idx, "name": name, "output": output, "is_urgent": urgent,
            "is_active": active, "is_focused": focused, "active_window_id": None}


def niri_window(window_id, workspace_id, app_id="kitty", title="", column=1, row=1, floating=False):
    """A window as niri reports it; COLUMN and ROW are its place in the scrolling layout, which a floating window lacks."""
    return {"id": window_id, "title": title, "app_id": app_id, "pid": 1000 + window_id,
            "workspace_id": workspace_id, "is_focused": False, "is_floating": floating, "is_urgent": False,
            "layout": {"pos_in_scrolling_layout": None if floating else [column, row],
                       "tile_size": [960.0, 1080.0], "window_size": [960, 1080],
                       "tile_pos_in_workspace_view": None, "window_offset_in_tile": [0.0, 0.0]},
            "focus_timestamp": None}


def two_outputs(active=3, focus="DP-1"):
    """Two outputs as niri reports them with empty-workspace-above-first, which HDMI-A-1 turns off: (workspaces, windows).

    DP-1 holds eight workspaces, empty at the top and at the bottom with a
    window on each of 2 to 7, and ACTIVE is its active one. HDMI-A-1 holds
    three, a window on 1 and on 2 and the empty one at the bottom, and 1 is
    active. A window on the first workspace of HDMI-A-1 means that niri keeps
    no empty workspace above it there, which is legitimate: since 25.11, niri
    takes the option per output, and HDMI-A-1 turns it off with
    output "HDMI-A-1" { layout { empty-workspace-above-first false; }; }.
    FOCUS names the output whose active workspace has the focus. The
    workspace with the index n has the id 10 + n on DP-1 and 20 + n on
    HDMI-A-1, and its window the id 100 + n or 200 + n.
    """
    workspaces = [niri_workspace(10 + idx, idx, "DP-1", active=idx == active,
                                 focused=focus == "DP-1" and idx == active) for idx in range(1, 9)]
    workspaces += [niri_workspace(20 + idx, idx, "HDMI-A-1", active=idx == 1,
                                  focused=focus == "HDMI-A-1" and idx == 1) for idx in range(1, 4)]
    windows = [niri_window(100 + idx, 10 + idx, title=f"window {idx}") for idx in range(2, 8)]
    windows += [niri_window(200 + idx, 20 + idx, title=f"window {idx}") for idx in range(1, 3)]
    return workspaces, windows


def by_id(entries, entry_id):
    return next(entry for entry in entries if entry["id"] == entry_id)


def initial_events(workspaces, windows):
    """The two events with which niri's event stream begins, among others."""
    return [{"WorkspacesChanged": {"workspaces": workspaces}}, {"WindowsChanged": {"windows": windows}}]


class NiriStub:
    """A stand-in for niri's socket, which answers the way niri does.

    niri answers the request "EventStream" with {"Ok":"Handled"} and then
    sends one event per line. A check takes the connections of the helper
    one by one and decides what goes back on each.
    """

    def __init__(self, workdir):
        self.path = os.path.join(tempfile.mkdtemp(prefix="n", dir=workdir), "s")
        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server.bind(self.path)
        self.server.listen(16)
        self.server.settimeout(HELPER_TIMEOUT)

    def accept(self):
        """The next connection and the request read from it, or (None, None) if none came in time."""
        try:
            connection, _ = self.server.accept()
        except OSError:
            return None, None
        connection.settimeout(HELPER_TIMEOUT)
        request = b""
        try:
            while not request.endswith(b"\n"):
                chunk = connection.recv(4096)
                if not chunk:
                    break
                request += chunk
        except OSError:
            pass
        return connection, request

    def close(self):
        self.server.close()


def niri_send(connection, *messages):
    """Sends each message as a line of JSON, as niri does; bytes go out as they are."""
    connection.sendall(b"".join((m if isinstance(m, bytes) else json.dumps(m).encode()) + b"\n" for m in messages))


class WorkspacesHelper:
    """waybar-niri-workspaces, started as waybar starts a custom module, with a pipe for its output.

    NIRI_SOCKET and WAYBAR_OUTPUT_NAME come from ENV alone, never from the
    session that runs the checks. COMMAND replaces the command line of the
    helper.
    """

    def __init__(self, env, command=None):
        environment = {k: v for k, v in os.environ.items() if k not in ("NIRI_SOCKET", "WAYBAR_OUTPUT_NAME")}
        environment.update(env)
        self.process = subprocess.Popen(command or [repo_path(NIRI_WORKSPACES)], stdin=subprocess.DEVNULL,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment)
        self.pending = b""

    def line(self, timeout=HELPER_TIMEOUT):
        """The next line the helper prints; None once its output has ended, TIMED_OUT if none comes in time."""
        deadline = time.monotonic() + timeout
        fd = self.process.stdout.fileno()
        while b"\n" not in self.pending:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([fd], [], [], remaining)[0]:
                return TIMED_OUT
            chunk = os.read(fd, 1 << 16)
            if not chunk:
                return None
            self.pending += chunk
        line, self.pending = self.pending.split(b"\n", 1)
        return line + b"\n"

    def remaining_lines(self):
        """The lines the helper printed and no check has read yet, once it has ended."""
        return (self.pending + self.process.stdout.read()).splitlines(keepends=True)

    def close_pipe(self):
        """Closes the end of the pipe that waybar reads, as waybar does when it lets go of the module."""
        self.process.stdout.close()

    def ended(self):
        """(exit status, stderr) once the helper has ended, or None if it still runs after HELPER_TIMEOUT."""
        try:
            self.process.wait(HELPER_TIMEOUT)
        except subprocess.TimeoutExpired:
            return None
        return self.process.returncode, self.process.stderr.read()

    def stop(self):
        if self.process.poll() is None:
            self.process.kill()
        self.process.wait()
        self.process.stdout.close()
        self.process.stderr.close()


def workspaces_output(label, line, out_errors):
    r"""What waybar makes of LINE, a line the helper printed; None after reporting a missing or broken line.

    Like waybar 0.15, it turns every \x of the line into \u00 before it
    parses the JSON (replaceHexadecimalEscape in include/util/json.hpp).
    """
    if line is TIMED_OUT:
        out_errors.append(f"❌ {label}: printed no line within {HELPER_TIMEOUT} s.")
        return None
    if line is None:
        out_errors.append(f"❌ {label}: ended without printing a line.")
        return None
    line = line.replace(b"\\x", b"\\u00")
    return module_output(label, subprocess.CompletedProcess([], 0, line, b""), out_errors)


def workspaces_show(workdir, label, events, out_errors, output=None):
    """The first line the helper prints once the stand-in for niri has sent EVENTS, parsed; None after a failure.

    OUTPUT goes into WAYBAR_OUTPUT_NAME; None leaves the variable unset.
    """
    stub = NiriStub(workdir)
    env = {"NIRI_SOCKET": stub.path}
    if output is not None:
        env["WAYBAR_OUTPUT_NAME"] = output
    helper = WorkspacesHelper(env)
    try:
        connection, request = stub.accept()
        if connection is None:
            out_errors.append(f"❌ {label}: the helper did not connect to niri within {HELPER_TIMEOUT} s.")
            return None
        with connection:
            if request != b'"EventStream"\n':
                out_errors.append(f"❌ {label}: the helper asked niri for {request!r} instead of the event stream.")
                return None
            niri_send(connection, {"Ok": "Handled"}, *events)
            return workspaces_output(label, helper.line(), out_errors)
    finally:
        helper.stop()
        stub.close()


def workspace_text(text):
    """TEXT without the markup of the highlight that check_workspaces_highlight pins down, or TEXT itself if it has none.

    Every other check that compares the text compares what the highlight
    encloses, so that a change to its markup fails that one check alone. A
    name reaches the text escaped, so every "<" in it starts a tag, and the
    tags go whatever their form; the one space on each side goes as well. A
    highlight around nothing stays as it is: only an empty text hides the
    module.
    """
    plain = re.sub(r"<[^>]*>", "", text)
    inside = plain.removeprefix(" ").removesuffix(" ")
    return inside if plain != text and inside else text


def expect_workspaces(label, out, text, classes, out_errors):
    """The module shows TEXT with CLASSES, once workspace_text has taken the highlight off."""
    if out is None:
        return
    shown = workspace_text(out["text"])
    if shown != text or out["class"] != classes:
        out_errors.append(f"❌ {label}: shows {shown!r} with class {out['class']!r}, "
                          f"expected {text!r} with {classes!r}.")


def check_workspaces_numbers(workdir, out_errors):
    """The text is the index of the active workspace of the bar's output and the index of the last workspace in use there.

    The index is the one that `niri msg action focus-workspace 3` addresses.
    A workspace is in use while it holds a window or carries a name, and the
    active one always counts. niri keeps an empty workspace at the bottom of
    each output, and with empty-workspace-above-first another one at the
    top, which then has the index 1 and so lies within the number. The one
    at the bottom counts only while it is active; otherwise every bar would
    count a workspace that holds nothing. A name follows the numbers after a
    middle dot.
    """
    _, windows = two_outputs()
    named_empty, _ = two_outputs()
    by_id(named_empty, 18)["name"] = "Notes"
    named_empty.append(niri_workspace(19, 9, "DP-1"))
    named_active, _ = two_outputs()
    by_id(named_active, 13)["name"] = "Projekt"
    cases = [
        ("in the typical case", two_outputs(3)[0], "3/7"),
        ("with the empty workspace at the top active", two_outputs(1)[0], "1/7"),
        ("with the empty workspace at the bottom active", two_outputs(8)[0], "8/8"),
        ("with an empty workspace that carries a name", named_empty, "3/8"),
        ("with a name on the active workspace", named_active, "3/7 · Projekt"),
    ]
    for label, workspaces, text in cases:
        label = f"waybar-niri-workspaces {label}"
        out = workspaces_show(workdir, label, initial_events(workspaces, windows), out_errors, output="DP-1")
        expect_workspaces(label, out, text, ["focused"], out_errors)


def check_workspaces_outputs(workdir, out_errors):
    """Each bar shows the output it sits on; without a usable WAYBAR_OUTPUT_NAME, the output that has the focus.

    waybar sets WAYBAR_OUTPUT_NAME for the exec of a custom module. A name
    that matches no workspace, say an output that niri has not yet given
    workspaces to, is treated like a missing one.
    """
    cases = [
        ("on DP-1", "DP-1", "DP-1", "3/7", ["focused"]),
        ("on HDMI-A-1", "HDMI-A-1", "DP-1", "1/2", []),
        ("without WAYBAR_OUTPUT_NAME, DP-1 focused", None, "DP-1", "3/7", ["focused"]),
        ("without WAYBAR_OUTPUT_NAME, HDMI-A-1 focused", None, "HDMI-A-1", "1/2", ["focused"]),
        ("on an output that has no workspaces, HDMI-A-1 focused", "DP-9", "HDMI-A-1", "1/2", ["focused"]),
    ]
    for label, output, focus, text, classes in cases:
        label = f"waybar-niri-workspaces {label}"
        out = workspaces_show(workdir, label, initial_events(*two_outputs(focus=focus)), out_errors, output=output)
        expect_workspaces(label, out, text, classes, out_errors)


def check_workspaces_names(workdir, out_errors):
    """A name is shortened to 24 characters, the last of them an ellipsis, and then escaped for Pango.

    waybar renders the text as Pango markup, where a "<" or "&" from a name
    would break the label or turn into markup. The name is shortened before
    it is escaped, so that the cut neither splits an entity nor counts its
    characters.
    """
    cases = [
        ("Quartalsabschluss Q3 '26", "Quartalsabschluss Q3 '26"),
        ("Quartalsabschluss Q3 '26!", "Quartalsabschluss Q3 '2…"),
        ("Tom & Jerry <Planung> 2026", "Tom &amp; Jerry &lt;Planung&gt; 2…"),
    ]
    for name, shown in cases:
        workspaces, windows = two_outputs()
        by_id(workspaces, 13)["name"] = name
        label = f"waybar-niri-workspaces with the name {name!r}"
        out = workspaces_show(workdir, label, initial_events(workspaces, windows), out_errors, output="DP-1")
        expect_workspaces(label, out, f"3/7 · {shown}", ["focused"], out_errors)


def check_workspaces_highlight(workdir, out_errors):
    """The text stands dark grey in bold on Ditana's orange, with a space inside before and after it; the "?" of a failed connection does not.

    #ffbb00 is the colour of niri's focus ring on the active monitor in the
    skel config.kdl, and the Ditana logo carries it too. The span puts the
    orange behind the text alone, so that it forms a field within the
    module's box, which stays grey and turns red with the class urgent; the
    spaces let the orange enclose the text instead of ending at its first
    and last character. Every bar highlights the active workspace of its own
    output, whether that output has the focus or not, and the name is part
    of the highlighted text. The "?" names no workspace and stays on the
    grey. The other checks compare the text without the markup of the
    highlight, so that a change to its markup fails this check alone. The
    empty text that hides the module outside niri stays empty, which
    check_workspaces_outside_niri pins down: waybar would show a span around
    nothing.
    """
    highlighted = '<span background="#ffbb00" foreground="#262626" weight="bold"> {} </span>'
    _, windows = two_outputs()
    named, _ = two_outputs()
    by_id(named, 13)["name"] = "Tom & Jerry"
    urgent, _ = two_outputs()
    by_id(urgent, 22)["is_urgent"] = True
    cases = [
        ("on the output with the focus", two_outputs()[0], "DP-1", "3/7"),
        ("with a name", named, "DP-1", "3/7 · Tom &amp; Jerry"),
        ("without the focus, with an urgent workspace", urgent, "HDMI-A-1", "1/2"),
    ]
    for label, workspaces, output, text in cases:
        label = f"waybar-niri-workspaces highlighting the active workspace {label}"
        out = workspaces_show(workdir, label, initial_events(workspaces, windows), out_errors, output=output)
        expected = highlighted.format(text)
        if out is not None and out["text"] != expected:
            out_errors.append(f"❌ {label}: shows {out['text']!r}, expected {expected!r}.")

    label = "waybar-niri-workspaces without a connection to niri"
    helper = WorkspacesHelper({"NIRI_SOCKET": os.path.join(workdir, "no-niri-here"), "WAYBAR_OUTPUT_NAME": "DP-1"})
    try:
        out = workspaces_output(label, helper.line(), out_errors)
        if out is not None and out["text"] != "?":
            out_errors.append(f"❌ {label}: shows {out['text']!r}, expected a \"?\" without the highlight.")
    finally:
        helper.stop()


def check_workspaces_backslashes(workdir, out_errors):
    r"""A backslash in a name or a window title reaches the bar as it is, also with an x after it.

    waybar 0.15 turns every \x of a line into \u00 before it parses the JSON,
    which made the title C:\xampp\htdocs show as C:\u00ampp\htdocs and the
    name \x41 as \u0041. workspaces_output does the same as waybar, so the
    check sees what the bar shows.
    """
    workspaces, windows = two_outputs()
    by_id(workspaces, 13)["name"] = "\\x41 \\\\x"
    by_id(windows, 103)["title"] = "C:\\xampp\\htdocs"
    label = "waybar-niri-workspaces with backslashes in a name and a window title"
    out = workspaces_show(workdir, label, initial_events(workspaces, windows), out_errors, output="DP-1")
    expect_workspaces(label, out, "3/7 · \\x41 \\\\x", ["focused"], out_errors)
    if out is not None and "C:\\xampp\\htdocs" not in out["tooltip"]:
        out_errors.append(f"❌ {label}: the tooltip does not show the title 'C:\\xampp\\htdocs': {out['tooltip']!r}.")


def check_workspaces_tooltip(workdir, out_errors):
    """The tooltip lists, for every output, the workspaces that hold windows or carry a name and the active one, with their windows.

    The bar's own output comes first. Each workspace shows its index and
    name, and the active one of each output is marked. Below a workspace
    come its windows in niri's column order, within a column from top to
    bottom, and floating windows last, whatever the order in which niri
    lists them. Each window shows its app ID, of a reverse DNS ID such as
    org.gnome.Nautilus only the last part, shortened to 16 characters, and
    its title shortened to 60. The ID of a Chrome web app contains dots
    without being a reverse DNS ID and stays whole. <tt> keeps the columns
    aligned, and everything from niri is escaped. The bar sits on HDMI-A-1
    here, which sorts after the other two outputs.
    """
    workspaces = [
        niri_workspace(11, 1, "DP-1", active=True, focused=True),
        niri_workspace(12, 2, "DP-1"),
        niri_workspace(21, 1, "HDMI-A-1"),
        niri_workspace(22, 2, "HDMI-A-1", active=True),
        niri_workspace(23, 3, "HDMI-A-1", name="Später"),
        niri_workspace(24, 4, "HDMI-A-1"),
        niri_workspace(31, 1, "DP-2", name="Mail & <Chat>", active=True),
        niri_workspace(32, 2, "DP-2"),
    ]
    long_title = "A window title that goes on and on, long past the width of any tooltip"
    windows = [
        niri_window(224, 22, "com.example.AVeryLongApplicationName", long_title, floating=True),
        niri_window(221, 22, "org.gnome.Nautilus", "Home", column=2, row=1),
        niri_window(225, 22, "chrome-web.whatsapp.com__-Default", "WhatsApp", column=3),
        niri_window(222, 22, "kitty", "~/src & <tests>", column=1),
        niri_window(223, 22, "org.gnome.Nautilus", "Downloads", column=2, row=2),
        niri_window(311, 31, "thunderbird", "Inbox"),
    ]
    expected = "\n".join([
        "<tt>HDMI-A-1",
        "▸ 2",
        f"    {'kitty':16}  ~/src &amp; &lt;tests&gt;",
        f"    {'Nautilus':16}  Home",
        f"    {'Nautilus':16}  Downloads",
        f"    {'chrome-web.what…':16}  WhatsApp",
        f"    {'AVeryLongApplic…':16}  {long_title[:59]}…",
        "  3 · Später",
        "",
        "DP-1",
        "▸ 1",
        "",
        "DP-2",
        "▸ 1 · Mail &amp; &lt;Chat&gt;",
        f"    {'thunderbird':16}  Inbox</tt>",
    ])
    label = "waybar-niri-workspaces tooltip"
    out = workspaces_show(workdir, label, initial_events(workspaces, windows), out_errors, output="HDMI-A-1")
    expect_workspaces(label, out, "2/3", [], out_errors)
    if out is not None and out["tooltip"] != expected:
        out_errors.append(f"❌ {label}:\n{out['tooltip']}\nexpected:\n{expected}")


def check_workspaces_classes(workdir, out_errors):
    """The class "focused" marks the bar whose output has the focus, "urgent" one with an urgent workspace on its output.

    An urgent workspace on another output does not concern this bar; the bar
    on that output shows it.
    """
    cases = [
        ("on the output with the focus", "DP-1", None, ["focused"]),
        ("on an output without the focus", "HDMI-A-1", None, []),
        ("with an urgent workspace on its output", "DP-1", 15, ["focused", "urgent"]),
        ("with an urgent workspace on another output", "HDMI-A-1", 15, []),
        ("without the focus, with an urgent workspace on its output", "HDMI-A-1", 22, ["urgent"]),
    ]
    for label, output, urgent, classes in cases:
        workspaces, windows = two_outputs()
        if urgent is not None:
            by_id(workspaces, urgent)["is_urgent"] = True
        label = f"waybar-niri-workspaces {label}"
        out = workspaces_show(workdir, label, initial_events(workspaces, windows), out_errors, output=output)
        expect_workspaces(label, out, "3/7" if output == "DP-1" else "1/2", classes, out_errors)


def check_workspaces_unknown_events(workdir, out_errors):
    """Events the helper does not know are skipped, in the first burst of the stream as well.

    niri-git has been sending TouchpadToggled since October 2026, and no
    released version of niri-ipc knows it, so a module that parses the
    stream with niri-ipc stops there. The stand-in puts that event, one from
    a niri yet to come, an event that is no object and a line that is no
    JSON between the workspaces and the windows.
    """
    workspaces, windows = two_outputs()
    first, last = initial_events(workspaces, windows)
    events = [first, {"TouchpadToggled": {"on": True}}, {"SomethingFromTheFuture": {"detail": [1, 2]}},
              "UnitEvent", [1, 2], b"no JSON at all", last, {"KeyboardLayoutsChanged": {}}]
    label = "waybar-niri-workspaces with unknown events in the first burst"
    expect_workspaces(label, workspaces_show(workdir, label, events, out_errors, output="DP-1"), "3/7", ["focused"],
                      out_errors)


def check_workspaces_waits_for_windows(workdir, out_errors):
    """Nothing is printed before niri has sent the list of windows.

    The total depends on the workspaces that hold windows: without them the
    typical case would show 3/3 instead of 3/7. A window that opens before
    the list arrives does not make the list known.
    """
    workspaces, windows = two_outputs()
    label = "waybar-niri-workspaces before the windows are known"
    stub = NiriStub(workdir)
    helper = WorkspacesHelper({"NIRI_SOCKET": stub.path, "WAYBAR_OUTPUT_NAME": "DP-1"})
    try:
        connection, _ = stub.accept()
        if connection is None:
            out_errors.append(f"❌ {label}: the helper did not connect to niri within {HELPER_TIMEOUT} s.")
            return
        with connection:
            first, last = initial_events(workspaces, windows)
            niri_send(connection, {"Ok": "Handled"}, first, {"WindowOpenedOrChanged": {"window": windows[0]}})
            early = helper.line(QUIET_PERIOD)
            if early is not TIMED_OUT:
                out_errors.append(f"❌ {label}: printed {early!r}.")
                return
            niri_send(connection, last)
            label = "waybar-niri-workspaces once the windows are known"
            expect_workspaces(label, workspaces_output(label, helper.line(), out_errors), "3/7", ["focused"],
                              out_errors)
    finally:
        helper.stop()
        stub.close()


def check_workspaces_events(workdir, out_errors):
    """Later events change single entries as niri-ipc's EventStreamState does, and only a change prints a line.

    WorkspaceActivated makes a workspace the active one of its output and,
    with "focused", the focused one of all outputs; windows that open and
    close change the workspaces in use; WorkspacesChanged and WindowsChanged
    replace the whole lists. A window that moves to another column sends
    WindowLayoutsChanged alone, and the tooltip follows it.
    WorkspaceActivated and WorkspaceUrgencyChanged naming a workspace that
    is not known change nothing, and neither do WindowClosed and
    WindowLayoutsChanged naming a window that is not known, where
    EventStreamState would panic on WorkspaceActivated, WindowClosed and
    WindowLayoutsChanged. Along with them, the check sends
    WorkspaceActiveWindowChanged naming a workspace that is not known, where
    EventStreamState would panic as well, and WindowUrgencyChanged naming a
    window that is not known; the module shows neither active_window_id nor
    the urgency of a window, so check_workspaces_state_unknown_ids follows
    these two in the helper's State. A step whose events leave the line as
    it is must not print it again, so the last event of each step is the
    one that changes the line; a line printed in between would arrive in
    place of the expected one.
    """
    workspaces, windows = two_outputs()
    replaced, _ = two_outputs(active=5)
    by_id(replaced, 15)["name"] = "Neu"
    moved = niri_window(103, 13, title="window 3", column=3)["layout"]
    steps = [
        ([{"WorkspaceActivated": {"id": 15, "focused": True}}], "5/7", ["focused"], None),
        ([{"WindowFocusChanged": {"id": 105}},
          {"WorkspaceActivated": {"id": 99, "focused": True}},
          {"WorkspaceUrgencyChanged": {"id": 99, "urgent": True}},
          {"WorkspaceActiveWindowChanged": {"workspace_id": 99, "active_window_id": 105}},
          {"WindowClosed": {"id": 999}},
          {"WindowUrgencyChanged": {"id": 999, "urgent": True}},
          {"WindowLayoutsChanged": {"changes": [[999, moved]]}},
          {"WindowOpenedOrChanged": {"window": niri_window(108, 18, title="window 8")}}], "5/8", ["focused"], None),
        ([{"WorkspaceActivated": {"id": 21, "focused": True}}], "5/8", [], None),
        ([{"WindowClosed": {"id": 108}}], "5/7", [], None),
        ([{"WorkspaceUrgencyChanged": {"id": 12, "urgent": True}}], "5/7", ["urgent"], None),
        ([{"WindowOpenedOrChanged": {"window": niri_window(109, 13, title="window 9", column=2)}}],
         "5/7", ["urgent"], ("window 3", "window 9")),
        ([{"WindowLayoutsChanged": {"changes": [[103, moved]]}}], "5/7", ["urgent"], ("window 9", "window 3")),
        ([{"WorkspacesChanged": {"workspaces": replaced}}], "5/7 · Neu", ["focused"], None),
        ([{"WindowsChanged": {"windows": []}}], "5/5 · Neu", ["focused"], None),
    ]
    stub = NiriStub(workdir)
    helper = WorkspacesHelper({"NIRI_SOCKET": stub.path, "WAYBAR_OUTPUT_NAME": "DP-1"})
    try:
        connection, _ = stub.accept()
        if connection is None:
            out_errors.append(f"❌ waybar-niri-workspaces did not connect to niri within {HELPER_TIMEOUT} s.")
            return
        with connection:
            niri_send(connection, {"Ok": "Handled"}, *initial_events(workspaces, windows))
            label = "waybar-niri-workspaces at the start of the event stream"
            out = workspaces_output(label, helper.line(), out_errors)
            expect_workspaces(label, out, "3/7", ["focused"], out_errors)
            for events, text, classes, order in steps:
                niri_send(connection, *events)
                label = f"waybar-niri-workspaces after {', '.join(next(iter(e)) for e in events)}"
                out = workspaces_output(label, helper.line(), out_errors)
                if out is None:
                    return
                expect_workspaces(label, out, text, classes, out_errors)
                if order and not 0 <= out["tooltip"].find(order[0]) < out["tooltip"].find(order[1]):
                    out_errors.append(f"❌ {label}: the tooltip does not list {order[0]!r} before {order[1]!r}: "
                                      f"{out['tooltip']!r}.")
            extra = helper.line(QUIET_PERIOD)
            if extra is not TIMED_OUT:
                out_errors.append(f"❌ waybar-niri-workspaces printed {extra!r} without a change.")
    finally:
        helper.stop()
        stub.close()


# Loads the helper as a module, applies the events received via stdin as a JSON
# list against its State, and prints the workspaces and windows of the State as
# a JSON line immediately after each event.
STATE_PROBE = r'''
import importlib.machinery, importlib.util, json, sys
loader = importlib.machinery.SourceFileLoader("waybar_niri_workspaces", sys.argv[1])
helper = importlib.util.module_from_spec(importlib.util.spec_from_loader(loader.name, loader))
loader.exec_module(helper)
state = helper.State()
for event in json.load(sys.stdin):
    state.apply(event)
    print(json.dumps({"workspaces": state.workspaces, "windows": state.windows}))
'''


def state_after_each(label, events, out_errors):
    """The helper's State after each of EVENTS, as STATE_PROBE prints it; None after reporting a failure.

    JSON turns the ids that key the workspaces and the windows into strings.
    """
    try:
        res = subprocess.run([sys.executable, "-I", "-B", "-c", STATE_PROBE, repo_path(NIRI_WORKSPACES)],
                             input=json.dumps(events), capture_output=True, text=True, timeout=HELPER_TIMEOUT)
    except subprocess.TimeoutExpired:
        out_errors.append(f"❌ {label}: did not finish within {HELPER_TIMEOUT} s.")
        return None
    lines = res.stdout.splitlines()
    try:
        states = [json.loads(line) for line in lines]
    except ValueError:
        states = None
    if res.returncode != 0 or states is None or len(states) != len(events):
        out_errors.append(f"❌ {label}: exit status {res.returncode}, stderr {res.stderr!r}, {len(lines)} lines "
                          f"printed; expected status 0 and a line of JSON for each of the {len(events)} events.")
        return None
    return states


def check_workspaces_window_focus(out_errors):
    """WindowFocusChanged gives the focus to the window it names, and to none without an id; an id that is not known changes nothing.

    niri sends no id once no window has the focus. For an id it does not
    know, EventStreamState takes the focus from every window as well, while
    WindowClosed, WindowUrgencyChanged and WindowLayoutsChanged naming a
    window that is not known change nothing here. The focus of a window does
    not show in the module, so the check applies the events to the helper's
    State and reads the focus from there.
    """
    workspaces, windows = two_outputs()
    by_id(windows, 103)["is_focused"] = True
    steps = [
        ({"WindowFocusChanged": {"id": 105}}, [105]),
        ({"WindowFocusChanged": {"id": 999}}, [105]),
        ({"WindowFocusChanged": {"id": None}}, []),
        ({"WindowFocusChanged": {"id": 999}}, []),
        ({"WindowFocusChanged": {"id": 202}}, [202]),
    ]
    events = initial_events(workspaces, windows) + [event for event, _ in steps]
    expected = [[], [103]] + [focused for _, focused in steps]
    label = "waybar-niri-workspaces following WindowFocusChanged"
    states = state_after_each(label, events, out_errors)
    if states is None:
        return
    got = [sorted(w["id"] for w in (state["windows"] or {}).values() if w.get("is_focused")) for state in states]
    if got != expected:
        out_errors.append(f"❌ {label}: the focused windows went {got!r}; expected {expected!r}.")


def state_changes(before, after):
    """The entries that differ between two States as STATE_PROBE prints them, named like "workspace 15" or "window 105"."""
    changes = []
    for part, noun in (("workspaces", "workspace"), ("windows", "window")):
        old, new = before[part] or {}, after[part] or {}
        changes += [f"{noun} {key}" for key in sorted(set(old) | set(new)) if old.get(key) != new.get(key)]
    return changes


def check_workspaces_state_unknown_ids(out_errors):
    """WorkspaceActiveWindowChanged naming a workspace that is not known and WindowUrgencyChanged naming a window that is not known change nothing.

    The module shows neither active_window_id nor the urgency of a window,
    so check_workspaces_events, which sends both, cannot tell what they do.
    The check applies them to the helper's State, as
    check_workspaces_window_focus does with WindowFocusChanged, and compares
    the State after each event with the one before. Before each of them, an
    event of the same kind names a workspace or a window that is known and
    has to change that one entry: a State that the probe printed without its
    workspaces or its windows would otherwise let the event pass.
    """
    workspaces, windows = two_outputs()
    steps = [
        ({"WorkspaceActiveWindowChanged": {"workspace_id": 15, "active_window_id": 105}}, ["workspace 15"]),
        ({"WorkspaceActiveWindowChanged": {"workspace_id": 99, "active_window_id": 105}}, []),
        ({"WindowUrgencyChanged": {"id": 105, "urgent": True}}, ["window 105"]),
        ({"WindowUrgencyChanged": {"id": 999, "urgent": True}}, []),
    ]
    events = initial_events(workspaces, windows) + [event for event, _ in steps]
    states = state_after_each("waybar-niri-workspaces applying events to its State", events, out_errors)
    if states is None:
        return
    for (event, expected), before, after in zip(steps, states[1:], states[2:]):
        changed = state_changes(before, after)
        if changed != expected:
            out_errors.append(f"❌ waybar-niri-workspaces following {json.dumps(event)}: changed "
                              f"{changed or 'nothing'} in its State; expected {expected or 'nothing'}.")


# Loads the helper as a module, puts a pause() in its place that logs every
# delay and immediately returns, then executes it. The stand-in ends the
# helper once it has paused as many times as the check asks.
RECORDED_PAUSES = r'''
import importlib.machinery, importlib.util, json, sys
path, log, count = sys.argv[1], sys.argv[2], int(sys.argv[3])
loader = importlib.machinery.SourceFileLoader("waybar_niri_workspaces", path)
helper = importlib.util.module_from_spec(importlib.util.spec_from_loader(loader.name, loader))
loader.exec_module(helper)
pauses = []
def pause(seconds):
    pauses.append(seconds)
    with open(log, "w") as f:
        json.dump(pauses, f)
    if len(pauses) == count:
        sys.exit(0)
helper.pause = pause
sys.exit(helper.main())
'''


def workspaces_pauses(workdir, env, count):
    """Runs the helper with a stand-in for its pause() until it has paused COUNT times.

    Returns the delays it asked for, the lines it printed and its exit
    status, or None if it did not get there within HELPER_TIMEOUT.
    """
    log = os.path.join(tempfile.mkdtemp(dir=workdir), "pauses")
    helper = WorkspacesHelper(env, [sys.executable, "-I", "-B", "-c", RECORDED_PAUSES,
                                    repo_path(NIRI_WORKSPACES), log, str(count)])
    try:
        ended = helper.ended()
        if ended is None:
            return None
        lines = [json.loads(line) for line in helper.remaining_lines()]
        with open(log) as f:
            return {"pauses": json.load(f), "lines": lines, "status": ended[0], "stderr": ended[1]}
    except (OSError, ValueError):
        return None
    finally:
        helper.stop()


def check_workspaces_reconnect(workdir, out_errors):
    """After a connection fails or ends, the helper shows "?" and tries again after 1, 2, 4 and then every 8 seconds.

    A connection that niri answered starts the series again at 1 second; an
    answer that refuses the event stream does not count as one. The helper
    runs with a stand-in for its pause(), which records each delay and
    returns at once, so that the check neither waits 15 seconds nor depends
    on how busy the machine is. The stand-in for niri closes connections
    without an answer, refuses one, and answers one with the workspaces and
    windows before it closes it.
    """
    missing = os.path.join(workdir, "no-niri-here")
    run = workspaces_pauses(workdir, {"NIRI_SOCKET": missing, "WAYBAR_OUTPUT_NAME": "DP-1"}, 5)
    label = "waybar-niri-workspaces without a niri to connect to"
    if run is None or run["pauses"] != [1, 2, 4, 8, 8] or run["status"] != 0 or run["stderr"]:
        out_errors.append(f"❌ {label}: expected the delays [1, 2, 4, 8, 8], got {run!r}.")
    elif [(workspace_text(line["text"]), line["class"]) for line in run["lines"]] != [("?", ["error"])] \
            or missing not in run["lines"][0]["tooltip"]:
        out_errors.append(f"❌ {label}: expected one \"?\" of class error that names {missing} in its tooltip, "
                          f"got {run['lines']!r}.")

    script = ["close", "close", "refuse", "close", "close", "answer", "close"]
    stub = NiriStub(workdir)

    def serve():
        for action in script:
            connection, _ = stub.accept()
            if connection is None:
                return
            with connection:
                if action == "refuse":
                    niri_send(connection, {"Err": "the stand-in refuses"})
                elif action == "answer":
                    niri_send(connection, {"Ok": "Handled"}, *initial_events(*two_outputs()))

    server = threading.Thread(target=serve, daemon=True)
    server.start()
    try:
        run = workspaces_pauses(workdir, {"NIRI_SOCKET": stub.path, "WAYBAR_OUTPUT_NAME": "DP-1"}, len(script))
    finally:
        server.join(HELPER_TIMEOUT)
        stub.close()
    label = "waybar-niri-workspaces reconnecting to niri"
    if run is None or run["pauses"] != [1, 2, 4, 8, 8, 1, 2] or run["status"] != 0 or run["stderr"]:
        out_errors.append(f"❌ {label}: expected the delays [1, 2, 4, 8, 8, 1, 2], got {run!r}.")
        return
    shown = [(workspace_text(line["text"]), line["class"]) for line in run["lines"]]
    error = ("?", ["error"])
    if shown != [error, error, error, ("3/7", ["focused"]), error, error]:
        out_errors.append(f"❌ {label}: showed {shown!r}; expected \"?\" for each failure that differs from the "
                          f"one before, and 3/7 while niri answered.")


def expect_quiet_end(label, helper, out_errors):
    """The helper ends with status 0 and nothing on stderr once waybar has closed the pipe."""
    ended = helper.ended()
    if ended is None:
        out_errors.append(f"❌ {label}: still runs {HELPER_TIMEOUT} s after waybar closed the pipe.")
    elif ended != (0, b""):
        out_errors.append(f"❌ {label}: ended with status {ended[0]} and {ended[1]!r} on stderr after waybar closed "
                          f"the pipe; expected status 0 and nothing on stderr.")


def check_workspaces_outside_niri(workdir, out_errors):
    """Without NIRI_SOCKET, the helper prints an empty text once, which hides the module, and keeps running.

    ditana-config sets up waybar alike for niri and Wayfire, so the module is
    in Wayfire's bar as well. waybar 0.15 does not check exec-if for a custom
    module without an interval, so the helper hides the module itself. Were
    it to end, waybar would start it again after restart-interval, every few
    seconds. It ends quietly once waybar closes the pipe.
    """
    label = "waybar-niri-workspaces without NIRI_SOCKET"
    helper = WorkspacesHelper({})
    try:
        out = workspaces_output(label, helper.line(), out_errors)
        if out is not None and out["text"] != "":
            out_errors.append(f"❌ {label}: shows {out['text']!r}, expected an empty text, which hides the module.")
        extra = helper.line(QUIET_PERIOD)
        if extra is not TIMED_OUT:
            out_errors.append(f"❌ {label}: printed {extra!r} after hiding the module, or ended.")
        helper.close_pipe()
        expect_quiet_end(label, helper, out_errors)
    finally:
        helper.stop()


def check_workspaces_closed_pipe(workdir, out_errors):
    """When waybar closes the pipe, the helper ends quietly with status 0, while it follows niri and while it waits to reconnect.

    A write to a closed pipe fails with BrokenPipeError in Python, and an
    exception left unhandled ends the helper with a traceback on stderr,
    which waybar passes on to its log. While the helper follows niri, the
    stand-in sends a change after the pipe is closed, so that the helper has
    a line to print. While it waits to reconnect, nothing it could print
    would differ from the "?" it shows, so only the closed pipe itself can
    end the wait.
    """
    label = "waybar-niri-workspaces following niri"
    stub = NiriStub(workdir)
    helper = WorkspacesHelper({"NIRI_SOCKET": stub.path, "WAYBAR_OUTPUT_NAME": "DP-1"})
    try:
        connection, _ = stub.accept()
        if connection is None:
            out_errors.append(f"❌ {label}: the helper did not connect to niri within {HELPER_TIMEOUT} s.")
        else:
            with connection:
                niri_send(connection, {"Ok": "Handled"}, *initial_events(*two_outputs()))
                workspaces_output(label, helper.line(), out_errors)
                helper.close_pipe()
                try:
                    niri_send(connection, {"WorkspaceActivated": {"id": 15, "focused": True}})
                except OSError:
                    pass
                expect_quiet_end(label, helper, out_errors)
    finally:
        helper.stop()
        stub.close()

    label = "waybar-niri-workspaces waiting to reconnect"
    helper = WorkspacesHelper({"NIRI_SOCKET": os.path.join(workdir, "no-niri-here"), "WAYBAR_OUTPUT_NAME": "DP-1"})
    try:
        out = workspaces_output(label, helper.line(), out_errors)
        expect_workspaces(label, out, "?", ["error"], out_errors)
        helper.close_pipe()
        expect_quiet_end(label, helper, out_errors)
    finally:
        helper.stop()


# Stand-ins for niri msg and rofi; stand_in_home details their behaviour.
NIRI_STAND_IN = r'''#!PYTHON -IS
import json, os, sys

ASCII_CASE = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")
args = sys.argv[1:]
with open(os.environ["STUB_NIRI_LOG"], "a") as f:
    f.write(json.dumps(args) + "\n")
state = os.environ["STUB_NIRI_STATE"]
with open(state) as f:
    workspaces = json.load(f)
focused = next(w for w in workspaces if w["is_focused"])


def done(changed=False):
    if changed:
        with open(state, "w") as f:
            json.dump(workspaces, f)
    sys.exit(0)


def refuse(message):
    print(f"error: {message}", file=sys.stderr)
    sys.exit(2)


if args == ["msg", "-j", "workspaces"]:
    print(json.dumps(workspaces))
    done()
if args[:2] != ["msg", "action"] or len(args) < 3:
    refuse(f"unexpected arguments {args}")
action, rest = args[2], args[3:]
if action == "set-workspace-name":
    if rest[:1] == ["--"]:
        rest = rest[1:]
    elif rest[:1] and rest[0].startswith("-") and rest[0] != "-":
        refuse(f"unexpected argument '{rest[0]}' found")
    if len(rest) != 1:
        refuse(f"unexpected arguments {rest}")
    taken = any(w["name"] is not None and w["name"].translate(ASCII_CASE) == rest[0].translate(ASCII_CASE)
                for w in workspaces)
    if not taken:
        focused["name"] = rest[0]
    done(not taken)
if action == "unset-workspace-name" and not rest:
    focused["name"] = None
    done(True)
refuse(f"unexpected action {args[2:]}")
'''

ROFI_STAND_IN = r'''#!PYTHON -IS
import json, os, sys

args = sys.argv[1:]
with open(os.environ["STUB_ROFI_LOG"], "a") as f:
    f.write(json.dumps(args) + "\n")
if "-v" in args or "-version" in args:
    print("Version: 2.0.0")
    sys.exit(0)
if "-h" in args or "-help" in args or "--help" in args:
    print("rofi usage:\n\trofi [-options ...]")
    sys.exit(0)
with open(os.environ["STUB_ROFI_ANSWERS"]) as f:
    answers = json.load(f)
if not answers:
    sys.exit(1)
with open(os.environ["STUB_ROFI_ANSWERS"], "w") as f:
    json.dump(answers[1:], f)
answer = answers[0]
if "focus" in answer:
    with open(os.environ["STUB_NIRI_STATE"]) as f:
        workspaces = json.load(f)
    target = next(w for w in workspaces if w["id"] == answer["focus"])
    previous = next(w for w in workspaces if w["output"] == target["output"] and w["is_active"])
    for w in workspaces:
        if w["output"] == target["output"]:
            w["is_active"] = w is target
        w["is_focused"] = w is target
    if previous is not target and previous["name"] is None and previous["active_window_id"] is None:
        workspaces.remove(previous)
        for w in workspaces:
            if w["output"] == previous["output"] and w["idx"] > previous["idx"]:
                w["idx"] -= 1
    with open(os.environ["STUB_NIRI_STATE"], "w") as f:
        json.dump(workspaces, f)
field = args[args.index("-filter") + 1] if "-filter" in args[:-1] else ""
field = answer.get("type", field)
status = answer.get("exit", 0)
if status == 0 or 10 <= status <= 28:
    print(field)
sys.exit(status)
'''

PASS_THROUGH_LAUNCH = '#!/bin/sh\nexec "$@"\n'


def stand_in_home(workdir, workspaces, answers):
    """A directory with the stand-ins for niri and rofi; returns it and the environment that runs with them.

    The stand-in for niri holds WORKSPACES and logs every call. It names
    and unnames the focused workspace, as niri does. Like niri, it drops a
    name without a word that a workspace already carries, the focused one
    included, comparing ASCII letters regardless of case and every other
    character exactly (Rust's eq_ignore_ascii_case). Like clap, which parses
    the arguments of niri msg, it refuses a name that begins with "-" unless
    "--" came before it.

    The stand-in for rofi logs every call and answers with ANSWERS in turn.
    Each answer is what the user does in the dialog: "type" replaces the
    text in the field, which otherwise holds what -filter put there, and
    "exit" is the exit status, 0 (Enter) unless given. "focus" names the id
    of a workspace that gets the focus while the dialog is open, as when the
    user presses a key that niri has bound to focus-workspace-down; it
    becomes the active workspace of its output as well. If the workspace
    that was active there before is empty and unnamed, the stand-in removes
    it, and the workspaces below it on that output move up by one index, as
    niri does with such a workspace between two others once the switch has
    ended. A workspace counts as empty when it has no active_window_id, as
    niri reports one without windows. Like rofi, it prints the field for
    Enter (0) and for a custom key (10 to 28), and nothing for Escape (1).
    Like rofi, it looks for -v and -help among all words of its command
    line, wherever they stand, and then prints its version or its usage
    instead of opening a dialog. A dialog beyond the answers is left with
    Escape.

    PATH holds nothing but the stand-ins, python3 and sh, so that no check
    can reach the real niri or rofi; NIRI_SOCKET and WAYLAND_DISPLAY are
    not passed on either.
    """
    home = tempfile.mkdtemp(dir=workdir)
    bin_dir = os.path.join(home, "bin")
    os.mkdir(bin_dir)
    for name, source in (("niri", NIRI_STAND_IN), ("rofi", ROFI_STAND_IN)):
        write_file(os.path.join(bin_dir, name), source.replace("PYTHON", sys.executable, 1))
        os.chmod(os.path.join(bin_dir, name), 0o755)
    os.symlink(sys.executable, os.path.join(bin_dir, "python3"))
    os.symlink("/bin/sh", os.path.join(bin_dir, "sh"))
    write_file(os.path.join(home, "launch"), PASS_THROUGH_LAUNCH)
    os.chmod(os.path.join(home, "launch"), 0o755)
    write_file(os.path.join(home, "workspaces.json"), json.dumps(workspaces))
    write_file(os.path.join(home, "answers.json"), json.dumps(answers))
    env = {
        "PATH": bin_dir,
        "HOME": home,
        "STUB_NIRI_STATE": os.path.join(home, "workspaces.json"),
        "STUB_NIRI_LOG": os.path.join(home, "niri.log"),
        "STUB_ROFI_LOG": os.path.join(home, "rofi.log"),
        "STUB_ROFI_ANSWERS": os.path.join(home, "answers.json"),
    }
    return home, env


def stand_in_results(home, res):
    """What happened with the stand-ins in HOME during the run RES: niri's calls and workspaces, rofi's calls."""
    with open(os.path.join(home, "workspaces.json")) as f:
        workspaces = json.load(f)
    return {
        "status": None if res is None else res.returncode,
        "stderr": None if res is None else res.stderr,
        "workspaces": workspaces,
        "niri": [json.loads(line) for line in read_lines(os.path.join(home, "niri.log"))],
        "rofi": [json.loads(line) for line in read_lines(os.path.join(home, "rofi.log"))],
    }


def rename_run(workdir, workspaces, answers):
    """Runs rename-niri-workspace with the stand-ins for niri and rofi; see stand_in_home and stand_in_results."""
    home, env = stand_in_home(workdir, workspaces, answers)
    try:
        res = subprocess.run([repo_path(RENAME_WORKSPACE)], env=env, capture_output=True, text=True,
                             timeout=HELPER_TIMEOUT)
    except (subprocess.TimeoutExpired, OSError):
        res = None
    return stand_in_results(home, res)


def niri_actions(run):
    """The actions sent to niri, without the queries."""
    return [call[2:] for call in run["niri"] if call[:2] == ["msg", "action"]]


def rofi_option(argv, option):
    """The value rofi takes for OPTION from ARGV, or None."""
    return argv[argv.index(option) + 1] if option in argv[:-1] else None


def dialog_scene(name=None, other_name=None):
    """Workspace 3 on DP-1 has the focus and carries NAME; workspace 2 on HDMI-A-1 carries OTHER_NAME."""
    return [niri_workspace(12, 2, "DP-1"),
            niri_workspace(13, 3, "DP-1", name=name, active=True, focused=True),
            niri_workspace(21, 1, "HDMI-A-1"),
            niri_workspace(22, 2, "HDMI-A-1", name=other_name, active=True)]


def expect_rename(label, run, names, actions, out_errors):
    """The dialog ended with status 0, sent exactly ACTIONS to niri and left the workspaces with NAMES (id: name)."""
    got = {w["id"]: w["name"] for w in run["workspaces"] if w["id"] in names}
    if run["status"] != 0 or niri_actions(run) != actions or got != names:
        out_errors.append(f"❌ {label}: exit status {run['status']} (stderr {run['stderr']!r}), actions "
                          f"{niri_actions(run)!r}, names {got!r}; expected status 0, actions {actions!r}, "
                          f"names {names!r}.")


def expect_dialogs(label, run, count, out_errors):
    """The dialog opened COUNT times; returns the command lines of rofi, or None after reporting a different count."""
    if len(run["rofi"]) != count:
        out_errors.append(f"❌ {label}: opened rofi {len(run['rofi'])} times, expected {count}: {run['rofi']!r}.")
        return None
    return run["rofi"]


def check_rename_field(workdir, out_errors):
    """The field holds the current name; confirming it unchanged sends nothing to niri.

    The prompt names the workspace by the index that focus-workspace takes,
    and the note below the field says what an empty field does. An unnamed
    workspace starts with an empty field, and confirming that leaves it
    unnamed, again without a call.
    """
    for name in ("Projekt", None):
        label = f"rename-niri-workspace on a workspace named {name!r}, confirmed as it is"
        run = rename_run(workdir, dialog_scene(name), [{}])
        dialogs = expect_dialogs(label, run, 1, out_errors)
        if dialogs and (rofi_option(dialogs[0], "-p") != "Workspace 3" or rofi_option(dialogs[0], "-filter") != name
                        or rofi_option(dialogs[0], "-mesg") != RENAME_HINT):
            out_errors.append(f"❌ {label}: rofi ran with {dialogs[0]!r}; expected the prompt 'Workspace 3', "
                              f"the field holding {name!r} and the note {RENAME_HINT!r}.")
        expect_rename(label, run, {13: name}, [], out_errors)


def check_rename_option_like_names(workdir, out_errors):
    """A name that begins with "-" stays out of rofi's field, and "--" goes before every name sent to niri.

    rofi takes every word of its command line for an option: "-filter -v"
    makes it print its version and exit with 0, and that version would have
    become the name. niri msg parses its arguments with clap, which takes
    "-x" for an option unless "--" came before it.
    """
    label = "rename-niri-workspace on a workspace named '-v'"
    run = rename_run(workdir, dialog_scene("-v"), [{"type": "Neu"}])
    dialogs = expect_dialogs(label, run, 1, out_errors)
    if dialogs and ("-filter" in dialogs[0] or "-v" in dialogs[0]):
        out_errors.append(f"❌ {label}: rofi ran with {dialogs[0]!r}, which puts '-v' on its command line.")
    expect_rename(label, run, {13: "Neu"}, [["set-workspace-name", "--", "Neu"]], out_errors)

    label = "rename-niri-workspace setting the name '-x'"
    run = rename_run(workdir, dialog_scene("Projekt"), [{"type": "-x"}])
    expect_rename(label, run, {13: "-x"}, [["set-workspace-name", "--", "-x"]], out_errors)


def check_rename_empty_field(workdir, out_errors):
    """An empty field removes the name only when the dialog opened with a text in the field, which the user deleted.

    That text is the current name or, when the dialog opens again after a
    conflict, the text entered before. A text that begins with "-" cannot go
    into the field, which then opens empty: confirming it changes nothing,
    and the note says that an empty field keeps the name. Before, Enter on
    that empty field removed the name: with "Projekt" on workspace 3 and
    "-X" on another one, typing "-x" opened the dialog again without a text,
    and Enter took "Projekt" away.
    """
    label = "rename-niri-workspace with the name deleted from the field"
    run = rename_run(workdir, dialog_scene("Projekt"), [{"type": ""}])
    expect_rename(label, run, {13: None}, [["unset-workspace-name"]], out_errors)

    label = "rename-niri-workspace with the text entered before deleted from the field"
    run = rename_run(workdir, dialog_scene("Projekt", "Mail"), [{"type": "mail"}, {"type": ""}])
    dialogs = expect_dialogs(label, run, 2, out_errors)
    if dialogs and rofi_option(dialogs[1], "-filter") != "mail":
        out_errors.append(f"❌ {label}: rofi ran again with {dialogs[1]!r}; expected the field holding 'mail'.")
    expect_rename(label, run, {13: None, 22: "Mail"}, [["unset-workspace-name"]], out_errors)

    label = "rename-niri-workspace with an empty field on a workspace named '-v'"
    run = rename_run(workdir, dialog_scene("-v"), [{}])
    dialogs = expect_dialogs(label, run, 1, out_errors)
    if dialogs and rofi_option(dialogs[0], "-mesg") != RENAME_KEEP_HINT:
        out_errors.append(f"❌ {label}: rofi ran with {dialogs[0]!r}; expected the note {RENAME_KEEP_HINT!r}.")
    expect_rename(label, run, {13: "-v"}, [], out_errors)

    label = "rename-niri-workspace with an empty field after '-x', which workspace 2 on HDMI-A-1 carries as '-X'"
    run = rename_run(workdir, dialog_scene("Projekt", "-X"), [{"type": "-x"}, {}])
    note = f'Workspace 2 on HDMI-A-1 is already named "-X".\n{RENAME_KEEP_HINT}'
    dialogs = expect_dialogs(label, run, 2, out_errors)
    if dialogs and ("-filter" in dialogs[1] or rofi_option(dialogs[1], "-mesg") != note):
        out_errors.append(f"❌ {label}: rofi ran again with {dialogs[1]!r}; expected the field empty and the note "
                          f"{note!r}.")
    expect_rename(label, run, {13: "Projekt", 22: "-X"}, [], out_errors)


def check_rename_cancel(workdir, out_errors):
    """Escape and rofi's custom keys change nothing.

    rofi exits with 1 for Escape and with 10 to 28 for the custom keys
    kb-custom-1 to kb-custom-19; for a custom key it prints the text in the
    field as for Enter.
    """
    for status in (1, 10, 28):
        label = f"rename-niri-workspace left with exit status {status} of rofi"
        run = rename_run(workdir, dialog_scene("Projekt"), [{"type": "Neu", "exit": status}])
        expect_rename(label, run, {13: "Projekt"}, [], out_errors)


def check_rename_case_change(workdir, out_errors):
    """A change of case alone removes the name and then sets it again.

    niri drops a name without a word when a workspace carries it already,
    the focused one included, and compares ASCII letters regardless of case:
    set-workspace-name alone would leave "projekt" as it was. "Ä" and "ä"
    are no ASCII letters and differ for niri, so that change is a plain
    rename.
    """
    label = "rename-niri-workspace changing 'projekt' to 'Projekt'"
    run = rename_run(workdir, dialog_scene("projekt"), [{"type": "Projekt"}])
    expect_rename(label, run, {13: "Projekt"},
                  [["unset-workspace-name"], ["set-workspace-name", "--", "Projekt"]], out_errors)

    label = "rename-niri-workspace changing 'äpfel' to 'Äpfel'"
    run = rename_run(workdir, dialog_scene("äpfel"), [{"type": "Äpfel"}])
    expect_rename(label, run, {13: "Äpfel"}, [["set-workspace-name", "--", "Äpfel"]], out_errors)


def check_rename_taken_name(workdir, out_errors):
    """A name another workspace carries opens the dialog again, with the text as entered and a note naming that workspace and its output.

    niri would drop the name without a word. The comparison is niri's, so
    "MAIL & <CHAT>" is taken by "Mail & <Chat>" while "äpfel" is not taken
    by "Äpfel". The note is Pango markup, and the name in it escaped. The
    text entered again follows the rule for the field: one that begins with
    "-" stays out of it.
    """
    label = "rename-niri-workspace with a name that workspace 2 on HDMI-A-1 carries"
    run = rename_run(workdir, dialog_scene(None, "Mail & <Chat>"), [{"type": "MAIL & <CHAT>"}, {"type": "Post"}])
    note = f'Workspace 2 on HDMI-A-1 is already named "Mail &amp; &lt;Chat&gt;".\n{RENAME_HINT}'
    dialogs = expect_dialogs(label, run, 2, out_errors)
    if dialogs and (rofi_option(dialogs[1], "-filter") != "MAIL & <CHAT>" or rofi_option(dialogs[1], "-mesg") != note
                    or rofi_option(dialogs[1], "-p") != "Workspace 3"):
        out_errors.append(f"❌ {label}: rofi ran again with {dialogs[1]!r}; expected the field holding "
                          f"'MAIL & <CHAT>' and the note {note!r}.")
    expect_rename(label, run, {13: "Post", 22: "Mail & <Chat>"}, [["set-workspace-name", "--", "Post"]], out_errors)

    label = "rename-niri-workspace with 'äpfel' while workspace 2 on HDMI-A-1 carries 'Äpfel'"
    run = rename_run(workdir, dialog_scene(None, "Äpfel"), [{"type": "äpfel"}])
    expect_dialogs(label, run, 1, out_errors)
    expect_rename(label, run, {13: "äpfel", 22: "Äpfel"}, [["set-workspace-name", "--", "äpfel"]], out_errors)

    label = "rename-niri-workspace with '-x' while workspace 2 on HDMI-A-1 carries '-X'"
    run = rename_run(workdir, dialog_scene(None, "-X"), [{"type": "-x"}, {"exit": 1}])
    dialogs = expect_dialogs(label, run, 2, out_errors)
    if dialogs and ("-filter" in dialogs[1] or '"-X"' not in (rofi_option(dialogs[1], "-mesg") or "")):
        out_errors.append(f"❌ {label}: rofi ran again with {dialogs[1]!r}; expected the field empty and a note "
                          f"naming '-X'.")
    expect_rename(label, run, {13: None, 22: "-X"}, [], out_errors)


def check_rename_focus_moved(workdir, out_errors):
    """When another workspace has the focus by the time the user confirms, the dialog changes nothing.

    niri keeps handling its key bindings while rofi is open, since rofi asks
    for a shortcuts inhibitor only with -global-kb. The dialog reads the
    focused workspace again after the user confirms; without comparing it to
    the one it opened for, Mod+Page_Down pressed during the dialog gave the
    name to the workspace below, and an empty field removed that one's name.
    The stand-in for rofi moves the focus before it answers: from workspace 3
    to workspace 4 below it, as Mod+Page_Down does, in the first dialog and
    in one opened again after a conflict. Such a move changes the index and
    the name of the focused workspace alike, so a dialog that compared
    either of them in place of the id would pass those cases too. Comparing
    the name, it would name the wrong workspace when the focus moves from
    one unnamed workspace to another; comparing the output and the index,
    when niri removes the workspace that the focus left, empty and unnamed,
    and the one below takes its index. Each of these two is a case of its
    own. In the first, workspace 3 holds a window, so that niri keeps it and
    workspace 4 keeps its index; in the second, both workspaces are unnamed
    as well, so that neither the output nor the index nor the name, nor all
    of them together, tell them apart.

    Each case also checks that the focus did move, to the index the case
    gives, and that nothing went to stderr: a case naming a target that its
    scene does not hold makes the stand-in for rofi end with a traceback and
    exit status 1, which the dialog takes for Escape, so the case would pass
    without the dialog comparing anything; and a workspace 4 that kept its
    index, because the stand-in left the empty workspace 3 in place, would
    let a dialog pass that compared the index.
    """
    named = dialog_scene("Projekt", "Mail & <Chat>") + [niri_workspace(14, 4, "DP-1", name="Unten")]
    named_kept = {13: "Projekt", 14: "Unten", 22: "Mail & <Chat>"}
    unnamed = dialog_scene() + [niri_workspace(14, 4, "DP-1")]
    by_id(unnamed, 13)["active_window_id"] = 103
    emptied = dialog_scene() + [niri_workspace(14, 4, "DP-1")]
    cases = [
        ("a new name after the focus moved to workspace 4", named, [{"type": "Neu", "focus": 14}], named_kept, 4),
        ("an empty field after the focus moved to workspace 4", named, [{"type": "", "focus": 14}], named_kept, 4),
        ("a new name in the dialog opened again after the focus moved to workspace 4", named,
         [{"type": "MAIL & <CHAT>"}, {"type": "Neu", "focus": 14}], named_kept, 4),
        ("a new name after the focus moved from the unnamed workspace 3 to the unnamed workspace 4", unnamed,
         [{"type": "Neu", "focus": 14}], {13: None, 14: None}, 4),
        # Workspace 3 is empty and lacks a name, just as it was after the user
        # closed its last window, and niri retains it solely while it remains
        # active. Pressing Mod+Page_Down in the dialog moves the focus to
        # workspace 4, and upon completion of the switch, niri removes workspace
        # 3, causing workspace 4 to assume index 3. DP-1 continues to be the
        # focused output, so rofi, whose layer surface lies there, keeps the
        # keyboard, and the user can confirm. The focused workspace then aligns
        # with the one the dialog initially opened for, matching in output,
        # index and name, and differs only in its id.
        ("a new name after the focus moved from the empty workspace 3 to workspace 4, which then took the index 3",
         emptied, [{"type": "Neu", "focus": 14}], {14: None}, 3),
    ]
    for case, scene, answers, names, index in cases:
        label = f"rename-niri-workspace confirming {case}"
        target = next(answer["focus"] for answer in answers if "focus" in answer)
        run = rename_run(workdir, scene, answers)
        focused = [(w["id"], w["idx"]) for w in run["workspaces"] if w["is_focused"]]
        if focused != [(target, index)] or run["stderr"]:
            out_errors.append(f"❌ {label}: the focus ended on {focused!r} (id, index) with {run['stderr']!r} on "
                              f"stderr; expected it on the id {target} at the index {index}, where the stand-in for "
                              f"rofi moves it, and nothing on stderr.")
            continue
        expect_dialogs(label, run, len(answers), out_errors)
        expect_rename(label, run, names, [], out_errors)


def check_workspaces_commands(bar_config, workdir, out_errors):
    """A click on the module opens the rename dialog for the focused workspace, and the module does not respond to scrolling.

    waybar 0.15 sets WAYBAR_OUTPUT_NAME for exec only: AModule starts the
    commands for clicks and scrolling through forkExec without the output,
    so no command can address the bar's output by name. A click needs none,
    as niri focuses the output under the pointer on every click that hits
    no window, before waybar starts the command. A command that focused the
    output from WAYBAR_OUTPUT_NAME first would send focus-monitor with an
    empty name, which niri ignores.

    Scrolling on the module used to switch the workspaces of the focused
    output. With warp-mouse-to-focus, which the niri config of the skel
    turns on, niri puts the pointer onto the window that has the focus after
    focus-workspace-up and focus-workspace-down, so once a switch reached a
    workspace with a window, the next step of the mouse wheel scrolled in
    that window, a page in the browser for instance. waybar also takes every
    smooth-scroll event of a touchpad for a scroll command of its own, as
    smooth-scrolling-threshold is 0 unless set, so a short swipe skipped
    several workspaces, whereas the skel rate-limits its bindings for the
    mouse wheel with cooldown-ms=150. Mod+mouse wheel and the keyboard
    shortcuts switch workspaces instead. waybar connects no handler for
    scrolling to a custom module that has none of on-scroll-up,
    on-scroll-down, on-scroll-left and on-scroll-right, so the module must
    have none of them.

    The click runs here through /bin/sh without WAYBAR_OUTPUT_NAME, as
    waybar runs it, with a launch that passes its arguments straight on,
    the dialog from this repository and the stand-ins for niri and rofi.
    Workspace 3 on DP-1 has the focus, as niri leaves it after a click on
    the bar of DP-1, so the dialog has to ask for workspace 3, and leaving
    it with Escape has to send niri nothing.
    """
    bars = bar_config if isinstance(bar_config, list) else [bar_config]
    module = next((bar[WORKSPACES_MODULE] for bar in bars if isinstance(bar.get(WORKSPACES_MODULE), dict)), None)
    if module is None:
        out_errors.append(f"❌ waybar has no '{WORKSPACES_MODULE}' module to check the commands of.")
        return
    scroll_keys = sorted(key for key in module if key.startswith("on-scroll"))
    if scroll_keys:
        out_errors.append(f"❌ waybar '{WORKSPACES_MODULE}' responds to scrolling through {', '.join(scroll_keys)}; "
                          f"after a switch, niri puts the pointer onto the window that has the focus, where the next "
                          f"step of the mouse wheel lands.")
    label = f"waybar '{WORKSPACES_MODULE}' on-click"
    command = module.get("on-click")
    if not isinstance(command, str):
        out_errors.append(f"❌ {label} is missing.")
        return
    home, env = stand_in_home(workdir, dialog_scene(), [{"exit": 1}])
    helpers = os.path.abspath(repo_path("/usr/lib/ditana")) + "/"
    command = command.replace(LAUNCH, os.path.join(home, "launch")).replace("/usr/lib/ditana/", helpers)
    try:
        res = subprocess.run(["/bin/sh", "-c", command], env=env, capture_output=True, text=True,
                             timeout=HELPER_TIMEOUT)
    except subprocess.TimeoutExpired:
        res = None
    run = stand_in_results(home, res)
    if run["status"] != 0 or niri_actions(run):
        out_errors.append(f"❌ {label}: exit status {run['status']} (stderr {run['stderr']!r}), sent "
                          f"{niri_actions(run)!r} to niri; expected status 0 and nothing sent.")
    opened = [rofi_option(argv, "-p") for argv in run["rofi"]]
    if opened != ["Workspace 3"]:
        out_errors.append(f"❌ {label}: opened the dialogs {opened!r}; expected ['Workspace 3'].")


def check_niri_workspaces(all_settings, out_errors):
    with tempfile.TemporaryDirectory() as workdir:
        check_workspaces_numbers(workdir, out_errors)
        check_workspaces_outputs(workdir, out_errors)
        check_workspaces_names(workdir, out_errors)
        check_workspaces_highlight(workdir, out_errors)
        check_workspaces_backslashes(workdir, out_errors)
        check_workspaces_tooltip(workdir, out_errors)
        check_workspaces_classes(workdir, out_errors)
        check_workspaces_unknown_events(workdir, out_errors)
        check_workspaces_waits_for_windows(workdir, out_errors)
        check_workspaces_events(workdir, out_errors)
        check_workspaces_window_focus(out_errors)
        check_workspaces_state_unknown_ids(out_errors)
        check_workspaces_reconnect(workdir, out_errors)
        check_workspaces_outside_niri(workdir, out_errors)
        check_workspaces_closed_pipe(workdir, out_errors)
        check_rename_field(workdir, out_errors)
        check_rename_option_like_names(workdir, out_errors)
        check_rename_empty_field(workdir, out_errors)
        check_rename_cancel(workdir, out_errors)
        check_rename_case_change(workdir, out_errors)
        check_rename_taken_name(workdir, out_errors)
        check_rename_focus_moved(workdir, out_errors)
        try:
            bar_config = installed_waybar_config(all_settings, workdir)
        except (RuntimeError, ValueError):
            bar_config = None
        if bar_config is not None:
            check_workspaces_commands(bar_config, workdir, out_errors)


print("🔍 Checking the waybar module for niri's workspaces and its rename dialog...")
niri_errors = []
check_niri_workspaces(settings, niri_errors)
for line in niri_errors:
    print(line)
if niri_errors:
    errors = True

# ---------------------------------------------------------------------------
# waybar-display-scale adjusts the bar's dimensions according to the largest
# display's DPI and pixel width.
#
# Every check runs the script on copies of the skel waybar files, with its
# own display-info and only stubs and the utilities the script requires on
# its PATH, ensuring that no check has the ability to restart the waybar on
# the machine where it is being run.
# ---------------------------------------------------------------------------

WAYBAR_STYLE = '/etc/skel/.config/waybar/style.css'

DISPLAY_SCALE_STUBS = {
    "systemctl": '#!/bin/sh\nprintf "systemctl %s\\n" "$*" >> "$STUB_LOG"\n'
                 'case "$*" in *is-active*) exit 3 ;; esac\n',
    "pgrep": '#!/bin/sh\nprintf "pgrep %s\\n" "$*" >> "$STUB_LOG"\n'
             '[ -n "$STUB_WAYBAR_RUNNING" ] && [ ! -e "$STUB_LOG.killed" ] && exit 0\nexit 1\n',
    "pkill": '#!/bin/sh\nprintf "pkill %s\\n" "$*" >> "$STUB_LOG"\n'
             '[ -n "$STUB_WAYBAR_RUNNING" ] || exit 1\n: > "$STUB_LOG.killed"\n',
    "uwsm": '#!/bin/sh\nprintf "uwsm %s\\n" "$*" >> "$STUB_LOG"\nexit 1\n',
    "inotifywait": '#!/bin/sh\nprintf "inotifywait %s\\n" "$*" >> "$STUB_LOG"\n',
}
DISPLAY_SCALE_LAUNCH_STUB = '#!/bin/sh\nprintf "launch %s\\n" "$*" >> "$STUB_LOG"\n'
DISPLAY_SCALE_TOOLS = ("awk", "sed", "mktemp", "cmp", "cat", "rm", "dirname", "basename", "sleep", "grep", "head")
DISPLAY_SCALE_TIMEOUT = 10
DISPLAY_INFO_DIRECTORY = object()


def display_scale_home(workdir, display_info, style=None):
    """Prepares one run of waybar-display-scale below WORKDIR and returns its directory.

    The directory holds config/waybar with a copy of the skel config.jsonc and
    of the skel style.css (or STYLE in its place), a display-info file holding
    DISPLAY_INFO (no file if it is None, a directory if it is
    DISPLAY_INFO_DIRECTORY), bin with the stubs and links to the tools the
    script needs, and the stub of launch, which is not in bin.
    """
    root = tempfile.mkdtemp(dir=workdir)
    waybar = os.path.join(root, "config", "waybar")
    os.makedirs(waybar)
    shutil.copy(repo_path(WAYBAR_CONFIG), waybar)
    if style is None:
        shutil.copy(repo_path(WAYBAR_STYLE), waybar)
    else:
        write_file(os.path.join(waybar, "style.css"), style)
    if display_info is DISPLAY_INFO_DIRECTORY:
        os.mkdir(os.path.join(root, "display-info"))
    elif display_info is not None:
        write_file(os.path.join(root, "display-info"), display_info)
    for name in ("home", "tmp", "bin"):
        os.mkdir(os.path.join(root, name))
    for name, body in DISPLAY_SCALE_STUBS.items():
        write_file(os.path.join(root, "bin", name), body)
        os.chmod(os.path.join(root, "bin", name), 0o755)
    write_file(os.path.join(root, "launch"), DISPLAY_SCALE_LAUNCH_STUB)
    os.chmod(os.path.join(root, "launch"), 0o755)
    for tool in DISPLAY_SCALE_TOOLS:
        os.symlink(shutil.which(tool), os.path.join(root, "bin", tool))
    return root


def display_scale_run(root, args=("--once",), waybar_running=False):
    """Runs waybar-display-scale on the files below ROOT.

    The environment is built from scratch: PATH holds the stubs and the tools
    only; HOME, XDG_CONFIG_HOME and TMPDIR lie below ROOT, and so do
    DITANA_DISPLAY_INFO and DITANA_LAUNCH_BIN, whose stub is not on PATH;
    neither XDG_RUNTIME_DIR nor a D-Bus address is passed on. systemctl finds
    no active unit and pgrep no waybar, so a restart attempt ends after these
    questions and never reaches pkill, uwsm or launch. WAYBAR_RUNNING stands
    for a waybar started by hand: pgrep then finds it until the pkill stub has
    been called, uwsm reports no session, and the restart goes on to launch.
    Even the real launch could start nothing here: it is a
    "#!/usr/bin/env bash" script, and bash is not on this PATH. The
    inotifywait stub watches nothing and ends at once, which ends the loop
    of a run without --once.

    Returns the exit status, stdout, stderr and the calls the stubs recorded
    during this run, one "name arguments" line each, or None if the run did
    not finish within DISPLAY_SCALE_TIMEOUT seconds.
    """
    calls = os.path.join(root, "calls")
    for path in (calls, calls + ".killed"):
        if os.path.exists(path):
            os.remove(path)
    env = {
        "PATH": os.path.join(root, "bin"),
        "HOME": os.path.join(root, "home"),
        "XDG_CONFIG_HOME": os.path.join(root, "config"),
        "TMPDIR": os.path.join(root, "tmp"),
        "DITANA_DISPLAY_INFO": os.path.join(root, "display-info"),
        "DITANA_LAUNCH_BIN": os.path.join(root, "launch"),
        "STUB_LOG": calls,
    }
    if waybar_running:
        env["STUB_WAYBAR_RUNNING"] = "1"
    try:
        res = subprocess.run([repo_path(WAYBAR_DISPLAY_SCALE)] + list(args), env=env,
                             capture_output=True, text=True, timeout=DISPLAY_SCALE_TIMEOUT)
    except subprocess.TimeoutExpired:
        return None
    return {"status": res.returncode, "stdout": res.stdout, "stderr": res.stderr, "calls": read_lines(calls)}


def display_scale_files(root):
    """The content of config.jsonc and style.css below ROOT."""
    contents = []
    for name in ("config.jsonc", "style.css"):
        with open(os.path.join(root, "config", "waybar", name)) as f:
            contents.append(f.read())
    return tuple(contents)


def display_scale_sizes(root):
    """The sizes the waybar files below ROOT carry, as far as waybar-display-scale may change them.

    The font size is the one of the first "* {" rule, comments left out.
    """
    config, style = display_scale_files(root)
    bar = jsonc_loads(config)
    font = re.search(r"^\*\s*\{[^}]*?font-size:\s*(\d+)px", re.sub(r"/\*.*?\*/", "", style, flags=re.S), re.M)
    return {
        "height": bar.get("height"),
        "taskbar icon-size": bar.get("wlr/taskbar", {}).get("icon-size"),
        "background-size": set(re.findall(r"background-size: (\d+px \d+px)", style)),
        "min-width": set(re.findall(r"min-width: (\d+px)", style)),
        "font-size of * {": int(font.group(1)) if font else None,
    }


def expected_display_scale_sizes(height, icon_size, bg_size, min_width, font_size):
    return {
        "height": height,
        "taskbar icon-size": icon_size,
        "background-size": {f"{bg_size}px {bg_size}px"},
        "min-width": {f"{min_width}px"},
        "font-size of * {": font_size,
    }


def display_scale_ran(label, run, out_errors):
    """Reports a run that hung or failed; returns whether it ended with status 0."""
    if run is None:
        out_errors.append(f"❌ waybar-display-scale, {label}: did not finish within {DISPLAY_SCALE_TIMEOUT} s.")
        return False
    if run["status"] != 0:
        out_errors.append(f"❌ waybar-display-scale, {label}: exit status {run['status']} "
                          f"(stdout {run['stdout']!r}, stderr {run['stderr']!r}).")
        return False
    return True


def check_display_scale_sizes(workdir, out_errors):
    """The bar is sized for the first display in display-info, by its DPI and by its width.

    The DPI alone used to decide. On a laptop with a 1920x1080 panel at 128 DPI
    that gave a bar 59 px high with an 18 px font, and the launchers and the
    modules on the right filled the whole width: not a single taskbar icon had
    room. A display narrower than 40 bar heights now shrinks height, icons and
    font by the factor it lacks, but not below three quarters. akino, a 5120 px
    wide monitor at 141 DPI, keeps the sizes of the skel files, which were made
    for it; its display-info is taken as it is, with a smaller second display
    that must not count. A 24-inch 1080p monitor is wide enough for its smaller
    bar, and a 1366x768 panel at 100 DPI would need less than three quarters
    and gets the floor. Every size is rounded half up.
    """
    cases = [
        ("akino", "DP-1 140.68 5120 2160\nHDMI-A-1 105.51 1920 1080\n", (64, 64, 56, 64, 18)),
        ("the Dell laptop", "eDP-1 128.34 1920 1080\n", (48, 48, 42, 48, 15)),
        ("a 24-inch 1080p monitor", "HDMI-A-1 92 1920 1080\n", (44, 44, 39, 44, 18)),
        ("a 1366x768 panel", "eDP-1 100 1366 768\n", (36, 36, 31, 36, 14)),
    ]
    for label, display_info, sizes in cases:
        root = display_scale_home(workdir, display_info)
        if not display_scale_ran(f"on {label}", display_scale_run(root), out_errors):
            continue
        got = display_scale_sizes(root)
        for key, want in expected_display_scale_sizes(*sizes).items():
            if got[key] != want:
                out_errors.append(f"❌ waybar-display-scale on {label} ({display_info.splitlines()[0]}) "
                                  f"set {key} to {got[key]!r}, expected {want!r}.")


def check_display_scale_leaves_other_sizes(workdir, out_errors):
    """Only the sizes that follow the display change; every other size stays as it is.

    The tray has an icon-size of its own in config.jsonc, and the launcher
    rules hide their labels with "font-size: 0;". A font size in px that the
    user gave to another rule is theirs. The font size of "* {" is found by
    the braces of the rule, outside of comments, and not by lines. Each case
    after the first is a form that a line-based sed range got wrong: "* {" on
    a single line, where a range would have run on into the next rule; a rule
    of the user on the line of a one-line "* {" without a font size, or on the
    line that closes "* {", where the substitution took the user's font size;
    a block comment in the style of the skel's, whose lines begin with " * ",
    one of them with "{", which opened a range through the user's next rule;
    and a "}" in a comment inside "* {", which ended the range before the font
    size, so that the font kept its size on a narrow display. The last two
    cases put something before "* {": a rule of the user, since "* {" is found
    by its selector and not by being the first rule, and an @import, which
    ends with ";" rather than with a brace, as many waybar themes begin.
    """
    user_rule = "#clock {\n  font-size: 20px;\n}\n"
    one_line_rule = "#clock { font-size: 20px; }"
    with open(repo_path(WAYBAR_STYLE)) as f:
        skel_style = f.read()
    cases = [
        ("the skel style.css with a rule of the user", skel_style + "\n" + user_rule, 15, user_rule),
        ('a one-line "* {" followed by a rule of the user',
         "* { font-family: sans-serif; font-size: 18px; }\n" + user_rule, 15, user_rule),
        ('a rule of the user on the line of a one-line "* {" without a font size',
         "* { font-family: sans-serif; } " + one_line_rule + "\n", None, one_line_rule),
        ('a rule of the user on the line that closes "* {"',
         "* {\n  font-size: 18px;\n} " + one_line_rule + "\n", 15, one_line_rule),
        ('a block comment with a line that begins with "{", before a rule of the user',
         skel_style + "\n/*\n * Own additions. The sizes below are mine, from the opening\n"
         " * { to the closing brace of each rule.\n */\n" + user_rule, 15, user_rule),
        ('a "}" in a comment inside "* {"',
         "* {\n  /* the size below ends at the } of this rule */\n  font-size: 18px;\n}\n" + user_rule,
         15, user_rule),
        ('a rule of the user before "* {"', user_rule + "\n" + skel_style, 15, user_rule),
        ('an @import before "* {"', '@import "colors.css";\n\n' + skel_style, 15, '@import "colors.css";'),
    ]
    for label, style, want_font, user_text in cases:
        root = display_scale_home(workdir, "eDP-1 128.34 1920 1080\n", style)
        if not display_scale_ran(label, display_scale_run(root), out_errors):
            continue
        config, patched = display_scale_files(root)
        font = display_scale_sizes(root)["font-size of * {"]
        if font != want_font:
            out_errors.append(f"❌ waybar-display-scale, {label}: font-size of * {{ is {font!r}, expected {want_font!r}.")
        if user_text not in patched:
            out_errors.append(f"❌ waybar-display-scale, {label}: changed the user's rule {user_text!r}.")
        if patched.count("font-size: 0;") != style.count("font-size: 0;"):
            out_errors.append(f"❌ waybar-display-scale, {label}: changed a \"font-size: 0;\" of the launchers.")
        tray = jsonc_loads(config).get("tray", {}).get("icon-size")
        if tray != 32:
            out_errors.append(f"❌ waybar-display-scale, {label}: set the tray's icon-size to {tray!r}, expected 32.")


def check_display_scale_own_font_rule(workdir, out_errors):
    """A later "* {" rule of the user's own keeps its font size; only the first one, the skel's, follows the display.

    The skel opens style.css with "* {", and that font size is the one the
    script owns. A user who wants a font size of their own adds a "* {" rule
    further down, which CSS lets win. If the script rewrote that one as well,
    a user would have no way to keep a font size of their own; the price of
    keeping one is that the bar does not shrink its font on a narrow display.
    """
    own_rule = "* {\n  font-size: 22px;\n}\n"
    with open(repo_path(WAYBAR_STYLE)) as f:
        style = f.read() + "\n" + own_rule
    root = display_scale_home(workdir, "eDP-1 128.34 1920 1080\n", style)
    if not display_scale_ran('with a "* {" rule of the user', display_scale_run(root), out_errors):
        return
    font = display_scale_sizes(root)["font-size of * {"]
    if font != 15:
        out_errors.append(f"❌ waybar-display-scale with a \"* {{\" rule of the user: font-size of the skel's "
                          f"* {{ is {font!r}, expected 15.")
    if own_rule not in display_scale_files(root)[1]:
        out_errors.append(f"❌ waybar-display-scale changed the user's own rule {own_rule!r}.")


def check_display_scale_restarts_on_change(workdir, out_errors):
    """waybar is restarted when the files change, and only then.

    waybar reads its config at start only, so a change needs a restart. A
    restart without one would close whatever menu or tooltip is open, on every
    hotplug of a display. The skel files carry akino's sizes, so akino's
    display-info leaves them as they are; the Dell's changes them. With the
    stubs, a restart attempt shows as systemctl being asked for waybar.service.
    """
    attempt = "systemctl --user is-active --quiet waybar.service"
    for label, display_info, restarts in [("akino", "DP-1 140.68 5120 2160\n", False),
                                          ("the Dell laptop", "eDP-1 128.34 1920 1080\n", True)]:
        root = display_scale_home(workdir, display_info)
        before = display_scale_files(root)
        run = display_scale_run(root)
        if not display_scale_ran(f"on {label}", run, out_errors):
            continue
        changed = display_scale_files(root) != before
        if changed != restarts or (attempt in run["calls"]) != restarts:
            out_errors.append(f"❌ waybar-display-scale on {label}: files {'changed' if changed else 'unchanged'}, "
                              f"stub calls {run['calls']!r}; expected the files "
                              f"{'changed and a restart attempt' if restarts else 'unchanged and no restart attempt'}.")


def check_display_scale_respawns_by_launch(workdir, out_errors):
    """A waybar started by hand is killed and started again by the launch that DITANA_LAUNCH_BIN names.

    Without a systemd unit for waybar and without a uwsm session,
    restart_waybar kills waybar and starts it again through launch.
    check_display_scale_respawn looks at restart_waybar on its own; here the
    whole script runs, so that the launch it calls is the one its LAUNCH takes
    from DITANA_LAUNCH_BIN. The stub of launch is not on PATH: a script that
    called launch by name or by its installed path would miss it.
    """
    root = display_scale_home(workdir, "eDP-1 128.34 1920 1080\n")
    run = display_scale_run(root, waybar_running=True)
    if not display_scale_ran("with a waybar started by hand", run, out_errors):
        return
    if "pkill -x waybar" not in run["calls"] or run["calls"][-1:] != ["launch waybar"]:
        out_errors.append(f"❌ waybar-display-scale with a waybar started by hand: stub calls {run['calls']!r}; "
                          f"expected pkill -x waybar and, last, launch waybar through DITANA_LAUNCH_BIN.")


def check_display_scale_second_run(workdir, out_errors):
    """A second run on the same display changes nothing and restarts nothing.

    The service runs the script again on every change of display-info, and
    wayland-display-info rewrites the file when any parameter of any display
    changes. Each run has to arrive at the same files, or waybar would be
    restarted every time.
    """
    root = display_scale_home(workdir, "eDP-1 128.34 1920 1080\n")
    if not display_scale_ran("first run", display_scale_run(root), out_errors):
        return
    first = display_scale_files(root)
    run = display_scale_run(root)
    if not display_scale_ran("second run", run, out_errors):
        return
    if display_scale_files(root) != first or run["calls"]:
        out_errors.append(f"❌ waybar-display-scale changed the files again in a second run on the same display, "
                          f"or tried to restart waybar (stub calls {run['calls']!r}).")


def check_display_scale_unusable_display_info(workdir, out_errors):
    """A display-info the script cannot use leaves the files alone, and the run still succeeds.

    wayland-display-info writes an empty file when no display reports a
    physical size, and there is no file before it has run once. A file without
    a DPI in its first line can only come from elsewhere, for example one
    written by hand for DITANA_DISPLAY_INFO to try a size; a size computed from
    it would end up in the user's config. DITANA_DISPLAY_INFO naming a
    directory, say the cache directory instead of the file in it, makes the
    read itself fail, just as a file would that disappears between the check
    for it and the read. The variables the read should have filled were then
    unset, and under set -u the script stopped: --once with status 1, the
    service every three seconds, restarted by Restart=always. A first line
    without a usable width is sized by the DPI alone, as before the width
    counted: for the Dell's DPI that is 59/59/52/59 with the font at 18 px.
    """
    untouched = [
        ("no display-info", None),
        ("a directory in place of display-info", DISPLAY_INFO_DIRECTORY),
        ("an empty display-info", ""),
        ("a first line without a DPI", "eDP-1\n"),
        ("a DPI that is no number", "eDP-1 high 1920 1080\n"),
        ("a line of garbage", "garbage\n"),
    ]
    for label, display_info in untouched:
        root = display_scale_home(workdir, display_info)
        before = display_scale_files(root)
        run = display_scale_run(root)
        if not display_scale_ran(f"with {label}", run, out_errors):
            continue
        if display_scale_files(root) != before or run["calls"]:
            out_errors.append(f"❌ waybar-display-scale with {label}: changed the files or tried to restart "
                              f"waybar (stub calls {run['calls']!r}).")

    for label, display_info in [("no width", "eDP-1 128.34\n"),
                                ("a width that is no number", "eDP-1 128.34 wide 1080\n"),
                                ("a width of 0", "eDP-1 128.34 0 1080\n")]:
        root = display_scale_home(workdir, display_info)
        if not display_scale_ran(f"with {label}", display_scale_run(root), out_errors):
            continue
        got = display_scale_sizes(root)
        want = expected_display_scale_sizes(59, 59, 52, 59, 18)
        if got != want:
            out_errors.append(f"❌ waybar-display-scale with {label} ({display_info.strip()}) set {got!r}, "
                              f"expected the sizes by DPI alone {want!r}.")


def check_display_scale_arguments(workdir, out_errors):
    """--once applies the sizes and exits; without arguments the script watches display-info; anything else is refused.

    --once is what a user runs by hand, and what these checks run: it must not
    start inotifywait. Without arguments the script is the service, and it
    watches the directory of display-info, which DITANA_DISPLAY_INFO has to
    move as well. A wrong argument ends with the usage and exit status 2
    before the files are touched.
    """
    display_info = "eDP-1 128.34 1920 1080\n"
    root = display_scale_home(workdir, display_info)
    run = display_scale_run(root)
    if display_scale_ran("--once", run, out_errors) and any(c.startswith("inotifywait ") for c in run["calls"]):
        out_errors.append(f"❌ waybar-display-scale --once started inotifywait: {run['calls']!r}.")

    root = display_scale_home(workdir, display_info)
    run = display_scale_run(root, ())
    if display_scale_ran("without arguments", run, out_errors):
        watches = [c for c in run["calls"] if c.startswith("inotifywait ")]
        if len(watches) != 1 or not watches[0].endswith(" " + root):
            out_errors.append(f"❌ waybar-display-scale without arguments ran {watches!r}; expected one "
                              f"inotifywait on {root}, the directory of DITANA_DISPLAY_INFO.")
        if display_scale_sizes(root) != expected_display_scale_sizes(48, 48, 42, 48, 15):
            out_errors.append(f"❌ waybar-display-scale without arguments did not size the bar for the Dell laptop: "
                              f"{display_scale_sizes(root)!r}.")

    for args in (["--twice"], ["once"], ["--once", "--once"], ["--once", "extra"], [""]):
        root = display_scale_home(workdir, display_info)
        before = display_scale_files(root)
        run = display_scale_run(root, args)
        if (run is None or run["status"] != 2 or run["stdout"] or "usage:" not in run["stderr"]
                or run["calls"] or display_scale_files(root) != before):
            out_errors.append(f"❌ waybar-display-scale {args!r}: expected the usage, exit status 2 and the files "
                              f"untouched, got {run!r}.")


def check_display_scale_once_reports_failure(workdir, out_errors):
    """--once ends with status 1 when it cannot write the sizes, and leaves the files and waybar alone.

    Whoever runs --once, by hand or from a script, learns only from the status
    that nothing was applied. The script writes through mktemp, which fails
    when the temporary directory is full, read-only or gone; a TMPDIR that does
    not exist is the way to get there here.
    """
    root = display_scale_home(workdir, "eDP-1 128.34 1920 1080\n")
    os.rmdir(os.path.join(root, "tmp"))
    before = display_scale_files(root)
    run = display_scale_run(root)
    if run is None or run["status"] != 1 or run["calls"] or display_scale_files(root) != before:
        out_errors.append(f"❌ waybar-display-scale --once without a usable TMPDIR: expected exit status 1, "
                          f"the files untouched and no restart attempt, got {run!r}.")


print("🔍 Checking how waybar-display-scale sizes the bar...")
display_scale_errors = []
missing_tools = [tool for tool in DISPLAY_SCALE_TOOLS if shutil.which(tool) is None]
if missing_tools:
    display_scale_errors.append(f"❌ waybar-display-scale needs {', '.join(missing_tools)}, missing here.")
else:
    with tempfile.TemporaryDirectory() as workdir:
        check_display_scale_sizes(workdir, display_scale_errors)
        check_display_scale_leaves_other_sizes(workdir, display_scale_errors)
        check_display_scale_own_font_rule(workdir, display_scale_errors)
        check_display_scale_restarts_on_change(workdir, display_scale_errors)
        check_display_scale_respawns_by_launch(workdir, display_scale_errors)
        check_display_scale_second_run(workdir, display_scale_errors)
        check_display_scale_unusable_display_info(workdir, display_scale_errors)
        check_display_scale_arguments(workdir, display_scale_errors)
        check_display_scale_once_reports_failure(workdir, display_scale_errors)
for line in display_scale_errors:
    print(line)
if display_scale_errors:
    errors = True

print("🔍 Checking Thunar custom actions...")
thunar_errors = []
check_thunar_actions(settings, thunar_errors)
for line in thunar_errors:
    print(line)
if thunar_errors:
    errors = True

# ---------------------------------------------------------------------------
# Every program found within /usr/lib/ditana/ that the niri config of the
# skel calls is shipped.
# ---------------------------------------------------------------------------

NIRI_CONFIG = '/etc/skel/.config/niri/config.kdl'


def check_niri_binds(all_settings, out_errors):
    """Every program under /usr/lib/ditana/ that the niri config of the skel calls is shipped by some setting.

    Mod+N opens the rename dialog, for instance. A key bound to a program
    that is not there does nothing visible: niri writes the error to the
    journal when it fails to start the program, and nothing appears on
    screen.
    """
    shipped = {f for s in all_settings for f in s.get('files', [])}
    with open(repo_path(NIRI_CONFIG)) as f:
        programs = sorted(set(DITANA_PROGRAM_RE.findall(f.read())))
    for program in programs:
        if program not in shipped:
            out_errors.append(f"❌ {NIRI_CONFIG} names {program}, which no setting ships.")


print("🔍 Checking programs under /usr/lib/ditana/ that the niri config of the skel calls...")
niri_bind_errors = []
check_niri_binds(settings, niri_bind_errors)
for line in niri_bind_errors:
    print(line)
if niri_bind_errors:
    errors = True

# ---------------------------------------------------------------------------
# The rules for the RAM disk apply exclusively to accounts created from the
# skeleton, and to no others.
#
# systemd-tmpfiles-setup.service executes within the user manager of each
# account, including that of a system account like greetd's greeter. Thus,
# the rules are contained in the skeleton, and only a home made from it
# holds them. The checks apply them using the actual systemd-tmpfiles,
# inside a stand-in root for an installed system.
# ---------------------------------------------------------------------------

RAMDISK_SETTINGS = ('install-ramdisk', 'install-ramdisk-thunar-bookmark')
SKELETON = '/etc/skel'
SKELETON_USER_HOME = 'home/user'
NOBODY = 65534
# The parameters by which systemd-tmpfiles-setup.service in a user manager
# starts systemd-tmpfiles.
USER_TMPFILES_SETUP = ('--user', '--create', '--remove', '--boot')


def runtime_dir(root):
    """The runtime directory below ROOT that logind creates for an account with the uid of this process."""
    return os.path.join(root, "run/user", str(os.getuid()))


def ramdisk_root(all_settings, workdir):
    """A stand-in below WORKDIR for the root of an installed system that holds a home made from the skeleton.

    The files of RAMDISK_SETTINGS lie at their targets, as the installer
    copies them; a file missing from folders/ is left out, since the check
    of referenced files reports it. home/user is a copy of etc/skel, as
    useradd -m makes it, and runtime_dir() exists, as logind creates it
    for a session. The path it returns runs through no symbolic link, for
    the reason check_ramdisk_below_link gives.
    """
    root = os.path.realpath(tempfile.mkdtemp(dir=workdir))
    for s in all_settings:
        if s.get('name') not in RAMDISK_SETTINGS:
            continue
        for target in s.get('files', []):
            if os.path.isfile(repo_path(target)):
                path = os.path.join(root, target.lstrip("/"))
                os.makedirs(os.path.dirname(path), exist_ok=True)
                shutil.copy(repo_path(target), path)
    skeleton = os.path.join(root, SKELETON.lstrip("/"))
    home = os.path.join(root, SKELETON_USER_HOME)
    if os.path.isdir(skeleton):
        shutil.copytree(skeleton, home)
    else:
        os.makedirs(home)
    os.makedirs(runtime_dir(root), mode=0o700)
    return root


def user_tmpfiles_setup(tmpfiles, root, home):
    """Runs TMPFILES as systemd-tmpfiles-setup.service does in the user manager of an account whose home is HOME.

    The environment is built from scratch: HOME, XDG_RUNTIME_DIR from
    runtime_dir(), and XDG_CONFIG_DIRS and XDG_DATA_DIRS, which put
    ROOT/etc, ROOT/usr/local/share and ROOT/usr/share in the search path in
    place of /etc, /usr/local/share and /usr/share. Neither the rules of the
    machine running the checks nor the XDG_CONFIG_HOME and XDG_DATA_HOME of
    its user get in. --root would be the direct way, but systemd-tmpfiles
    refuses it together with --user: "Combination of --user and --root= is
    not supported."
    """
    env = {
        "PATH": os.environ.get("PATH", os.defpath),
        "HOME": home,
        "XDG_RUNTIME_DIR": runtime_dir(root),
        "XDG_CONFIG_DIRS": os.path.join(root, "etc"),
        "XDG_DATA_DIRS": os.path.join(root, "usr/local/share") + ":" + os.path.join(root, "usr/share"),
    }
    return subprocess.run([tmpfiles, *USER_TMPFILES_SETUP], env=env, stdin=subprocess.DEVNULL,
                          capture_output=True, text=True)


def tree_state(root):
    """Every path below ROOT, with its type and mode, and with the target of a symlink or the content of a file."""
    state = {}
    for directory, dirs, files in os.walk(root):
        for name in dirs + files:
            path = os.path.join(directory, name)
            info = os.lstat(path)
            if stat.S_ISLNK(info.st_mode):
                detail = os.readlink(path)
            elif stat.S_ISREG(info.st_mode):
                with open(path, "rb") as f:
                    detail = f.read()
            else:
                detail = None
            state[os.path.relpath(path, root)] = (stat.S_IFMT(info.st_mode), stat.S_IMODE(info.st_mode), detail)
    return state


def check_ramdisk_system_account(tmpfiles, all_settings, workdir, out_errors):
    """For an account whose home is /, such as greetd's greeter, the RAM disk rules create nothing and report nothing.

    From /usr/share/user-tmpfiles.d the rules ran in the user manager of
    every account. For the greeter the link became /RAMDisk, and each boot
    left "systemd-tmpfiles: Failed to create symlink '/RAMDisk': Permission
    denied" in the journal as an error; the - behind the type changes the
    exit status, not the message. The account is not created from the
    skeleton, so the rules must not reach it at all. Here the stand-in root
    is the home as well, as / is the greeter's, and it can be written to: a
    rule that reached the account leaves a path behind even where its run
    reports nothing, as when the checks run as root.
    """
    root = ramdisk_root(all_settings, workdir)
    before = tree_state(root)
    run = user_tmpfiles_setup(tmpfiles, root, root)
    after = tree_state(root)
    changed = sorted(path for path in before.keys() | after.keys() if before.get(path) != after.get(path))
    label = "systemd-tmpfiles in the user manager of an account whose home is /"
    if run.returncode != 0 or run.stdout or run.stderr:
        out_errors.append(f"❌ {label} exited with {run.returncode} and printed {run.stdout + run.stderr!r}; "
                          f"expected exit status 0 and no output.")
    if changed:
        out_errors.append(f"❌ {label} created or changed {', '.join(changed)}; expected nothing.")


def check_ramdisk_skeleton_user(tmpfiles, all_settings, workdir, out_errors):
    """A user whose home was made from the skeleton still gets the RAM disk, the link ~/RAMDisk to it and its bookmark.

    The RAM disk is the directory ramdisk in the runtime directory, with
    mode 0700. The bookmarks file of GTK, which Thunar shows in its side
    pane, holds the one line "file://HOME/RAMDisk RAM Disk". Moving the
    rules out of /usr/share/user-tmpfiles.d must not cost the user created
    by the installer any of this, and the rules still run without a word.
    """
    root = ramdisk_root(all_settings, workdir)
    home = os.path.join(root, SKELETON_USER_HOME)
    ramdisk = os.path.join(runtime_dir(root), "ramdisk")
    link = os.path.join(home, "RAMDisk")
    bookmarks = os.path.join(home, ".config/gtk-3.0/bookmarks")
    run = user_tmpfiles_setup(tmpfiles, root, home)
    label = "systemd-tmpfiles in the user manager of a user created from the skeleton"
    if run.returncode != 0 or run.stdout or run.stderr:
        out_errors.append(f"❌ {label} exited with {run.returncode} and printed {run.stdout + run.stderr!r}; "
                          f"expected exit status 0 and no output.")
    mode = stat.S_IMODE(os.lstat(ramdisk).st_mode) if os.path.isdir(ramdisk) else None
    if mode is None or os.path.islink(ramdisk):
        out_errors.append(f"❌ {label} created no directory {os.path.relpath(ramdisk, root)}.")
    elif mode != 0o700:
        out_errors.append(f"❌ {label} created {os.path.relpath(ramdisk, root)} with mode {mode:04o}; expected 0700.")
    target = os.readlink(link) if os.path.islink(link) else None
    if target != ramdisk:
        found = "as no link" if target is None else f"linking to {target}"
        out_errors.append(f"❌ {label} left {os.path.relpath(link, root)} {found}; expected a link to {ramdisk}.")
    expected = [f"file://{home}/RAMDisk RAM Disk"]
    if not os.path.isfile(bookmarks):
        out_errors.append(f"❌ {label} created no {os.path.relpath(bookmarks, root)}.")
    else:
        with open(bookmarks) as f:
            lines = f.read().splitlines()
        if lines != expected:
            out_errors.append(f"❌ {label} wrote {lines!r} to {os.path.relpath(bookmarks, root)}; "
                              f"expected {expected!r}.")


def check_ramdisk_below_link(tmpfiles, all_settings, workdir, out_errors):
    """Both checks above still pass where the path to the stand-in root runs through a symbolic link that is not root's.

    TMPDIR may name such a link, say ~/tmp leading to another disk, and the
    stand-in roots then lie below it. systemd-tmpfiles takes the step from
    an absolute link that an account other than root owns to / for an
    unsafe path transition and goes no further, and the - behind the type
    of each RAM disk rule makes it do so without a word and with exit
    status 0. The check of a user created from the skeleton then found
    neither the RAM disk nor ~/RAMDisk nor the bookmarks and blamed the
    rules, and the check of an account whose home is / let
    ditana-ramdisk.conf pass even from /usr/share/user-tmpfiles.d, as it
    could create nothing there either. So ramdisk_root() resolves the path.
    Here WORKDIR/link leads to WORKDIR/target, and it is absolute, since a
    relative link within one directory is a safe step. Where the checks
    run as root, as in CI, the link is handed to nobody, since a link of
    root's own is a safe step too, and where no other uid is mapped, as
    for uid 0 in a user namespace of one uid, the check skips. It runs only
    where both checks pass in WORKDIR itself, as it would otherwise just
    repeat what they found.
    """
    target = os.path.join(workdir, "target")
    link = os.path.join(workdir, "link")
    os.mkdir(target)
    os.symlink(os.path.abspath(target), link)
    if os.getuid() == 0:
        try:
            os.lchown(link, NOBODY, -1)
        except OSError:
            skip("other-account", "No account but root can own a symbolic link here: skipping the RAM disk checks "
                 "below a link that another account owns.", out_errors)
            return
    found = []
    check_ramdisk_system_account(tmpfiles, all_settings, link, found)
    check_ramdisk_skeleton_user(tmpfiles, all_settings, link, found)
    owner = os.lstat(link).st_uid
    out_errors.extend(f"❌ Below a symbolic link that uid {owner} owns, {line.removeprefix('❌ ')}" for line in found)


def check_ramdisk(all_settings, out_errors):
    """Applies the RAM disk rules of RAMDISK_SETTINGS with the real systemd-tmpfiles, and skips where it is missing.

    The checks find the rules through the files of these settings. Under
    another name a setting would ship nothing into the stand-in root, and
    the check for an account whose home is / would pass for want of rules
    rather than because they stay out of its reach, so a missing name is an
    error of its own.
    """
    names = {s.get('name') for s in all_settings}
    missing = [name for name in RAMDISK_SETTINGS if name not in names]
    if missing:
        out_errors.append(f"❌ No setting is named {' or '.join(missing)}, whose RAM disk rules these checks apply.")
        return
    tmpfiles = shutil.which("systemd-tmpfiles")
    if tmpfiles is None:
        skip("systemd-tmpfiles", "No systemd-tmpfiles here: skipping the checks of what the RAM disk rules create for "
             "an account whose home is / and for a user created from the skeleton.", out_errors)
        return
    with tempfile.TemporaryDirectory() as workdir:
        found = []
        check_ramdisk_system_account(tmpfiles, all_settings, workdir, found)
        check_ramdisk_skeleton_user(tmpfiles, all_settings, workdir, found)
        if not found:
            check_ramdisk_below_link(tmpfiles, all_settings, workdir, found)
        out_errors.extend(found)


print("🔍 Checking what the RAM disk rules create in the user manager of each account...")
ramdisk_errors = []
check_ramdisk(settings, ramdisk_errors)
for line in ramdisk_errors:
    print(line)
if ramdisk_errors:
    errors = True

# ---------------------------------------------------------------------------
# Each shell script included with Ditana must successfully pass shellcheck.
# ---------------------------------------------------------------------------

# Scripts that failed shellcheck at the time this check was introduced. The
# list can only decrease in size: all other shell scripts that are shipped
# must pass.
SHELLCHECK_PENDING = {
    "folders/etc/profile.d/ditana-bash-setup.sh",
    "folders/usr/lib/ditana/create-debug-user",
    "folders/usr/lib/ditana/flatpak-finalize",
    "folders/usr/lib/ditana/flatpak-show-progress",
    "folders/usr/lib/ditana/print-system-load",
    "folders/usr/lib/ditana/start-xfce4-greetd",
    "folders/usr/lib/ditana/xfce-first-login",
    "folders/usr/local/bin/brave",
}


def shell_interpreter(path):
    with open(path, "rb") as f:
        first = f.readline().decode(errors="replace").strip()
    if not first.startswith("#!"):
        return None
    words = first[2:].split()
    if words and os.path.basename(words[0]) == "env":
        words = words[1:]
    name = os.path.basename(words[0]) if words else None
    return name if name in ("sh", "bash") else None


print("🔍 Running shellcheck on shipped shell scripts...")
for path in sorted(referenced_files):
    if shell_interpreter(path) is None:
        continue
    ok, msg = run_check(["shellcheck", "--norc", "-s", "bash", "--enable=require-double-brackets",
                         "-e", "SC2129,SC1091,SC2219,SC2207,SC2145", path])
    if path in SHELLCHECK_PENDING:
        if ok:
            print(f"❌ {path} passes shellcheck now; remove it from SHELLCHECK_PENDING in validate-logic.py.")
            errors = True
    elif not ok:
        print(f"❌ Shellcheck failed for {path}:\n{msg.strip()}")
        errors = True

# ---------------------------------------------------------------------------
# Each setting that ships a Python script installs python alongside it.
# ---------------------------------------------------------------------------


def python_script(path):
    """Whether the file at PATH begins with a #! line that runs Python."""
    with open(path, "rb") as f:
        first = f.readline().decode(errors="replace")
    words = first[2:].split() if first.startswith("#!") else []
    if words and os.path.basename(words[0]) == "env":
        words = [w for w in words[1:] if not w.startswith("-")]
    return bool(words) and os.path.basename(words[0]).startswith("python")


def check_python_helpers(all_settings, out_errors):
    """A setting that ships a Python script installs python along with it.

    The workspace helper and the rename dialog are Python scripts. Today
    python reaches every Wayland session anyway: uwsm depends on it, and
    under niri so does niri-settings-git. But those are dependencies of
    other packages, which an update of them can drop, and a script whose
    interpreter is missing fails without a word on screen: waybar hides the
    module whose helper does not start, and a key bound to the rename
    dialog does nothing visible.
    """
    for s in all_settings:
        for target in s.get('files', []):
            path = repo_path(target)
            if os.path.isfile(path) and python_script(path) and "python" not in s.get('arch-packages', []):
                out_errors.append(f"❌ Setting '{s.get('name')}' ships the Python script {target} "
                                  f"without installing python.")


print("🔍 Checking that settings shipping Python scripts install python...")
python_errors = []
check_python_helpers(settings, python_errors)
for line in python_errors:
    print(line)
if python_errors:
    errors = True

# ---------------------------------------------------------------------------
# Files that pacman does not ever extract.
#
# A setting enters NoExtract patterns into /etc/pacman.conf by invoking
# /usr/lib/ditana/no-extract within its chroot-script, and ships the helper
# itself. block-localsearch utilizes it to keep localsearch from starting. The
# helper runs here on a copy of the [options] section from Arch's pacman.conf,
# situated within a temporary root, and the patterns are evaluated against the
# file lists of the current repositories. pacman compares a pattern using
# fnmatch(3) with no flags, permitting * to match a slash as well, against the
# path inside the package, which does not include a leading slash; it reads the
# list from the end, with the first matching pattern determining the outcome,
# and a leading ! turns that match into an exception.
# ---------------------------------------------------------------------------

NO_EXTRACT = '/usr/lib/ditana/no-extract'
BLOCK_LOCALSEARCH = 'block-localsearch'
LOCALSEARCH = 'localsearch'
LOCALSEARCH_ENTRY_DIRS = ('usr/lib/systemd/user/', 'usr/share/dbus-1/services/', 'etc/xdg/autostart/')
ARCH_MIRRORLIST = '/etc/pacman.d/mirrorlist'
DITANA_MIRRORLIST = '/etc/pacman.d/ditana-mirrorlist'
REPO_SYNC_TIMEOUT = 600

# The duration allowed for the processes of a pacman run to terminate following
# SIGTERM, and then again following SIGKILL.
STOP_GRACE = 5

# The environment variable that marks the processes associated with a single
# pacman run. Every process from the run inherits it, faked included.
RUN_MARKER = 'DITANA_VALIDATE_RUN'

# The [options] section found in /etc/pacman.conf, as provided by pacman 7.1.0.
ARCH_PACMAN_OPTIONS = """\
[options]
# The following paths are commented out with their default values listed.
# If you wish to use different paths, uncomment and update the paths.
#RootDir     = /
#DBPath      = /var/lib/pacman/
#CacheDir    = /var/cache/pacman/pkg/
#LogFile     = /var/log/pacman.log
#GPGDir      = /etc/pacman.d/gnupg/
#HookDir     = /etc/pacman.d/hooks/
HoldPkg     = pacman glibc
#XferCommand = /usr/bin/curl -L -C - -f -o %o %u
#XferCommand = /usr/bin/wget --passive-ftp -c -O %o %u
#CleanMethod = KeepInstalled
Architecture = auto

# Pacman won't upgrade packages listed in IgnorePkg and members of IgnoreGroup
#IgnorePkg   =
#IgnoreGroup =

#NoUpgrade   =
#NoExtract   =

# Misc options
#UseSyslog
#Color
#NoProgressBar
CheckSpace
#VerbosePkgLists
ParallelDownloads = 5
DownloadUser = alpm
#DisableSandboxFilesystem
#DisableSandboxSyscalls

# By default, pacman accepts packages signed by keys that its local keyring
# trusts (see pacman-key and its man page), as well as unsigned packages.
SigLevel    = Required DatabaseOptional
LocalFileSigLevel = Optional
#RemoteFileSigLevel = Required
"""
ARCH_NO_EXTRACT_LINE = "#NoExtract   =\n"

# The pacman.conf files that the helper runs on, each featuring the line below
# which the patterns are placed: Arch's default one, and another that lacks
# the line "#NoExtract", where they are positioned directly beneath
# "[options]".
NO_EXTRACT_CONFS = (
    ("Arch's pacman.conf", ARCH_PACMAN_OPTIONS, ARCH_NO_EXTRACT_LINE),
    ("a pacman.conf without #NoExtract", ARCH_PACMAN_OPTIONS.replace(ARCH_NO_EXTRACT_LINE, ""), "[options]\n"),
)

# What the local database of pacman inside the test root says each
# installed package owns, excluding directories. The first three entries
# detail the files they really install: the entry points of localsearch
# and the Wayland session of xfce4-session, which must be removed, and
# beside them the remaining files of the three, including the GSettings
# schema of localsearch, which must be preserved. The last one belongs to
# the calls made by the check itself.
NO_EXTRACT_PACKAGES = {
    "localsearch-3.12.0-1": [
        "etc/xdg/autostart/localsearch-3.desktop",
        "usr/bin/localsearch",
        "usr/lib/systemd/user/localsearch-3.service",
        "usr/lib/systemd/user/localsearch-control-3.service",
        "usr/lib/systemd/user/localsearch-writeback-3.service",
        "usr/share/dbus-1/services/org.freedesktop.LocalSearch3.Control.service",
        "usr/share/dbus-1/services/org.freedesktop.LocalSearch3.Writeback.service",
        "usr/share/dbus-1/services/org.freedesktop.LocalSearch3.service",
        "usr/share/dbus-1/services/org.freedesktop.Tracker3.Miner.Files.Control.service",
        "usr/share/dbus-1/services/org.freedesktop.Tracker3.Miner.Files.service",
        "usr/share/dbus-1/services/org.freedesktop.Tracker3.Writeback.service",
        "usr/share/glib-2.0/schemas/org.freedesktop.Tracker3.Miner.Files.gschema.xml",
    ],
    "tinysparql-3.12.0-1": [
        "usr/bin/tinysparql",
        "usr/lib/systemd/user/tinysparql-xdg-portal-3.service",
        "usr/share/dbus-1/services/org.freedesktop.portal.Tracker.service",
    ],
    "xfce4-session-4.20.4-1": [
        "usr/share/wayland-sessions/xfce-wayland.desktop",
        "usr/share/xsessions/xfce.desktop",
    ],
    "ditana-no-extract-test-1-1": [
        "usr/share/ditana-no-extract-test/drop",
        "usr/share/ditana-no-extract-test/keep",
        "usr/share/ditana-no-extract-test/overlap",
        "usr/share/ditana-no-extract-test/sub/dir/drop",
    ],
}

# Files present in the test root that were not installed by any package. A
# pattern matches each of these, but they must remain nonetheless.
NO_EXTRACT_UNOWNED = [
    "etc/xdg/autostart/localsearch-local.desktop",
    "usr/share/ditana-no-extract-test/unowned",
]

LIBC = ctypes.CDLL(None)
LIBC.fnmatch.argtypes = (ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int)
LIBC.fnmatch.restype = ctypes.c_int


def pacman_fnmatch(pattern, path):
    """fnmatch(3) without flags, the call pacman makes for a NoExtract pattern.

    Python's fnmatch module is no stand-in: it takes a backslash literally and
    knows neither [^...] nor [[:alpha:]].
    """
    return LIBC.fnmatch(os.fsencode(pattern), os.fsencode(path), 0) == 0


def pacman_glob(pattern):
    """PATTERN as pacman hands it to fnmatch: without a leading ! or backslash."""
    return pattern[1:] if pattern[:1] in ('!', '\\') else pattern


def noextract_blocks(patterns, path):
    """Whether pacman leaves PATH, which has no leading slash, out under the NoExtract list PATTERNS.

    This is _alpm_fnmatch_patterns of libalpm: the list is read from its end,
    the first pattern that matches decides, a leading ! makes it an
    exception, and a leading backslash is dropped, so that a pattern can
    begin with a literal !. It gave the same answer as
    alpm_option_match_noextract of libalpm 16 for every list of up to three
    patterns drawn from a pool covering these cases, on a set of paths.
    """
    for pattern in reversed(patterns):
        if pacman_fnmatch(pacman_glob(pattern), path):
            return not pattern.startswith('!')
    return False


def literal_prefix(pattern):
    """The part of PATTERN before its first wildcard or backslash.

    Every path the pattern matches begins with it, which lets a scan skip all
    other paths before it calls fnmatch.
    """
    return re.split(r'[*?\[\\]', pacman_glob(pattern), maxsplit=1)[0]


def no_extract_calls(all_settings, out_errors):
    """The calls of the NoExtract helper in the settings, as (setting, reason, patterns).

    A setting enters NoExtract patterns by a chroot-script line that calls the
    helper and does nothing else. The checks below know the patterns of a
    setting only through such calls, and they cannot tell whether another line
    enters any. So every other script line that names the helper or NoExtract
    is reported, whatever it does: patterns it entered would escape them.
    """
    calls = []
    for s in all_settings:
        name = s.get('name', 'unknown')
        for field in INTERP_LIST_FIELDS:
            for line in s.get(field, []):
                if NO_EXTRACT not in line and 'NoExtract' not in line:
                    continue
                try:
                    argv = shlex.split(line)
                except ValueError:
                    argv = []
                if (field == 'chroot-script' and not is_backtick_code(line.strip())
                        and len(argv) >= 3 and argv[0] == NO_EXTRACT):
                    calls.append((name, argv[1], argv[2:]))
                else:
                    out_errors.append(f"❌ Setting '{name}' -> {field} names NoExtract or {NO_EXTRACT} in a line "
                                      f"other than a chroot-script line '{NO_EXTRACT} REASON PATTERN...': {line!r}")
    return calls


def put_package_files(root):
    """Puts the files of NO_EXTRACT_PACKAGES on the disk below ROOT, as pacman extracts them."""
    for package, paths in NO_EXTRACT_PACKAGES.items():
        for path in paths:
            write_file(os.path.join(root, path), f"{package}\n")


def no_extract_root(workdir, conf):
    """A root holding CONF as its pacman.conf, and the files of NO_EXTRACT_PACKAGES and NO_EXTRACT_UNOWNED.

    The packages are in pacman's local database there, as pacman lists them:
    "%FILES%", then every directory with a trailing slash and every file, in
    sorted order, then an empty line.
    """
    root = tempfile.mkdtemp(dir=workdir)
    write_file(os.path.join(root, "etc/pacman.conf"), conf)
    for package, paths in NO_EXTRACT_PACKAGES.items():
        directories = {path[:i + 1] for path in paths for i, c in enumerate(path) if c == '/'}
        write_file(os.path.join(root, "var/lib/pacman/local", package, "files"),
                   "%FILES%\n" + "".join(f"{p}\n" for p in sorted(directories.union(paths))) + "\n")
    put_package_files(root)
    for path in NO_EXTRACT_UNOWNED:
        write_file(os.path.join(root, path), "no package\n")
    return root


def no_extract_orders(calls):
    """Every rotation of CALLS, forwards and backwards.

    Each call comes first and last at least once, and each pair of calls runs
    in both orders.
    """
    orders = []
    for sequence in (calls, calls[::-1]):
        for i in range(len(sequence)):
            order = sequence[i:] + sequence[:i]
            if order not in orders:
                orders.append(order)
    return orders


def expected_no_extract_conf(conf, anchor, order):
    """CONF after the calls in ORDER, and its NoExtract list, as the helper is to leave them.

    Each call enters the patterns that are not listed yet, below its reason
    and directly below the line ANCHOR, so that the latest call comes first; a
    call with nothing left to enter leaves the file alone.
    """
    entered, blocks = set(), []
    for _, reason, patterns in order:
        new = []
        for pattern in patterns:
            if pattern not in entered:
                entered.add(pattern)
                new.append(pattern)
        if new:
            blocks.insert(0, (reason, new))
    inserted = "".join(f"# {reason}\n" + "".join(f"NoExtract = {p}\n" for p in new) for reason, new in blocks)
    head, line, tail = conf.partition(anchor)
    return head + line + inserted + tail, [p for _, new in blocks for p in new]


def check_no_extract_helper(calls, workdir, out_errors):
    """The helper enters every pattern exactly once and deletes what packages have already extracted.

    Settings run their chroot-scripts in an order nobody guarantees, and
    several may enter the same pattern. The sed that xfce.kdl used before
    appended its line behind every line that began with NoExtract or
    #NoExtract, so n settings doing the same would have left 2^n - 1 lines.
    The calls of the settings run here together with two of the check's own,
    one that repeats one pattern from each call of the settings and one with
    an exception, in several orders and each order twice, on Arch's
    pacman.conf and on one without the line #NoExtract, where the helper
    enters the patterns below [options] instead of giving up. pacman.conf must
    then hold every pattern once, each call's new patterns below its reason; a
    file that an installed package put on the disk and that the list blocks
    must be gone, while every other file remains, also one that no package
    installed; and pacman-conf must read exactly these patterns back.

    Before the second round, the files of the packages are back on the disk,
    as a second pacstrap into the root would put them there: pacstrap
    extracts with the pacman.conf of the live system, so what the root's
    pacman.conf lists keeps nothing out. The helper has to remove them again,
    although every pattern is listed by then. A helper that deleted only the
    files of the patterns it entered itself would pass the first round all
    the same, since the first call that enters a pattern removes its files.
    """
    pacman_conf = shutil.which("pacman-conf")
    if pacman_conf is None:
        skip("pacman-conf", "No pacman-conf here: skipping the check that pacman reads what no-extract enters.",
             out_errors)
    own = [
        ("validate-logic.py, repeating", "Entered by validate-logic.py, mostly for the second time.",
         [patterns[0] for _, _, patterns in calls] + ["usr/share/ditana-no-extract-test/overlap*"]),
        ("validate-logic.py, with an exception", "Entered by validate-logic.py, with an exception.",
         ["usr/share/ditana-no-extract-test/*", "!usr/share/ditana-no-extract-test/keep"]),
    ]
    for conf_name, conf_text, anchor in NO_EXTRACT_CONFS:
        for order in no_extract_orders(calls + own):
            label = f"no-extract on {conf_name}, called by " + ", ".join(f"'{name}'" for name, _, _ in order)
            root = no_extract_root(workdir, conf_text)
            conf = os.path.join(root, "etc/pacman.conf")
            expected, listed = expected_no_extract_conf(conf_text, anchor, order)
            found = []
            for round_name in ("first", "second"):
                if round_name == "second":
                    put_package_files(root)
                for name, reason, patterns in order:
                    res = run_helper(NO_EXTRACT, [reason] + patterns, {"DITANA_ROOT": root})
                    if res is None:
                        found.append(f"❌ {label}: the call of '{name}' in the {round_name} round did not finish.")
                    elif res.returncode != 0 or res.stderr:
                        found.append(f"❌ {label}: the call of '{name}' in the {round_name} round ended with exit "
                                     f"status {res.returncode}: {res.stderr.decode(errors='replace').strip()!r}")
                with open(conf) as f:
                    content = f.read()
                if content != expected:
                    diff = "".join(difflib.unified_diff(expected.splitlines(True), content.splitlines(True),
                                                        "expected", "pacman.conf"))
                    found.append(f"❌ {label}: pacman.conf after the {round_name} round is not as expected:\n{diff}")
                for package, paths in NO_EXTRACT_PACKAGES.items():
                    for path in paths:
                        gone = not os.path.lexists(os.path.join(root, path))
                        if gone and not noextract_blocks(listed, path):
                            found.append(f"❌ {label}: after the {round_name} round, {path} of {package} is gone, "
                                         f"although the list does not block it.")
                        elif not gone and noextract_blocks(listed, path):
                            found.append(f"❌ {label}: after the {round_name} round, {path} of {package} is still "
                                         f"there, although the list blocks it.")
                for path in NO_EXTRACT_UNOWNED:
                    if not os.path.lexists(os.path.join(root, path)):
                        found.append(f"❌ {label}: after the {round_name} round, {path} is gone, although no "
                                     f"package installed it.")
            if pacman_conf is not None:
                res = subprocess.run([pacman_conf, "--config", conf, "NoExtract"], capture_output=True, text=True)
                if res.returncode != 0 or res.stderr or res.stdout.splitlines() != listed:
                    found.append(f"❌ {label}: pacman-conf reads NoExtract as {res.stdout.splitlines()!r} (exit "
                                 f"status {res.returncode}, {res.stderr.strip()!r}), expected {listed!r}.")
            if found:
                out_errors.extend(found)
                break


def check_no_extract_shipped(all_settings, calls, out_errors):
    """Every setting that calls the helper ships it in its files.

    The installer copies only the files of the settings that are enabled.
    While block-localsearch alone shipped the helper, XFCE could not be
    installed without block-localsearch: the chroot-script of install-xfce
    called a helper that was not there.
    """
    shipping = {s.get('name', 'unknown') for s in all_settings if NO_EXTRACT in s.get('files', [])}
    for name in sorted({name for name, _, _ in calls} - shipping):
        out_errors.append(f"❌ Setting '{name}' calls {NO_EXTRACT} in its chroot-script without shipping it in its "
                          f"files.")


def cache_home():
    """$XDG_CACHE_HOME, or ~/.cache where it is unset, empty or relative, as the XDG Base Directory Specification has it."""
    path = os.environ.get("XDG_CACHE_HOME", "")
    return path if os.path.isabs(path) else os.path.join(os.path.expanduser("~"), ".cache")


def package_databases_path():
    """Where the private copy of the file lists stays between runs."""
    return os.path.join(cache_home(), "ditana-config", "package-databases")


def check_package_databases_path(out_errors):
    """The private copy of the file lists stays in the cache directory of the user, below ditana-config.

    It has to outlast the run, so that pacman -Fy fetches only the lists that
    changed on the mirror: extra.files alone is some 50 MB. The XDG Base
    Directory Specification puts it below $XDG_CACHE_HOME, and below ~/.cache
    where that is unset, empty or a relative path, which the specification
    says to ignore.
    """
    default = os.path.join(os.path.expanduser("~"), ".cache", "ditana-config", "package-databases")
    saved = os.environ.get("XDG_CACHE_HOME")
    try:
        for value, expected in (("/var/tmp/cache", "/var/tmp/cache/ditana-config/package-databases"),
                                (None, default), ("", default), ("cache", default)):
            if value is None:
                os.environ.pop("XDG_CACHE_HOME", None)
            else:
                os.environ["XDG_CACHE_HOME"] = value
            if package_databases_path() != expected:
                described = "unset" if value is None else f"set to {value!r}"
                out_errors.append(f"❌ With XDG_CACHE_HOME {described}, the private copy of the file lists would "
                                  f"be kept in {package_databases_path()}, not in {expected}.")
    finally:
        if saved is None:
            os.environ.pop("XDG_CACHE_HOME", None)
        else:
            os.environ["XDG_CACHE_HOME"] = saved


def environment_pids(entry):
    """The processes whose environment holds ENTRY, NAME=VALUE as bytes."""
    pids = []
    for name in os.listdir("/proc"):
        if name.isdigit():
            try:
                with open(f"/proc/{name}/environ", "rb") as f:
                    if entry in f.read().split(b"\0"):
                        pids.append(int(name))
            except OSError:
                pass
    return pids


def process_names(entry):
    """The names of the processes whose environment holds ENTRY, sorted."""
    names = []
    for pid in environment_pids(entry):
        with contextlib.suppress(OSError), open(f"/proc/{pid}/comm") as f:
            names.append(f.read().strip())
    return sorted(names)


def stop_processes(entry):
    """Ends every process whose environment holds ENTRY; returns those that are still there after SIGTERM and SIGKILL.

    Each signal gets STOP_GRACE seconds, and a process that turns up in the
    meantime gets it too. SIGTERM comes first because faked removes its SysV
    message queues and semaphore only when it ends that way.
    """
    for sig in (signal.SIGTERM, signal.SIGKILL):
        signalled = set()
        deadline = time.monotonic() + STOP_GRACE
        while time.monotonic() < deadline:
            pids = set(environment_pids(entry))
            if not pids:
                return []
            for pid in pids - signalled:
                try:
                    os.kill(pid, sig)
                except ProcessLookupError:
                    pass
            signalled |= pids
            time.sleep(0.02)
    return environment_pids(entry)


def run_contained(argv, timeout, stderr_path, on_line=None):
    """Runs ARGV, hands each line of its output to ON_LINE, and returns its exit status, or None if it did not finish within TIMEOUT seconds.

    None of its processes outlives the call, whether ARGV ends, times out or
    the caller fails. Under fakeroot that takes more than ending ARGV:
    fakeroot is a shell script that starts faked as a daemon in a session of
    its own and has a trap end it on exit, and SIGKILL runs no trap. When its
    timeout expired, subprocess.run killed just the script, and faked and
    pacman went on running. So every process of the run carries RUN_MARKER in
    its environment, which they all inherit, and whatever still carries it at
    the end is stopped. The stderr of ARGV goes to STDERR_PATH.

    Raises RuntimeError if a process of the run is still there after SIGKILL.
    """
    marker = secrets.token_hex(8)
    entry = f"{RUN_MARKER}={marker}".encode()
    expired = threading.Event()

    def expire():
        expired.set()
        stop_processes(entry)

    with open(stderr_path, "wb") as stderr:
        proc = subprocess.Popen(argv, env=dict(os.environ, **{RUN_MARKER: marker}), stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=stderr)
    timer = threading.Timer(timeout, expire)
    timer.start()
    try:
        for line in proc.stdout:
            if on_line is not None:
                on_line(line)
    finally:
        timer.cancel()
        timer.join()
        left = stop_processes(entry)
        proc.stdout.close()
        if not left:
            proc.wait()
    if left:
        raise RuntimeError(f"processes {left} of {shlex.join(argv)} are still there after SIGKILL")
    return None if expired.is_set() else proc.returncode


def last_line(path, fallback):
    """The last line of the file at PATH that is not blank, or FALLBACK."""
    with open(path, errors="replace") as f:
        lines = f.read().strip().splitlines()
    return lines[-1] if lines else fallback


def file_lists(dbpath, repos, workdir, on_entry, timeout=REPO_SYNC_TIMEOUT):
    """Brings the private copy of the file lists at DBPATH up to date and hands each line of pacman -Fl to ON_ENTRY.

    REPOS maps each repository to the line that names its servers, "Include
    = MIRRORLIST" or "Server = URL". ON_ENTRY gets each line of pacman -Fl
    --machinereadable as bytes: repository, package, version and path,
    separated by NUL. The file lists of the system are no basis: only root
    refreshes them, with pacman -Fy, and they may be weeks old. fakeroot lets
    pacman -Fy refresh a copy of its own without root. pacman -Fl reads
    nothing else, so the package databases of -Sy are not fetched. Nothing is
    installed from the copy, so it checks no signatures, which would need the
    keyring of root.

    The copy stays at DBPATH between runs, and pacman fetches a list only if
    it changed on the mirror. A mirror can answer with something that is no
    database at all, such as the login page of a hotel's network with status
    200: pacman -Fy keeps it, and pacman -Fl exits 0, lists nothing for that
    repository and says "Unrecognized archive format" on stderr only. So
    every repository has to turn up in the listing, and the list of one that
    does not is deleted. Kept, it would be all that pacman reads from then
    on, since the mirror answers 304 to a list that is newer than its own.

    Runs that share DBPATH take turns. A pacman stopped by a timeout leaves
    its lock db.lck behind, and every later -Fy would fail on it; while this
    run holds its own lock, no other pacman uses the copy, so a db.lck found
    then is stale.

    Returns None, or why there is no usable copy. Raises RuntimeError if
    pacman -Fl fails in another way.
    """
    try:
        os.makedirs(dbpath, exist_ok=True)
        lock = open(os.path.join(dbpath, "validate-logic.lock"), "w")
    except OSError as e:
        return f"no private copy of the file lists can be kept in {dbpath} ({e.strerror})"
    with lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        with contextlib.suppress(FileNotFoundError):
            os.remove(os.path.join(dbpath, "db.lck"))
        config = os.path.join(workdir, "file-lists.conf")
        write_file(config, "[options]\nArchitecture = auto\nSigLevel = Never\n"
                   + "".join(f"\n[{repo}]\n{servers}\n" for repo, servers in repos.items()))
        stderr_path = os.path.join(workdir, "pacman.stderr")
        pacman = ["pacman", "--dbpath", dbpath, "--config", config]
        status = run_contained(["fakeroot", "--"] + pacman + ["--logfile", "/dev/null", "--disable-sandbox", "-Fy"],
                               timeout, stderr_path)
        if status is None:
            return f"pacman -Fy did not finish within {timeout} s"
        if status != 0:
            return f"pacman -Fy failed ({last_line(stderr_path, f'exit status {status}')})"
        listed = set()
        current = None

        def entry(line):
            nonlocal current
            if current is None or not line.startswith(current):
                current = line.partition(b"\0")[0] + b"\0"
                listed.add(os.fsdecode(current[:-1]))
            on_entry(line)

        status = run_contained(pacman + ["-Fl", "--machinereadable"], timeout, stderr_path, entry)
        if status is None:
            raise RuntimeError(f"pacman -Fl did not finish within {timeout} s")
        if status != 0:
            raise RuntimeError(f"pacman -Fl failed ({last_line(stderr_path, f'exit status {status}')})")
        unreadable = [repo for repo in repos if repo not in listed]
        for repo in unreadable:
            with contextlib.suppress(FileNotFoundError):
                os.remove(os.path.join(dbpath, "sync", f"{repo}.files"))
        if unreadable:
            return (f"pacman cannot read the file lists of {', '.join(unreadable)} "
                    f"({last_line(stderr_path, 'it lists nothing for them')}), which are discarded")
    return None


class StandInMirrorHandler(http.server.SimpleHTTPRequestHandler):
    """Answers a request of pacman as the mode of its StandInMirror says."""

    PORTAL = b"<!DOCTYPE html>\n<html><body><form>Please log in to use this network.</form></body></html>\n"

    def __init__(self, request, client_address, server):
        super().__init__(request, client_address, server, directory=server.directory)

    def do_GET(self):
        mirror = self.server
        mirror.processes.append(process_names(mirror.probe))
        if mirror.mode == "serve":
            super().do_GET()
        elif mirror.mode == "portal":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(self.PORTAL)))
            self.end_headers()
            self.wfile.write(self.PORTAL)
        elif mirror.mode == "stall":
            mirror.released.wait()
        else:
            self.send_error(404)

    def log_request(self, code="-", size="-"):
        self.server.requests.append((self.path, int(code)))

    def log_message(self, format, *args):
        pass


class StandInMirror(http.server.ThreadingHTTPServer):
    """A mirror on 127.0.0.1 that pacman -Fy reaches over HTTP, answering as its mode says.

    "serve" serves the files in DIRECTORY and answers If-Modified-Since as a
    mirror does; "portal" answers every request with the login page of a
    network and status 200; "stall" answers nothing until the mirror is
    closed; "missing" answers 404. requests holds the path and the status of
    every answer, and processes, for every request, the names of the
    processes whose environment held the entry PROBE at that moment.
    """

    daemon_threads = True

    def __init__(self, directory, probe):
        super().__init__(("127.0.0.1", 0), StandInMirrorHandler)
        self.directory, self.probe, self.mode = directory, probe, "serve"
        self.requests, self.processes = [], []
        self.released = threading.Event()
        self.url = f"http://127.0.0.1:{self.server_address[1]}"
        threading.Thread(target=self.serve_forever, daemon=True).start()

    def __exit__(self, *exc):
        self.released.set()
        self.shutdown()
        self.server_close()


@contextlib.contextmanager
def probe_entry():
    """An entry NAME=VALUE, as bytes, in the environment of every process started meanwhile.

    It tells the processes of one run apart from all others, independently of
    the marker that run_contained gives them.
    """
    name, value = "DITANA_VALIDATE_PROBE", secrets.token_hex(8)
    os.environ[name] = value
    try:
        yield f"{name}={value}".encode()
    finally:
        del os.environ[name]


def write_file_list_database(path, packages, mtime):
    """A database of file lists such as pacman -Fy fetches, at PATH and with the modification time MTIME.

    It is a tar archive compressed with gzip that holds NAME-1-1/desc and
    NAME-1-1/files for each NAME in PACKAGES, which maps it to its paths.
    """
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with tarfile.open(path, "w:gz") as tar:
        for name, paths in packages.items():
            for member, text in (("desc", f"%NAME%\n{name}\n\n%VERSION%\n1-1\n\n"),
                                 ("files", "%FILES%\n" + "".join(f"{p}\n" for p in paths) + "\n")):
                data = text.encode()
                info = tarfile.TarInfo(f"{name}-1-1/{member}")
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
    os.utime(path, (mtime, mtime))


# The timeout that a run against a stand-in mirror that provides no response
# receives.
STAND_IN_TIMEOUT = 2


def stand_in_file_lists(workdir, mirror, dbpath, timeout=REPO_SYNC_TIMEOUT):
    """file_lists for a repository core on MIRROR: its problem, and the (package, path) pairs it listed."""
    lines = []
    try:
        problem = file_lists(dbpath, {"core": f"Server = {mirror.url}"}, workdir, lines.append, timeout)
    except RuntimeError as e:
        problem = str(e)
    return problem, sorted(tuple(os.fsdecode(line.rstrip(b"\n")).split("\0")[1::2]) for line in lines)


def check_file_lists_keep_copy(workdir, out_errors):
    """The private copy stays between runs, and pacman fetches a list again only when it changed on the mirror.

    A fresh copy on every run fetched all lists every time, extra.files alone
    some 50 MB. The first run against a stand-in mirror has to fetch
    core.files, the second must get 304 for it, and once the list on the
    mirror has changed, the third has to fetch and read the new one.
    """
    mirror_dir, dbpath = os.path.join(workdir, "keep-mirror"), os.path.join(workdir, "keep-copy")
    database = os.path.join(mirror_dir, "core.files")
    write_file_list_database(database, {"probe": ["usr/share/probe/one"]}, 1_700_000_000)
    with probe_entry() as probe, StandInMirror(mirror_dir, probe) as mirror:
        for run, status, listing in (("first", 200, [("probe", "usr/share/probe/one")]),
                                     ("second", 304, [("probe", "usr/share/probe/one")]),
                                     ("third", 200, [("probe", "usr/share/probe/two")])):
            if run == "third":
                write_file_list_database(database, {"probe": ["usr/share/probe/two"]}, 1_700_000_100)
            before = len(mirror.requests)
            problem, listed = stand_in_file_lists(workdir, mirror, dbpath)
            answers = mirror.requests[before:]
            if problem is not None or listed != listing or answers != [("/core.files", status)]:
                out_errors.append(f"❌ file_lists, {run} run against a mirror: returned {problem!r} and listed "
                                  f"{listed!r} after the answers {answers!r}, expected None and {listing!r} after "
                                  f"{[('/core.files', status)]!r}.")
                return


def check_file_lists_unreadable(workdir, out_errors):
    """A file list that pacman cannot read ends the checks against the repositories with a skip, and is discarded.

    A hotel's network answers every request with its login page until one
    logs in, and with status 200. pacman -Fy keeps the page as core.files,
    and pacman -Fl exits 0 and lists nothing, with "Unrecognized archive
    format" on stderr only; the checks reported every pattern as matching
    nothing then. The page is newer than the mirror's list, so kept, it would
    be all that pacman reads from then on, the mirror answering 304. The run
    against the portal has to name the problem and leave no core.files
    behind, and the next one, against the mirror, has to read its list.
    """
    mirror_dir, dbpath = os.path.join(workdir, "portal-mirror"), os.path.join(workdir, "portal-copy")
    write_file_list_database(os.path.join(mirror_dir, "core.files"), {"probe": ["usr/share/probe/one"]},
                             1_700_000_000)
    with probe_entry() as probe, StandInMirror(mirror_dir, probe) as mirror:
        mirror.mode = "portal"
        problem, listed = stand_in_file_lists(workdir, mirror, dbpath)
        if problem is None or not problem.startswith("pacman cannot read the file lists of core "):
            out_errors.append(f"❌ file_lists against a login page: returned {problem!r} and listed {listed!r}, "
                              f"not that pacman cannot read the file lists of core.")
        if os.path.exists(os.path.join(dbpath, "sync", "core.files")):
            out_errors.append("❌ file_lists against a login page kept the page as core.files.")
        mirror.mode = "serve"
        problem, listed = stand_in_file_lists(workdir, mirror, dbpath)
        if problem is not None or listed != [("probe", "usr/share/probe/one")]:
            out_errors.append(f"❌ file_lists against a mirror, after a login page: returned {problem!r} and "
                              f"listed {listed!r}, expected None and the list of the mirror.")


def check_file_lists_stop_after_timeout(workdir, out_errors):
    """No process of a run outlives its timeout, and the next run works.

    When its timeout expired, subprocess.run killed just the fakeroot script:
    faked, which fakeroot starts as a daemon in a session of its own, and
    pacman went on running, and pacman's lock was left behind, on which every
    later -Fy failed. Here the stand-in mirror answers nothing. While it
    waits, fakeroot, faked and pacman have to be there, and once file_lists
    has given up, none of them may be. The next run, against a mirror that
    answers, has to read its list.
    """
    mirror_dir, dbpath = os.path.join(workdir, "stall-mirror"), os.path.join(workdir, "stall-copy")
    write_file_list_database(os.path.join(mirror_dir, "core.files"), {"probe": ["usr/share/probe/one"]},
                             1_700_000_000)
    with probe_entry() as probe, StandInMirror(mirror_dir, probe) as mirror:
        mirror.mode = "stall"
        problem, _ = stand_in_file_lists(workdir, mirror, dbpath, STAND_IN_TIMEOUT)
        during, after = mirror.processes[:1], process_names(probe)
        if problem != f"pacman -Fy did not finish within {STAND_IN_TIMEOUT} s":
            out_errors.append(f"❌ file_lists against a mirror that answers nothing returned {problem!r}.")
        if not during or not {"fakeroot", "faked", "pacman"} <= set(during[0]):
            out_errors.append(f"❌ file_lists against a mirror that answers nothing: while the mirror waited, "
                              f"the run had the processes {during!r}, not fakeroot, faked and pacman.")
        if after:
            out_errors.append(f"❌ file_lists against a mirror that answers nothing left {after!r} running after "
                              f"its timeout.")
        mirror.released.set()
        mirror.mode = "serve"
        problem, listed = stand_in_file_lists(workdir, mirror, dbpath)
        if problem is not None or listed != [("probe", "usr/share/probe/one")]:
            out_errors.append(f"❌ file_lists against a mirror, after a timeout: returned {problem!r} and listed "
                              f"{listed!r}, expected None and the list of the mirror.")


def check_file_lists_stop_after_failure(workdir, out_errors):
    """No process of a run outlives a failing pacman -Fy.

    When pacman fails, fakeroot's trap sends faked a SIGTERM and exits
    without waiting for faked to end. Here the stand-in mirror answers 404,
    so pacman -Fy fails, and once file_lists has returned, nothing of the run
    may be left.
    """
    mirror_dir, dbpath = os.path.join(workdir, "missing-mirror"), os.path.join(workdir, "missing-copy")
    os.makedirs(mirror_dir)
    with probe_entry() as probe, StandInMirror(mirror_dir, probe) as mirror:
        mirror.mode = "missing"
        problem, _ = stand_in_file_lists(workdir, mirror, dbpath)
        during, after = mirror.processes[:1], process_names(probe)
        if problem is None or not problem.startswith("pacman -Fy failed ("):
            out_errors.append(f"❌ file_lists against a mirror that answers 404 returned {problem!r}.")
        if not during or not {"fakeroot", "faked", "pacman"} <= set(during[0]):
            out_errors.append(f"❌ file_lists against a mirror that answers 404: while the mirror answered, the "
                              f"run had the processes {during!r}, not fakeroot, faked and pacman.")
        if after:
            out_errors.append(f"❌ file_lists against a mirror that answers 404 left {after!r} running.")


class ReaderFailure(Exception):
    """What the reader of the listing raises in check_file_lists_stop_after_exception."""


def check_file_lists_stop_after_exception(workdir, out_errors):
    """No process of a run outlives an exception in the code that reads its output.

    A bug in the code that reads the listing raises while pacman -Fl is still
    writing it, and pacman then blocks on the full pipe for as long as
    validate-logic.py runs. Here the reader raises at the first line of a
    listing larger than a pipe holds, while pacman is still there; once the
    exception has left file_lists, nothing of the run may be left.
    """
    mirror_dir, dbpath = os.path.join(workdir, "raise-mirror"), os.path.join(workdir, "raise-copy")
    write_file_list_database(os.path.join(mirror_dir, "core.files"),
                             {"probe": [f"usr/share/probe/file-{i:05}" for i in range(5000)]}, 1_700_000_000)
    with probe_entry() as probe, StandInMirror(mirror_dir, probe) as mirror:
        during = []

        def fail(line):
            during.extend(process_names(probe))
            raise ReaderFailure(line)

        try:
            problem = file_lists(dbpath, {"core": f"Server = {mirror.url}"}, workdir, fail)
        except ReaderFailure:
            pass
        else:
            out_errors.append(f"❌ file_lists did not pass on the exception of its reader, and returned {problem!r}.")
        after = process_names(probe)
        if "pacman" not in during:
            out_errors.append(f"❌ file_lists: when its reader raised, the run had the processes {during!r}, "
                              f"without pacman.")
        if after:
            out_errors.append(f"❌ file_lists left {after!r} running after its reader raised an exception.")


def repository_matches(dbpath, repos, patterns, workdir):
    """What each of PATTERNS matches in REPOS, and the files that localsearch installs there.

    check_no_extract passes the repositories that a Ditana system installs
    from: core, extra and multilib, and the Ditana repository where its
    mirrorlist is installed. A single pacman -Fl lists every file of every
    package. pacman -Fx would
    go through all of them again for each pattern, and it compares with a
    regular expression that ignores case. Only a path that begins with the
    literal part of a pattern, or a file of localsearch, goes on to fnmatch.

    Returns ({pattern: {package: first path it matches}}, [files of localsearch], None),
    or (None, None, reason) where file_lists has no usable copy.
    """
    prefixes = tuple({os.fsencode(literal_prefix(p)) for p in patterns})
    package_field = b"\0" + os.fsencode(LOCALSEARCH) + b"\0"
    hits = {pattern: {} for pattern in patterns}
    localsearch_files = []

    def entry(line):
        of_localsearch = package_field in line
        if not of_localsearch and not line.rpartition(b"\0")[2].startswith(prefixes):
            return
        _, package, _, path = os.fsdecode(line.rstrip(b"\n")).split("\0")
        if of_localsearch and not path.endswith("/"):
            localsearch_files.append(path)
        for pattern, packages in hits.items():
            if package not in packages and pacman_fnmatch(pacman_glob(pattern), path):
                packages[package] = path

    problem = file_lists(dbpath, repos, workdir, entry)
    if problem is not None:
        return None, None, problem
    return hits, localsearch_files, None


def check_localsearch_entry_points(patterns, files, out_errors):
    """Every file through which localsearch starts matches a pattern of block-localsearch.

    localsearch has to stay installed: nautilus, gnome-music and gnome-photos
    depend on it, and nautilus aborts without its GSettings schema. So only
    the files it starts from are blocked, every file the package installs
    below usr/lib/systemd/user/, usr/share/dbus-1/services/ and
    etc/xdg/autostart/. Upstream has renamed them before: tracker-miner-fs-3
    became localsearch-3 in 3.8, without an alias. A new name or a new entry
    point would let localsearch run again without anything failing.
    """
    entry_points = [path for path in files if path.startswith(LOCALSEARCH_ENTRY_DIRS)]
    if not patterns:
        out_errors.append(f"❌ Setting '{BLOCK_LOCALSEARCH}' does not call {NO_EXTRACT}.")
        return
    if not entry_points:
        out_errors.append(f"❌ {LOCALSEARCH} installs nothing below {', '.join(LOCALSEARCH_ENTRY_DIRS)} in the "
                          f"repositories, or is gone from them: '{BLOCK_LOCALSEARCH}' needs a look.")
        return
    for path in entry_points:
        if not noextract_blocks(patterns, path):
            out_errors.append(f"❌ {LOCALSEARCH} installs {path}, which no pattern of '{BLOCK_LOCALSEARCH}' "
                              f"blocks: localsearch can start through it.")


def check_localsearch_spares_other_files(patterns, files, out_errors):
    """No pattern of block-localsearch matches a file of localsearch outside the directories it starts from.

    localsearch stays installed because nautilus aborts without its GSettings
    schema, usr/share/glib-2.0/schemas/org.freedesktop.Tracker3.Miner.Files.gschema.xml.
    A pattern that reaches beyond usr/lib/systemd/user/,
    usr/share/dbus-1/services/ and etc/xdg/autostart/ can block it:
    usr/share/*org.freedesktop.Tracker3.Miner* would, and the other checks
    would pass all the same, since that pattern still covers the entry points
    it was written for and matches files of localsearch alone. An exception
    blocks nothing and is left out.
    """
    for pattern in patterns:
        if pattern.startswith("!"):
            continue
        for path in files:
            if not path.startswith(LOCALSEARCH_ENTRY_DIRS) and pacman_fnmatch(pacman_glob(pattern), path):
                out_errors.append(f"❌ NoExtract pattern '{pattern}' of '{BLOCK_LOCALSEARCH}' matches {path} of "
                                  f"{LOCALSEARCH}, outside the directories it starts from: it blocks more than "
                                  f"its entry points.")


def check_no_extract_patterns_one_package(calls, hits, out_errors):
    """Every NoExtract pattern a setting enters matches files of exactly one package in the current repositories.

    A pattern that matches nothing is dead: the file it was written for has
    been renamed or dropped, and it blocks nothing any more. One that matches
    files of several packages blocks something it was not meant for:
    usr/lib/localsearch-* would also have taken localsearch-testutils apart.
    """
    for name, _, patterns in calls:
        for pattern in patterns:
            packages = hits[pattern]
            if not packages:
                out_errors.append(f"❌ NoExtract pattern '{pattern}' of '{name}' matches no file in the "
                                  f"repositories: it blocks nothing.")
            elif len(packages) > 1:
                listing = ", ".join(f"{package} ({path})" for package, path in sorted(packages.items()))
                out_errors.append(f"❌ NoExtract pattern '{pattern}' of '{name}' matches files of "
                                  f"{len(packages)} packages, {listing}: it blocks more than it is meant to.")


def check_no_extract(all_settings, out_errors):
    calls = no_extract_calls(all_settings, out_errors)
    check_no_extract_shipped(all_settings, calls, out_errors)
    check_package_databases_path(out_errors)
    with tempfile.TemporaryDirectory() as workdir:
        check_no_extract_helper(calls, workdir, out_errors)
        missing = [tool for tool in ("pacman", "fakeroot") if shutil.which(tool) is None]
        if missing:
            skip("pacman-fakeroot", f"No {' and no '.join(missing)} here: skipping the checks of the private copy of "
                 f"the file lists and of the NoExtract patterns against the repositories.", out_errors)
            return
        check_file_lists_keep_copy(workdir, out_errors)
        check_file_lists_unreadable(workdir, out_errors)
        check_file_lists_stop_after_timeout(workdir, out_errors)
        check_file_lists_stop_after_failure(workdir, out_errors)
        check_file_lists_stop_after_exception(workdir, out_errors)
        repos = {repo: f"Include = {ARCH_MIRRORLIST}" for repo in ("core", "extra", "multilib")}
        if os.path.isfile(DITANA_MIRRORLIST):
            repos["ditana"] = f"Include = {DITANA_MIRRORLIST}"
        else:
            skip("ditana-mirrorlist", f"No {DITANA_MIRRORLIST} here: comparing the NoExtract patterns with the Arch "
                 f"repositories only.", out_errors)
        patterns = list(dict.fromkeys(p for _, _, ps in calls for p in ps))
        try:
            hits, files, problem = repository_matches(package_databases_path(), repos, patterns, workdir)
        except RuntimeError as e:
            out_errors.append(f"❌ {e}")
            return
        if problem is not None:
            skip("file-lists", f"{problem}: skipping the checks of the NoExtract patterns against the repositories.",
                 out_errors)
            return
        own = [p for name, _, ps in calls if name == BLOCK_LOCALSEARCH for p in ps]
        check_localsearch_entry_points(own, files, out_errors)
        check_localsearch_spares_other_files(own, files, out_errors)
        check_no_extract_patterns_one_package(calls, hits, out_errors)


print("🔍 Checking the NoExtract patterns that settings enter...")
no_extract_errors = []
check_no_extract(settings, no_extract_errors)
for line in no_extract_errors:
    print(line)
if no_extract_errors:
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

print(f"🔍 Checking that the skips {EXPECTED_SKIPS} expects took place...")
for name in stale_expected_skips(skipped_names):
    print(f"❌ {EXPECTED_SKIPS} expects the skip {name}, but no check skipped as {name}. In CI an expected skip "
          f"that does not take place is an error, so that no stale entry stays in the list: remove {name} from it.")
    errors = True

if errors:
    print("❌ Validation failed!")
    sys.exit(1)
else:
    print("✅ All checks passed successfully!")
