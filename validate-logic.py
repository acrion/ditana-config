#!/usr/bin/env python3
import json
import os
import re
import secrets
import shlex
import signal
import stat
import subprocess
import sys
import shutil
import tempfile
import time
import xml.etree.ElementTree as ET

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
    the config, so that it exists wherever the button does.
    """
    for module, key, command in waybar_user_commands(bar_config):
        argv = shlex.split(command)
        if argv[0] != LAUNCH or len(argv) < 2:
            out_errors.append(
                f"❌ waybar '{module}' {key} runs {command!r} directly. Start it through "
                f"'{LAUNCH} ...' so that it survives a reload or restart of waybar.")
            continue
        for program in argv[:2]:
            if program.startswith("/") and program not in shipped_files:
                out_errors.append(
                    f"❌ waybar '{module}' {key} runs {program}, which the setting installing "
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
        print("ℹ️  No block device node in /dev here: skipping the block-device case of open-disks.")
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
    """Runs restart_waybar from waybar-display-scale against stubs that record each call."""
    with open(repo_path(WAYBAR_DISPLAY_SCALE)) as f:
        match = re.search(r"^restart_waybar\(\) \{$.*?^\}$", f.read(), re.M | re.S)
    if match is None:
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
    res = subprocess.run(["bash", "-c", stubs + match.group(0) + '\nrestart_waybar\nprintf "%s\\n" "${calls[@]}"'],
                         capture_output=True, text=True)
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
            out_errors.append(f"❌ {WAYBAR_DISPLAY_SCALE} has no restart_waybar() to check.")
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
            check_disk_opens_what_it_shows(bar_config, waybar_errors)

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
        print("ℹ️  No systemd user manager here: skipping the scope checks of launch.")

    check_open_disks(workdir, waybar_errors)
    check_open_disks_reports_failures(workdir, waybar_errors)

check_display_scale_respawn(waybar_errors)
check_display_scale_restarts(waybar_errors)

for line in waybar_errors:
    print(line)
if waybar_errors:
    errors = True

print("🔍 Checking Thunar custom actions...")
thunar_errors = []
check_thunar_actions(settings, thunar_errors)
for line in thunar_errors:
    print(line)
if thunar_errors:
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
