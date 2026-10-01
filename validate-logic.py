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
import threading
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
        print("ℹ️  No systemd user manager here: skipping the scope checks of launch.")

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
        print("ℹ️  No German locale here: skipping the locale checks of waybar-io-pressure.")
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
        print("ℹ️  No German locale here: skipping the locale checks of the arguments of waybar-io-pressure.")
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
