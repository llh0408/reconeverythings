#!/usr/bin/env bash
# ReconEveryThings first-time installer.
#
# Creates the Python environment, installs the CLI and MCP server, prepares
# .env, copies the Agent Skill into every detected harness, and registers the
# MCP server with each harness's native configuration format.
echo -e "\033[38;2;255;215;0m   ___                    ____                  __  __   _            \n  / _ \___ _______  ___  / __/  _____ ______ __/ /_/ /  (_)__  ___ ____\n / , _/ -_) __/ _ \/ _ \/ _/| |/ / -_) __/ // / __/ _ \/ / _ \/ _ \`(_-<\n/_/|_|\__/\__/\___/_//_/___/|___/\__/_/  \_, /\__/_//_/_/_//_/\_, /___/\n                                        /___/       @llh0408 /___/ \n \033[0m"
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$SCRIPT_DIR"
VENV_DIR="${REC_VENV_DIR:-$PROJECT_DIR/.venv}"
SKILL_SRC="$PROJECT_DIR/agent_skill"
MCP_NAME="reconeverythings"
SKILL_NAME="reconeverythings"
SUPPORTED="qoder claude codex dsh gemini opencode cursor copilot"

HARNESSES="auto"
DO_TOOLS=1
FORCE=0
NO_BACKUP=0
DO_VENV=1
DO_ENV=1
DO_SKILL=1
DO_MCP=1
DO_LINK=1
LOCAL_BIN="${REC_BIN_DIR:-$HOME/.local/bin}"

say() {
    printf '[install] %s\n' "$*"
}

warn() {
    printf '[install] warning: %s\n' "$*" >&2
}

die() {
    printf '[install] error: %s\n' "$*" >&2
    exit 1
}

usage() {
    cat <<'USAGE'
Usage: bash install.sh [options]

Options:
  --harness LIST       Harnesses to configure: auto, all, or a comma-separated
                       list of qoder, claude, codex, dsh, gemini, opencode,
                       cursor, copilot. Default: auto.
  --with-tools         Accepted for compatibility; tools are installed by
                       default.
  --skip-tools         Do not install the Go reconnaissance tools. This is
                       subfinder, httpx, naabu, katana, gau, and webanalyze;
                       Go and network access are required.
  --skip-venv          Do not create or install the Python environment.
  --skip-env           Do not create .env from .env.example.
  --skip-skill         Do not install the Agent Skill.
  --skip-mcp           Do not register the MCP server.
  --no-link            Do not link recn and rec-mcp into ~/.local/bin.
  --no-backup          Do not write .reconeverythings.bak config backups.
  --force              Replace foreign skill directories with the same name.
  -h, --help           Show this help.

Environment:
  PYTHON               Python 3.10+ interpreter. Default: python3.
  REC_VENV_DIR         Virtual environment path. Default: ./.venv.
  REC_BIN_DIR          Directory for user-level command links.
                       Default: ~/.local/bin.
  CODEX_HOME           Codex config directory. Default: ~/.codex.
  DSH_HOME             DeepSeek Harness config directory. Default: ~/.dsh.
  XDG_CONFIG_HOME      Base for OpenCode config. Default: ~/.config.

Notes:
  The installer also installs wafw00f into the virtual environment when it is
  missing. nmap is optional and is only used for the WAF fallback check.
  whatweb is expected from the system package manager. webanalyze technology
  definitions are downloaded to ~/.local/share/reconeverythings/.
USAGE
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --harness)
            [ "$#" -ge 2 ] || die "--harness requires a value"
            HARNESSES="$2"
            shift 2
            ;;
        --harness=*)
            HARNESSES="${1#*=}"
            shift
            ;;
        --with-tools)
            DO_TOOLS=1
            shift
            ;;
        --skip-tools)
            DO_TOOLS=0
            shift
            ;;
        --skip-venv)
            DO_VENV=0
            shift
            ;;
        --skip-env)
            DO_ENV=0
            shift
            ;;
        --skip-skill)
            DO_SKILL=0
            shift
            ;;
        --skip-mcp)
            DO_MCP=0
            shift
            ;;
        --no-link)
            DO_LINK=0
            shift
            ;;
        --no-backup)
            NO_BACKUP=1
            shift
            ;;
        --force)
            FORCE=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            usage >&2
            die "unknown option: $1"
            ;;
    esac
done

HARNESSES="$(printf '%s' "$HARNESSES" | tr ',' ' ')"
for harness in $HARNESSES; do
    case "$harness" in
        auto|all) ;;
        qoder|claude|codex|dsh|gemini|opencode|cursor|copilot) ;;
        *) die "unsupported harness: $harness" ;;
    esac
done

SYS_PYTHON="${PYTHON:-python3}"
command -v "$SYS_PYTHON" >/dev/null 2>&1 || die "Python interpreter not found: $SYS_PYTHON"
"$SYS_PYTHON" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)' \
    || die "Python 3.10 or newer is required"

if [ -x "$VENV_DIR/bin/python" ]; then
    PYTHON_BIN="$VENV_DIR/bin/python"
else
    PYTHON_BIN="$SYS_PYTHON"
fi

PY_HELPER="$(mktemp "${TMPDIR:-/tmp}/rec-install-helper.XXXXXX.py")"
cleanup() {
    rm -f "$PY_HELPER"
}
trap cleanup EXIT

cat > "$PY_HELPER" <<'PY'
import json
import os
import sys
import tempfile


def fail(message):
    sys.stderr.write("[install] error: %s\n" % message)
    raise SystemExit(1)


def read_text(path):
    if not os.path.exists(path):
        return ""
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return handle.read()
    except OSError as exc:
        fail("cannot read %s: %s" % (path, exc))


def write_atomic(path, text, default_mode=0o600):
    path = os.path.realpath(path)
    directory = os.path.dirname(os.path.abspath(path))
    if not os.path.isdir(directory):
        os.makedirs(directory, exist_ok=True)
    mode = os.stat(path).st_mode & 0o777 if os.path.exists(path) else default_mode
    handle, temporary = tempfile.mkstemp(prefix=".rec-install-", dir=directory)
    try:
        with os.fdopen(handle, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(text)
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def read_json(path):
    text = read_text(path)
    if not text.strip():
        return {}
    try:
        data = json.loads(text)
    except ValueError as exc:
        fail("cannot parse JSON %s: %s" % (path, exc))
    if not isinstance(data, dict):
        fail("JSON root must be an object: %s" % path)
    return data


def write_json(path, data):
    write_atomic(path, json.dumps(data, indent=2, ensure_ascii=False) + "\n")


def yaml_quote(value):
    return "'" + value.replace("'", "''") + "'"


def toml_quote(value):
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def json_standard(path, name, command, env_file, type_value, args):
    data = read_json(path)
    servers = data.get("mcpServers")
    if servers is None:
        servers = {}
        data["mcpServers"] = servers
    if not isinstance(servers, dict):
        fail("mcpServers must be an object in " + path)
    entry = {}
    if type_value:
        entry["type"] = type_value
    entry["command"] = command
    entry["args"] = args
    if env_file:
        entry["env"] = {"REC_ENV_FILE": env_file}
    servers[name] = entry
    write_json(path, data)


def json_opencode(path, name, command, env_file, args):
    data = read_json(path)
    servers = data.get("mcp")
    if servers is None:
        servers = {}
        data["mcp"] = servers
    if not isinstance(servers, dict):
        fail("mcp must be an object in " + path)
    entry = {"type": "local", "command": [command] + args, "enabled": True}
    if env_file:
        entry["environment"] = {"REC_ENV_FILE": env_file}
    servers[name] = entry
    write_json(path, data)


def toml_codex(path, name, command, env_file, args):
    text = read_text(path)
    block = [
        "[mcp_servers.%s]" % name,
        "command = %s" % toml_quote(command),
        "args = [%s]" % ", ".join(toml_quote(arg) for arg in args),
    ]
    if env_file:
        block.append("env = { REC_ENV_FILE = %s }" % toml_quote(env_file))
    header = "[mcp_servers.%s]" % name
    lines = text.splitlines()
    start = None
    for index, line in enumerate(lines):
        if line.strip() == header:
            start = index
            break
    if start is not None:
        end = start + 1
        while end < len(lines) and not lines[end].lstrip().startswith("["):
            end += 1
        replacement = block + ([""] if end < len(lines) else [])
        lines = lines[:start] + replacement + lines[end:]
        write_atomic(path, "\n".join(lines).rstrip() + "\n", 0o600)
        return
    text = text.rstrip()
    if text:
        text += "\n\n"
    write_atomic(path, text + "\n".join(block) + "\n", 0o600)


def dsh_mcp(path, name, command, env_file, args):
    text = read_text(path)
    start_marker = "# reconeverythings:mcp:start"
    end_marker = "# reconeverythings:mcp:end"
    start = text.find(start_marker)
    if start != -1:
        end = text.find(end_marker, start)
        if end != -1:
            text = text[:start].rstrip() + "\n" + text[end + len(end_marker):].lstrip("\n")
    block = [
        start_marker,
        "- id: mcp-%s" % name,
        "  name: '@deepseek-ai/dsh-mcp-client'",
        "  config:",
        "    serverName: %s" % name,
        "    transport: stdio",
        "    command: %s" % yaml_quote(command),
        "    args:",
    ]
    block.extend("      - %s" % yaml_quote(arg) for arg in args)
    if env_file:
        block.append("    env:")
        block.append("      REC_ENV_FILE: %s" % yaml_quote(env_file))
    block.append(end_marker)
    block_text = "\n".join(block) + "\n"
    significant = "\n".join(
        line for line in text.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ).strip()
    if significant in ("", "[]"):
        output = block_text
    else:
        output = text.rstrip() + "\n\n" + block_text
    write_atomic(path, output, 0o600)


def env_set(path, key, value):
    text = read_text(path)
    output = []
    replaced = False
    for line in text.splitlines():
        if line.strip().startswith(key + "="):
            output.append(key + "=" + value)
            replaced = True
        else:
            output.append(line)
    if not replaced:
        while output and not output[-1].strip():
            output.pop()
        if output:
            output.append("")
        output.append(key + "=" + value)
    write_atomic(path, "\n".join(output).rstrip() + "\n", 0o600)


def main(argv):
    if len(argv) < 2:
        fail("missing configuration mode")
    mode = argv[1]
    if mode == "json-standard":
        if len(argv) < 7:
            fail("json-standard requires path, name, command, env file, and type")
        json_standard(argv[2], argv[3], argv[4], argv[5], argv[6], argv[7:])
    elif mode == "json-opencode":
        if len(argv) < 6:
            fail("json-opencode requires path, name, command, and env file")
        json_opencode(argv[2], argv[3], argv[4], argv[5], argv[6:])
    elif mode == "toml-codex":
        if len(argv) < 6:
            fail("toml-codex requires path, name, command, and env file")
        toml_codex(argv[2], argv[3], argv[4], argv[5], argv[6:])
    elif mode == "dsh-mcp":
        if len(argv) < 6:
            fail("dsh-mcp requires path, name, command, and env file")
        dsh_mcp(argv[2], argv[3], argv[4], argv[5], argv[6:])
    elif mode == "env-set":
        if len(argv) < 5:
            fail("env-set requires path, key, and value")
        env_set(argv[2], argv[3], argv[4])
    else:
        fail("unknown configuration mode: " + mode)


if __name__ == "__main__":
    main(sys.argv)
PY

if [ "$DO_VENV" -eq 1 ]; then
    if [ ! -x "$VENV_DIR/bin/python" ]; then
        say "creating virtual environment: $VENV_DIR"
        "$SYS_PYTHON" -m venv "$VENV_DIR" || die "failed to create $VENV_DIR"
    fi
    PYTHON_BIN="$VENV_DIR/bin/python"
    "$PYTHON_BIN" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)' \
        || die "$PYTHON_BIN must be Python 3.10 or newer"
    say "installing ReconEveryThings and MCP dependencies"
    "$PYTHON_BIN" -m pip install --upgrade pip >/dev/null 2>&1 \
        || warn "pip upgrade skipped; continuing with the existing pip"
    (
        cd "$PROJECT_DIR"
        "$PYTHON_BIN" -m pip install -e ".[mcp]"
    ) || die "pip installation failed"
else
    [ -x "$PYTHON_BIN" ] || die "Python not found at $PYTHON_BIN"
    "$PYTHON_BIN" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)' \
        || die "$PYTHON_BIN must be Python 3.10 or newer"
    say "skipping virtual environment setup"
fi

ENV_FILE=""
if [ -f "$PROJECT_DIR/.env" ]; then
    ENV_FILE="$PROJECT_DIR/.env"
elif [ "$DO_ENV" -eq 1 ] && [ -f "$PROJECT_DIR/.env.example" ]; then
    cp "$PROJECT_DIR/.env.example" "$PROJECT_DIR/.env"
    chmod 600 "$PROJECT_DIR/.env"
    ENV_FILE="$PROJECT_DIR/.env"
    say "created $ENV_FILE from .env.example"
fi

WAFW00F_BIN="$(command -v wafw00f 2>/dev/null || true)"
if [ -x "$VENV_DIR/bin/wafw00f" ]; then
    WAFW00F_BIN="$VENV_DIR/bin/wafw00f"
elif [ -z "$WAFW00F_BIN" ] && [ "$DO_VENV" -eq 1 ]; then
    say "installing wafw00f into the virtual environment"
    if "$PYTHON_BIN" -m pip install --quiet wafw00f; then
        if [ -x "$VENV_DIR/bin/wafw00f" ]; then
            WAFW00F_BIN="$VENV_DIR/bin/wafw00f"
        fi
    else
        warn "could not install wafw00f; the WAF phase will use passive and nmap checks"
    fi
fi
if [ -n "$WAFW00F_BIN" ] && [ -n "$ENV_FILE" ] && [ -f "$ENV_FILE" ]; then
    "$PYTHON_BIN" "$PY_HELPER" env-set "$ENV_FILE" REC_WAFW00F_BIN "$WAFW00F_BIN" \
        || warn "could not record REC_WAFW00F_BIN in .env"
fi
NMAP_BIN="$(command -v nmap 2>/dev/null || true)"
if [ -n "$NMAP_BIN" ] && [ -n "$ENV_FILE" ] && [ -f "$ENV_FILE" ]; then
    "$PYTHON_BIN" "$PY_HELPER" env-set "$ENV_FILE" REC_NMAP_BIN "$NMAP_BIN" \
        || warn "could not record REC_NMAP_BIN in .env"
fi
WHATWEB_BIN="$(command -v whatweb 2>/dev/null || true)"
if [ -n "$WHATWEB_BIN" ] && [ -n "$ENV_FILE" ] && [ -f "$ENV_FILE" ]; then
    "$PYTHON_BIN" "$PY_HELPER" env-set "$ENV_FILE" REC_WHATWEB_BIN "$WHATWEB_BIN" \
        || warn "could not record REC_WHATWEB_BIN in .env"
else
    warn "whatweb not found; install it with: sudo apt install whatweb"
fi

if [ "$DO_TOOLS" -eq 1 ]; then
    if ! command -v go >/dev/null 2>&1; then
        warn "Go is not installed; skipping external reconnaissance tools"
        warn "install Go from https://go.dev/dl/ and rerun, or pass --skip-tools"
    else
        TOOL_BIN="${GOBIN:-$LOCAL_BIN}"
        mkdir -p "$TOOL_BIN" || warn "cannot create $TOOL_BIN"
        say "installing Go reconnaissance tools into $TOOL_BIN"
        TOOL_PACKAGES="subfinder github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
httpx github.com/projectdiscovery/httpx/cmd/httpx@latest
naabu github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
katana github.com/projectdiscovery/katana/cmd/katana@latest
gau github.com/lc/gau/v2/cmd/gau@latest
webanalyze github.com/rverton/webanalyze@latest"
        while read -r tool package; do
            [ -n "${tool:-}" ] || continue
            if [ -x "$TOOL_BIN/$tool" ] && [ "$FORCE" -ne 1 ]; then
                say "$tool already present at $TOOL_BIN/$tool"
                continue
            fi
            if GOBIN="$TOOL_BIN" go install "$package"; then
                say "installed $tool"
            else
                warn "failed to install $tool"
            fi
        done <<EOF
$TOOL_PACKAGES
EOF
        for tool in subfinder httpx naabu katana gau webanalyze; do
            upper="$(printf '%s' "$tool" | tr '[:lower:]' '[:upper:]')"
            if [ -x "$TOOL_BIN/$tool" ]; then
                if [ -n "$ENV_FILE" ] && [ -f "$ENV_FILE" ]; then
                    "$PYTHON_BIN" "$PY_HELPER" env-set "$ENV_FILE" \
                        "REC_${upper}_BIN" "$TOOL_BIN/$tool" \
                        || warn "could not record REC_${upper}_BIN in .env"
                fi
            else
                warn "$tool is still missing; recn will use its built-in fallback"
            fi
        done
        case ":$PATH:" in
            *":$TOOL_BIN:"*) ;;
            *) warn "add $TOOL_BIN to PATH to run the Go tools directly" ;;
        esac
    fi
fi

WEBANALYZE_BIN="$(command -v webanalyze 2>/dev/null || true)"
if [ -z "$WEBANALYZE_BIN" ] && [ -n "${TOOL_BIN:-}" ] && [ -x "$TOOL_BIN/webanalyze" ]; then
    WEBANALYZE_BIN="$TOOL_BIN/webanalyze"
fi
if [ -z "$WEBANALYZE_BIN" ] && [ -x "$LOCAL_BIN/webanalyze" ]; then
    WEBANALYZE_BIN="$LOCAL_BIN/webanalyze"
fi
if [ -n "$WEBANALYZE_BIN" ]; then
    if [ -n "$ENV_FILE" ] && [ -f "$ENV_FILE" ]; then
        "$PYTHON_BIN" "$PY_HELPER" env-set "$ENV_FILE" REC_WEBANALYZE_BIN "$WEBANALYZE_BIN" \
            || warn "could not record REC_WEBANALYZE_BIN in .env"
    fi
    DATA_DIR="$HOME/.local/share/reconeverythings"
    APPS_FILE="$DATA_DIR/technologies.json"
    mkdir -p "$DATA_DIR" || warn "cannot create $DATA_DIR"
    if [ ! -s "$APPS_FILE" ]; then
        say "downloading webanalyze technology definitions"
        if (cd "$DATA_DIR" && "$WEBANALYZE_BIN" -update >/dev/null 2>&1) && [ -s "$APPS_FILE" ]; then
            say "webanalyze definitions ready: $APPS_FILE"
        else
            warn "could not download webanalyze definitions; run: cd $DATA_DIR && webanalyze -update"
        fi
    fi
    if [ -s "$APPS_FILE" ] && [ -n "$ENV_FILE" ] && [ -f "$ENV_FILE" ]; then
        "$PYTHON_BIN" "$PY_HELPER" env-set "$ENV_FILE" REC_WEBANALYZE_APPS "$APPS_FILE" \
            || warn "could not record REC_WEBANALYZE_APPS in .env"
    fi
else
    warn "webanalyze not found; techstack will use httpx and whatweb only"
fi

harness_dir() {
    case "$1" in
        qoder) printf '%s' "$HOME/.qoder" ;;
        claude) printf '%s' "$HOME/.claude" ;;
        codex) printf '%s' "${CODEX_HOME:-$HOME/.codex}" ;;
        dsh) printf '%s' "${DSH_HOME:-$HOME/.dsh}" ;;
        gemini) printf '%s' "$HOME/.gemini" ;;
        opencode) printf '%s' "${XDG_CONFIG_HOME:-$HOME/.config}/opencode" ;;
        cursor) printf '%s' "$HOME/.cursor" ;;
        copilot) printf '%s' "$HOME/.copilot" ;;
    esac
}

harness_present() {
    case "$1" in
        qoder) [ -d "$HOME/.qoder" ] || command -v qoder >/dev/null 2>&1 ;;
        claude) [ -d "$HOME/.claude" ] || [ -f "$HOME/.claude.json" ] || command -v claude >/dev/null 2>&1 ;;
        codex) [ -d "${CODEX_HOME:-$HOME/.codex}" ] || command -v codex >/dev/null 2>&1 ;;
        dsh) [ -d "${DSH_HOME:-$HOME/.dsh}" ] || command -v dsh >/dev/null 2>&1 ;;
        gemini) [ -d "$HOME/.gemini" ] || command -v gemini >/dev/null 2>&1 ;;
        opencode) [ -d "${XDG_CONFIG_HOME:-$HOME/.config}/opencode" ] || command -v opencode >/dev/null 2>&1 ;;
        cursor) [ -d "$HOME/.cursor" ] || command -v cursor >/dev/null 2>&1 ;;
        copilot) [ -d "$HOME/.copilot" ] || command -v copilot >/dev/null 2>&1 ;;
    esac
}

skill_root() {
    case "$1" in
        qoder) printf '%s' "$HOME/.qoder/skills" ;;
        claude) printf '%s' "$HOME/.claude/skills" ;;
        codex) printf '%s' "${CODEX_HOME:-$HOME/.codex}/skills" ;;
        dsh) printf '%s' "${DSH_HOME:-$HOME/.dsh}/skills" ;;
        gemini) printf '%s' "$HOME/.gemini/skills" ;;
        opencode) printf '%s' "${XDG_CONFIG_HOME:-$HOME/.config}/opencode/skills" ;;
        cursor) printf '%s' "$HOME/.cursor/skills" ;;
        copilot) printf '%s' "$HOME/.copilot/skills" ;;
    esac
}

SELECTED=""
if [ "$HARNESSES" = "auto" ]; then
    for harness in $SUPPORTED; do
        if harness_present "$harness"; then
            SELECTED="$SELECTED $harness"
        fi
    done
    SELECTED="${SELECTED# }"
    [ -n "$SELECTED" ] || warn "no supported harness detected; only the shared skill will be installed"
elif [ "$HARNESSES" = "all" ]; then
    SELECTED="$SUPPORTED"
else
    SELECTED="$HARNESSES"
fi

backup_config() {
    path="$1"
    [ -f "$path" ] || return 0
    [ "$NO_BACKUP" -eq 1 ] && return 0
    cp -p "$path" "$path.reconeverythings.bak" 2>/dev/null \
        || warn "could not back up $path"
}

is_our_skill() {
    path="$1"
    [ -f "$path/SKILL.md" ] \
        && grep -q '^name:[[:space:]]*reconeverythings[[:space:]]*$' "$path/SKILL.md" 2>/dev/null
}

install_skill() {
    root="$1"
    label="$2"
    [ -f "$SKILL_SRC/SKILL.md" ] || {
        warn "skill source not found: $SKILL_SRC/SKILL.md"
        return 0
    }
    dest="$root/$SKILL_NAME"
    if [ -L "$dest" ]; then
        rm -f "$dest"
    elif [ -e "$dest" ]; then
        if is_our_skill "$dest"; then
            rm -rf "$dest"
        elif [ "$FORCE" -eq 1 ]; then
            rm -rf "$dest"
        else
            warn "$label: $dest exists and is not ReconEveryThings; keeping it (use --force)"
            return 0
        fi
    fi
    mkdir -p "$root"
    if cp -a "$SKILL_SRC" "$dest"; then
        say "$label: skill installed at $dest"
    else
        warn "$label: failed to copy skill to $dest"
    fi
}

run_helper() {
    "$PYTHON_BIN" "$PY_HELPER" "$@"
}

configure_json() {
    path="$1"
    type_value="$2"
    label="$3"
    backup_config "$path"
    if run_helper json-standard "$path" "$MCP_NAME" "$PYTHON_BIN" "$ENV_FILE" "$type_value" -m mcp_server.server; then
        say "$label: MCP server registered in $path"
    else
        warn "$label: failed to update $path"
    fi
}

configure_opencode() {
    path="$1"
    backup_config "$path"
    if run_helper json-opencode "$path" "$MCP_NAME" "$PYTHON_BIN" "$ENV_FILE" -m mcp_server.server; then
        say "OpenCode: MCP server registered in $path"
    else
        warn "OpenCode: failed to update $path"
    fi
}

configure_codex() {
    path="$1"
    backup_config "$path"
    if run_helper toml-codex "$path" "$MCP_NAME" "$PYTHON_BIN" "$ENV_FILE" -m mcp_server.server; then
        say "Codex CLI: MCP server registered in $path"
    else
        warn "Codex CLI: failed to update $path"
    fi
}

configure_dsh() {
    root="${DSH_HOME:-$HOME/.dsh}/profiles"
    found=0
    if [ -d "$root" ]; then
        for profile in "$root"/*; do
            [ -d "$profile" ] || continue
            [ -f "$profile/package.json" ] || continue
            patch="$profile/cordis.patch.yml"
            backup_config "$patch"
            if run_helper dsh-mcp "$patch" "$MCP_NAME" "$PYTHON_BIN" "$ENV_FILE" -m mcp_server.server; then
                say "DSH: MCP server registered in $patch"
                found=1
            else
                warn "DSH: failed to update $patch"
            fi
        done
    fi
    if [ "$found" -eq 0 ]; then
        warn "DSH: no profiles found under $root; MCP entry skipped"
    fi
}

link_binaries() {
    [ "$DO_LINK" -eq 1 ] || return 0
    mkdir -p "$LOCAL_BIN" || {
        warn "cannot create $LOCAL_BIN; command links skipped"
        return 0
    }
    for source in "$VENV_DIR/bin/recn" "$VENV_DIR/bin/rec-mcp"; do
        [ -x "$source" ] || continue
        name="$(basename "$source")"
        target="$LOCAL_BIN/$name"
        if [ -L "$target" ]; then
            current="$(readlink "$target" 2>/dev/null || true)"
            if [ "$current" != "$source" ] && [ "$FORCE" -ne 1 ]; then
                warn "$target points elsewhere; keeping it (use --force)"
                continue
            fi
            ln -sfn "$source" "$target" || warn "failed to update $target"
        elif [ -e "$target" ]; then
            if [ "$FORCE" -ne 1 ]; then
                warn "$target exists; not replacing it (use --force)"
                continue
            fi
            rm -f "$target"
            ln -s "$source" "$target" || warn "failed to link $target"
        else
            ln -s "$source" "$target" || warn "failed to link $target"
        fi
        say "$name linked at $target"
    done
    case ":$PATH:" in
        *":$LOCAL_BIN:"*) ;;
        *) warn "add $LOCAL_BIN to PATH or restart your shell" ;;
    esac
}

register_harness_mcp() {
    case "$1" in
        qoder) configure_json "$HOME/.qoder/settings.json" "" "Qoder" ;;
        claude) configure_json "$HOME/.claude.json" "" "Claude Code" ;;
        gemini) configure_json "$HOME/.gemini/config/mcp_config.json" "" "Gemini CLI" ;;
        cursor) configure_json "$HOME/.cursor/mcp.json" "stdio" "Cursor" ;;
        copilot) configure_json "$HOME/.copilot/mcp-config.json" "local" "Copilot CLI" ;;
        opencode) configure_opencode "${XDG_CONFIG_HOME:-$HOME/.config}/opencode/opencode.json" ;;
        codex) configure_codex "${CODEX_HOME:-$HOME/.codex}/config.toml" ;;
        dsh) configure_dsh ;;
    esac
}

if [ "$DO_SKILL" -eq 1 ]; then
    install_skill "$HOME/.agents/skills" "Shared skills"
    for harness in $SELECTED; do
        install_skill "$(skill_root "$harness")" "$harness"
    done
fi

if [ "$DO_MCP" -eq 1 ]; then
    for harness in $SELECTED; do
        register_harness_mcp "$harness"
    done
fi

if [ -x "$VENV_DIR/bin/recn" ]; then
    "$VENV_DIR/bin/recn" --version || warn "CLI version check failed"
fi
"$PYTHON_BIN" -c "import rec_cli, mcp_server.server" 2>/dev/null \
    || warn "Python packages are not importable with $PYTHON_BIN"

link_binaries

say "configuration complete"
if [ -n "$SELECTED" ]; then
    say "harnesses: $SELECTED"
else
    say "harnesses: shared skill only"
fi
say "next steps:"
say "  . \"$VENV_DIR/bin/activate\""
say "  recn -t example.com -m infra --stealth -o result.json"
say "restart each harness or start a new session, then verify with /skills and /mcp"
