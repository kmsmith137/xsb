"""Configuration: finding the root, loading the TOML layers, applying [[match]]
blocks, merging with source tracking, and expanding variables in paths.

Layers, later ones overriding earlier ones (plan §5.3):

  1. built-in defaults (data/defaults.toml, printed by `xsb config --defaults`)
  2. ~/.xsb/config.toml
  3. <root>/xsb.toml

Within a layer, [[match]] blocks are applied after the plain keys, in file
order, when their conditions hold. How a value merges depends on its kind:
scalars and lists of scalars replace; lists of tables ([[mount]], [[device]],
refuse) append, where an entry with the same key replaces the earlier one;
tables merge key by key.
"""

from __future__ import annotations

import fnmatch
import glob
import os
import re
import tomllib
from dataclasses import dataclass, field
from importlib import resources

from . import agents
from .context import Context
from .tomlw import toml_key, toml_value

CONFIG_NAME = "xsb.toml"

BUILTIN = "built-in"
USER_LAYER = "~/.xsb/config.toml"
PROJECT_LAYER = "xsb.toml"


class ConfigError(Exception):
    """Invalid or missing configuration. Launches are refused (I7)."""


# --------------------------------------------------------------------------
# Schema
# --------------------------------------------------------------------------

STR, BOOL, STRLIST, BOOLTABLE, STRTABLE = "string", "boolean", "list of strings", "table of booleans", "table of strings"


@dataclass(frozen=True)
class Entries:
    """A list of tables whose entries are identified by one key field."""
    key: str
    fields: dict
    defaults: dict


ENTRY_KINDS = {
    "mount": Entries("path", {"path": STR, "mode": ("ro", "rw"), "create": BOOL, "enabled": BOOL},
                     {"mode": "ro", "create": False, "enabled": True}),
    "device": Entries("glob", {"glob": STR, "enabled": BOOL}, {"enabled": True}),
    "refuse": Entries("dir", {"dir": STR, "reason": STR, "enabled": BOOL},
                      {"reason": "", "enabled": True}),
}

SCHEMA = {
    **{a.config_key: STR for a in agents.AGENTS.values()},
    "refuse": ENTRY_KINDS["refuse"],
    "protect": BOOLTABLE,
    "mount": ENTRY_KINDS["mount"],
    "device": ENTRY_KINDS["device"],
    "env": {"require": STRLIST, "forward": BOOLTABLE, "set": STRTABLE},
    "network": {"mode": ("enforced", "open")},
    "linux": {"image": STR, "extra_args": STRLIST},
}

MATCH_CONDITIONS = {"os": ("linux", "macos"), "hosts": STRLIST}

ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")

# Variables xsb sets itself (plan §5.5); config may not forward or set them.
RESERVED_ENV = {
    "HOME", "USER", "PATH", "TMPDIR", "XDG_CACHE_HOME",
    "HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "NO_PROXY", "no_proxy",
    "XSB_ROOT", "XSB_BACKEND", "XSB_NETWORK",
} | agents.reserved_env_names()


def _kind_name(kind) -> str:
    if isinstance(kind, tuple):
        return " | ".join(f'"{x}"' for x in kind)
    if isinstance(kind, Entries):
        return "list of tables"
    if isinstance(kind, dict):
        return "table"
    return kind


def _check_value(value, kind, where: str):
    """Check one value against its kind; `where` names it in errors."""
    def fail(msg=None):
        raise ConfigError(msg or f"{where}: expected {_kind_name(kind)}, got {toml_value_safe(value)}")

    if isinstance(kind, tuple):
        if not isinstance(value, str) or value not in kind:
            fail()
    elif kind == STR:
        if not isinstance(value, str):
            fail()
    elif kind == BOOL:
        if not isinstance(value, bool):
            fail()
    elif kind == STRLIST:
        if not isinstance(value, list):
            fail()
        _check_not_mixed(value, where)
        if not all(isinstance(x, str) for x in value):
            fail()
    elif kind in (BOOLTABLE, STRTABLE):
        if not isinstance(value, dict):
            fail()
        want = bool if kind == BOOLTABLE else str
        for k, v in value.items():
            if not isinstance(v, want):
                fail(f"{where}.{toml_key(k)}: expected {'true or false' if want is bool else 'a string'}, "
                     f"got {toml_value_safe(v)}")
    elif isinstance(kind, Entries):
        if isinstance(value, dict):
            name = where.split(": ")[-1]
            fail(f"{where}: must be a list of tables (write [[{name}]], not [{name}])")
        if not isinstance(value, list):
            fail()
        _check_not_mixed(value, where)
        for i, entry in enumerate(value, 1):
            ew = f"{where}[{i}]"
            if not isinstance(entry, dict):
                fail(f"{ew}: expected a table, got {toml_value_safe(entry)}")
            for k, v in entry.items():
                if k not in kind.fields:
                    raise ConfigError(f"{ew}: unknown key '{k}' (allowed: {', '.join(kind.fields)})")
                _check_value(v, kind.fields[k], f"{ew}.{k}")
            if kind.key not in entry:
                raise ConfigError(f"{ew}: missing '{kind.key}'")
    elif isinstance(kind, dict):
        if not isinstance(value, dict):
            fail()
        for k, v in value.items():
            if k not in kind:
                raise ConfigError(f"{where}: unknown key '{k}' (allowed: {', '.join(kind)})")
            _check_value(v, kind[k], f"{where}.{k}")


def toml_value_safe(v) -> str:
    try:
        return toml_value(v)
    except TypeError:
        return repr(v)


def _check_not_mixed(value: list, where: str):
    kinds = {isinstance(x, dict) for x in value}
    if len(kinds) > 1:
        raise ConfigError(f"{where}: a list may not mix tables and plain values")


def _check_env_names(data: dict, where: str):
    env = data.get("env", {})
    for name in env.get("require", []):
        _check_env_name(name, f"{where}: env.require")
    for sub in ("forward", "set"):
        for name in env.get(sub, {}):
            _check_env_name(name, f"{where}: env.{sub}")


def _check_env_name(name: str, where: str):
    if not ENV_NAME.fullmatch(name):
        raise ConfigError(f"{where}: invalid variable name {toml_value(name)}")
    if name in RESERVED_ENV:
        raise ConfigError(f"{where}: {name} is set by xsb itself and cannot be listed here")


def validate(data: dict, label: str):
    """Reject unknown keys and wrongly typed values (typos in security config)."""
    for k, v in data.items():
        if k == "match":
            if not isinstance(v, list) or not all(isinstance(b, dict) for b in v):
                raise ConfigError(f"{label}: 'match' must be written as [[match]] blocks")
            for i, block in enumerate(v, 1):
                where = f"{label}: [[match]] #{i}"
                for bk, bv in block.items():
                    if bk in MATCH_CONDITIONS:
                        _check_value(bv, MATCH_CONDITIONS[bk], f"{where}: {bk}")
                    elif bk == "match":
                        raise ConfigError(f"{where}: [[match]] blocks cannot be nested")
                    elif bk in SCHEMA:
                        _check_value(bv, SCHEMA[bk], f"{where}: match.{bk}")
                    else:
                        raise ConfigError(f"{where}: unknown key 'match.{bk}'")
                _check_env_names(block, where)
                _check_protect(block, where)
        elif k in SCHEMA:
            _check_value(v, SCHEMA[k], f"{label}: {k}")
        else:
            raise ConfigError(f"{label}: unknown key '{k}'")
    _check_env_names(data, label)
    _check_protect(data, label)


def _check_protect(data: dict, where: str):
    for pat in data.get("protect", {}):
        if "**" in pat:
            raise ConfigError(f"{where}: protect {toml_value(pat)}: '**' is not supported "
                              "(each '*' matches within one path component)")


# --------------------------------------------------------------------------
# Expansion of variables and paths (plan §5.3)
# --------------------------------------------------------------------------

_VAR = re.compile(r"\$(?:\{([^}]*)\}|([A-Za-z_][A-Za-z0-9_]*)|(\$)|)")


class Expander:
    """Expands ~ and $VARIABLES, and resolves relative paths against the root."""

    def __init__(self, ctx: Context, root: str | None):
        self.ctx = ctx
        self.root = root

    def variables(self) -> dict:
        v = dict(self.ctx.environ)
        v.update(HOME=self.ctx.home, USER=self.ctx.user, HOSTNAME=self.ctx.hostname,
                 CWD=self.ctx.cwd)
        if self.root is not None:
            v["ROOT"] = self.root
        return v

    def expand(self, s: str, what: str, escape=lambda v: v) -> str:
        """Expand ~ and variables. `escape` is applied to every substituted
        value (glob.escape, so a value like "proj[old]" stays literal)."""
        orig = s
        tail = ""
        if s == "~" or s.startswith("~/"):
            tail = escape(self.ctx.home)
            s = s[1:]
        elif s.startswith("~"):
            raise ConfigError(f"{what}: only ~ and ~/ are supported, not {toml_value(s)}")
        variables = self.variables()

        def repl(m):
            if m.group(3):
                return "$"                  # $$ is a literal $
            name = m.group(1) if m.group(1) is not None else m.group(2)
            if name is None or not ENV_NAME.fullmatch(name):
                raise ConfigError(f"{what}: stray '$' in {toml_value(orig)} (write $$ for a literal $)")
            if name not in variables:
                why = " (not in a project)" if name == "ROOT" else ""
                raise ConfigError(f"{what}: ${name} is not defined{why}, in {toml_value(orig)}")
            return escape(variables[name])

        return tail + _VAR.sub(repl, s)

    def path(self, s: str, what: str, escape=lambda v: v) -> str:
        p = self.expand(s, what, escape)
        if not os.path.isabs(p):
            if self.root is None:
                raise ConfigError(f"{what}: relative path {toml_value(s)} needs a project root")
            p = os.path.join(escape(self.root), p)
        return os.path.normpath(p)

    def pattern(self, s: str, what: str) -> str:
        """s as an absolute glob pattern: the root and substituted values are
        escaped, so only the glob characters written in s itself are special."""
        return self.path(s, what, escape=glob.escape)

    def glob(self, s: str, what: str) -> list[str]:
        """Existing paths matching s (after expansion). Missing ones, including
        broken symlinks, are skipped. `*` matches hidden names too, as the
        Seatbelt backend's regexes do."""
        return sorted(m for m in glob.glob(self.pattern(s, what), include_hidden=True)
                      if os.path.exists(m))


# --------------------------------------------------------------------------
# Finding the root (plan §5.2)
# --------------------------------------------------------------------------

def is_under(path: str, parent: str) -> bool:
    """True if path is parent or inside it (both normalized, absolute)."""
    parent = parent.rstrip("/") or "/"
    return path == parent or path.startswith(parent + "/") or parent == "/"


def search_stop(cwd: str, home: str) -> str:
    home_r = os.path.realpath(home)
    for h in (home, home_r):
        if is_under(cwd, h):
            return h
    return "/"


def find_configs(cwd: str, home: str) -> list[str]:
    """Every xsb.toml from cwd up to $HOME (inclusive), or to / outside $HOME."""
    cur = os.path.normpath(cwd)
    stop = search_stop(cur, home)
    found = []
    while True:
        p = os.path.join(cur, CONFIG_NAME)
        if os.path.lexists(p):
            found.append(p)
        if cur == stop or cur == "/":
            break
        cur = os.path.dirname(cur)
    return found


def find_root(ctx: Context, required: bool = True) -> tuple[str | None, str | None]:
    found = find_configs(ctx.cwd, ctx.home)
    if len(found) > 1:
        raise ConfigError(
            "more than one xsb.toml between here and " + ctx.tilde(search_stop(ctx.cwd, ctx.home))
            + "; refusing, since a nested xsb.toml could widen the policy:\n"
            + "\n".join("  " + p for p in found))
    if not found:
        if required:
            raise ConfigError(f"no {CONFIG_NAME} in {ctx.cwd} or its parents; "
                              "run `xsb init` in the directory that should be the project root")
        return None, None
    return os.path.dirname(found[0]), found[0]


# --------------------------------------------------------------------------
# Merging with source tracking
# --------------------------------------------------------------------------

@dataclass
class Entry:
    kind: str           # "mount" | "device" | "refuse"
    fields: dict        # with defaults filled in
    source: str
    key: str            # normalized key: a later entry with the same key replaces this one

    @property
    def enabled(self) -> bool:
        return self.fields.get("enabled", True)


class Merged:
    """The merged config: every value remembers which layer set it."""

    def __init__(self, expander: Expander):
        self.expander = expander
        self.values: dict[tuple, tuple] = {}          # path -> (value, source)
        self.entries: dict[str, list[Entry]] = {k: [] for k in ENTRY_KINDS}

    def apply(self, data: dict, source: str, schema: dict = SCHEMA, prefix: tuple = ()):
        for k, v in data.items():
            kind = schema[k]
            if isinstance(kind, Entries):
                for raw in v:
                    self._add_entry(k, raw, source)
            elif isinstance(kind, dict):
                self.apply(v, source, kind, prefix + (k,))
            elif kind in (BOOLTABLE, STRTABLE):
                for kk, vv in v.items():
                    self.values[prefix + (k, kk)] = (vv, source)
            else:
                self.values[prefix + (k,)] = (list(v) if isinstance(v, list) else v, source)

    def _add_entry(self, kind: str, raw: dict, source: str):
        spec = ENTRY_KINDS[kind]
        fields = {**spec.defaults, **raw}
        key = self._norm_key(fields[spec.key])
        self.entries[kind] = [e for e in self.entries[kind] if e.key != key]
        self.entries[kind].append(Entry(kind, fields, source, key))

    def _norm_key(self, raw: str) -> str:
        # Keys match after expansion, so "~/x" and "$HOME/x" name the same entry.
        # If expansion fails here, the error is reported when the entry is used.
        try:
            return self.expander.path(raw, "key")
        except ConfigError:
            return raw

    def get(self, *path, default=None):
        return self.values.get(path, (default, None))[0]

    def source(self, *path):
        return self.values.get(path, (None, None))[1]

    def table(self, *prefix) -> dict:
        """{key: (value, source)} for a table like ("env", "forward")."""
        n = len(prefix)
        return {p[n]: vs for p, vs in self.values.items() if len(p) == n + 1 and p[:n] == prefix}

    def active(self, kind: str) -> list[Entry]:
        return [e for e in self.entries[kind] if e.enabled]


def match_holds(block: dict, ctx: Context) -> bool:
    if "os" in block and block["os"] != ctx.os:
        return False
    if "hosts" in block:
        host = ctx.hostname.lower()
        if not any(fnmatch.fnmatchcase(host, pat.lower()) for pat in block["hosts"]):
            return False
    return True


def match_label(layer: str, i: int, block: dict) -> str:
    conds = ", ".join(f"{k} = {toml_value(block[k])}" for k in MATCH_CONDITIONS if k in block)
    return f"{layer} [[match]] #{i}" + (f" ({conds})" if conds else "")


def apply_layer(merged: Merged, data: dict, label: str, ctx: Context):
    merged.apply({k: v for k, v in data.items() if k != "match"}, label)
    for i, block in enumerate(data.get("match", []), 1):
        if match_holds(block, ctx):
            settings = {k: v for k, v in block.items() if k not in MATCH_CONDITIONS}
            merged.apply(settings, match_label(label, i, block))


# --------------------------------------------------------------------------
# Loading
# --------------------------------------------------------------------------

def defaults_text() -> str:
    return resources.files("xsb").joinpath("data/defaults.toml").read_text()


def read_toml(path: str, label: str) -> dict:
    try:
        with open(path, "rb") as f:
            return tomllib.load(f)
    except FileNotFoundError:
        raise ConfigError(f"{label}: cannot read {path} (a broken symlink?)") from None
    except tomllib.TOMLDecodeError as e:
        raise ConfigError(f"{label}: invalid TOML in {path}: {e}") from None
    except OSError as e:
        raise ConfigError(f"{label}: cannot read {path}: {e.strerror}") from None


@dataclass
class Config:
    ctx: Context
    root: str | None
    config_path: str | None              # <root>/xsb.toml, as found (maybe a symlink)
    merged: Merged
    layers: list = field(default_factory=list)   # (label, path or None)

    @property
    def expander(self) -> Expander:
        return self.merged.expander

    @property
    def files_read(self) -> list[str]:
        """Real paths of the config files read (for pinning read-only, I1)."""
        return [os.path.realpath(p) for _, p in self.layers if p]

    @property
    def network_mode(self) -> str:
        return self.merged.get("network", "mode")

    def agent_dir(self, agent: agents.Agent) -> str:
        raw = self.merged.get(agent.config_key)
        return self.expander.path(raw, f"{agent.config_key} {toml_value(raw)}")


def load_config(ctx: Context, require_root: bool = True, builtin_only: bool = False) -> Config:
    """The merged config for ctx.cwd. `builtin_only`: just the defaults (no root)."""
    root, config_path = (None, None) if builtin_only else find_root(ctx, required=require_root)
    merged = Merged(Expander(ctx, root))
    layers = [(BUILTIN, None)]

    data = tomllib.loads(defaults_text())
    validate(data, BUILTIN)
    apply_layer(merged, data, BUILTIN, ctx)

    if not builtin_only and os.path.lexists(ctx.user_config):
        data = read_toml(ctx.user_config, USER_LAYER)
        validate(data, USER_LAYER)
        apply_layer(merged, data, USER_LAYER, ctx)
        layers.append((USER_LAYER, ctx.user_config))

    if config_path:
        data = read_toml(config_path, PROJECT_LAYER)
        validate(data, PROJECT_LAYER)
        apply_layer(merged, data, PROJECT_LAYER, ctx)
        layers.append((PROJECT_LAYER, config_path))

    return Config(ctx=ctx, root=root, config_path=config_path, merged=merged, layers=layers)


# --------------------------------------------------------------------------
# `xsb config`: the merged config as TOML, each value tagged with its source
# --------------------------------------------------------------------------

def _describe_file(ctx: Context, path: str) -> str:
    s = ctx.tilde(path)
    if os.path.islink(path):
        s += " -> " + ctx.tilde(os.path.realpath(path))
    return s


def format_effective(cfg: Config) -> str:
    ctx, m = cfg.ctx, cfg.merged
    out = [f"# Effective xsb config for {ctx.cwd}",
           f"# Root: {cfg.root}" if cfg.root else "# Not in a project (no xsb.toml here or above).",
           "# Layers, later ones overriding earlier ones:",
           f"#   {BUILTIN:<20}  (`xsb config --defaults`)"]
    user_state = _describe_file(ctx, ctx.user_config) if os.path.lexists(ctx.user_config) else "(none)"
    out.append(f"#   {USER_LAYER:<20}  {user_state}")
    if cfg.config_path:
        out.append(f"#   {PROJECT_LAYER:<20}  {_describe_file(ctx, cfg.config_path)}")
    out.append("# Each value is tagged with the layer (or [[match]] block) that set it.")
    out.append("")

    def line(key: str, value, source) -> str:
        return f"{key} = {toml_value(value)}" + (f"   # {source}" if source else "")

    for a in agents.AGENTS.values():
        out.append(line(a.config_key, m.get(a.config_key), m.source(a.config_key)))
    if not m.entries["refuse"]:
        out.append("refuse = []")
    out.append("")

    for kind in ("refuse",):
        for e in m.entries[kind]:
            out += _format_entry(e) + [""]

    out.append("[protect]")
    for k, (v, s) in m.table("protect").items():
        out.append(line(toml_key(k), v, s))
    out.append("")

    for kind in ("mount", "device"):
        for e in m.entries[kind]:
            out += _format_entry(e) + [""]

    out.append("[env]")
    out.append(line("require", m.get("env", "require"), m.source("env", "require")))
    out.append("")
    for sub in ("forward", "set"):
        out.append(f"[env.{sub}]")
        for k, (v, s) in m.table("env", sub).items():
            out.append(line(toml_key(k), v, s))
        out.append("")

    out.append("[network]")
    out.append(line("mode", m.get("network", "mode"), m.source("network", "mode")))
    out.append("")
    out.append("[linux]")
    for k in ("image", "extra_args"):
        out.append(line(k, m.get("linux", k), m.source("linux", k)))
    return "\n".join(out) + "\n"


def _format_entry(e: Entry) -> list[str]:
    lines = [f"[[{e.kind}]]   # {e.source}"]
    spec = ENTRY_KINDS[e.kind]
    for k in spec.fields:
        if k == "enabled" and e.fields.get("enabled", True):
            continue
        if k in e.fields:
            lines.append(f"{k} = {toml_value(e.fields[k])}")
    return lines
