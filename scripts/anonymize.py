#!/usr/bin/env python3
"""Pseudonymisation réversible et 100 % locale.

  mask <chemin|->     produit une copie masquée (valeurs sensibles -> __ANON_CAT_001__)
  scan <chemin>       compte les valeurs sensibles sans rien écrire
  restore <chemin>    réinjecte les vraies valeurs à la place des jetons

La table de correspondance vit dans .anonymizer/mapping.json (jamais affichée).
Ce script n'imprime que des compteurs, jamais les valeurs détectées.
"""
import argparse
import ipaddress
import json
import re
import sys
from collections import Counter
from pathlib import Path

PLACEHOLDER_RE = re.compile(r"__ANON_[A-Z]+_\d{3,}__")
SKIP_DIRS = {".git", "node_modules", ".anonymizer", "__pycache__", ".venv", "venv"}
INTERNAL_SUFFIXES = (".local", ".lan", ".intranet", ".corp", ".internal",
                     ".home", ".priv", ".localdomain")
MAX_BYTES = 20 * 1024 * 1024


# --------------------------------------------------------------------- coffre
class Vault:
    """Table jeton <-> valeur réelle, persistée localement."""

    def __init__(self, directory, persist=True):
        self.dir = Path(directory)
        self.file = self.dir / "mapping.json"
        self.persist = persist
        self.entries = {}
        if persist and self.file.exists():
            self.entries = json.loads(self.file.read_text(encoding="utf-8"))["entries"]
        self.reverse = {v: k for k, v in self.entries.items()}
        self.counters = Counter()
        for tok in self.entries:
            cat, num = tok.strip("_").split("_")[1:3]
            self.counters[cat] = max(self.counters[cat], int(num))

    def token(self, cat, value):
        if value in self.reverse:
            return self.reverse[value]
        self.counters[cat] += 1
        tok = f"__ANON_{cat}_{self.counters[cat]:03d}__"
        self.entries[tok] = value
        self.reverse[value] = tok
        return tok

    def save(self):
        if not self.persist:
            return
        self.dir.mkdir(parents=True, exist_ok=True)
        ignore = self.dir / ".gitignore"
        if not ignore.exists():
            ignore.write_text("*\n", encoding="utf-8")
        self.file.write_text(
            json.dumps({"entries": self.entries}, ensure_ascii=False, indent=1),
            encoding="utf-8")


# ------------------------------------------------------------- configuration
class Config:
    """Fichier de termes : un terme par ligne, `domain:x.fr`, `allow:valeur`, `# commentaire`."""

    def __init__(self, path=None, vault=None):
        self.terms, self.domains, self.allow = [], [], set()
        self.allow_paths, self.deny_paths = [], []
        if not path and vault and (Path(vault) / "terms.txt").exists():
            path = Path(vault) / "terms.txt"      # emplacement par défaut
        if not path:
            return
        for raw in Path(path).read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            low = line.lower()
            if low.startswith("domain:"):
                self.domains.append("." + low[7:].strip().lstrip("."))
            elif low.startswith("allow-path:"):
                self.allow_paths.append(line[11:].strip())
            elif low.startswith("deny-path:"):
                self.deny_paths.append(line[10:].strip())
            elif low.startswith("allow:"):
                self.allow.add(line[6:].strip().lower())
            else:
                self.terms.append(line)
        self.terms.sort(key=len, reverse=True)


# ---------------------------------------------------------------- validateurs
def is_private_ip(value):
    try:
        ip = ipaddress.ip_address(value.strip("[]"))
    except ValueError:
        return False
    return ip.is_private and not ip.is_loopback and not ip.is_unspecified


def is_internal_host(host, cfg):
    h = host.lower().rstrip(".")
    if h in ("localhost", "") or h in cfg.allow:
        return False
    if is_private_ip(h):
        return True
    if re.fullmatch(r"[\d.]+|\[[0-9a-f:]+\]", h):
        return False                      # IP publique
    if "." not in h:
        return True                       # nom court = machine du réseau interne
    return h.endswith(INTERNAL_SUFFIXES) or any(
        h == d[1:] or h.endswith(d) for d in cfg.domains)


def luhn_ok(value):
    digits = [int(c) for c in value if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2:
            d = d * 2 - 9 if d > 4 else d * 2
        total += d
    return total % 10 == 0


def iban_ok(value):
    s = value.replace(" ", "").upper()
    if not 15 <= len(s) <= 34:
        return False
    s = s[4:] + s[:4]
    return int("".join(str(int(c, 36)) for c in s)) % 97 == 1


def secret_value_ok(value):
    if re.search(r"[(){}\[\]$<>]", value):
        return False                      # appel de fonction, variable, gabarit
    if re.fullmatch(r"[A-Za-z_.]+", value):
        return False                      # identifiant de code (self.password = password)
    return True


# ----------------------------------------------------------------- détecteurs
SECRET_KEYS = (r"(?:pass(?:word|wd|phrase)|pwd|mot_?de_?passe|mdp|secret|token|"
               r"api[_-]?key|access[_-]?key|private[_-]?key|credential)")

RULES = [
    # (catégorie, motif, groupe à masquer, validateur)
    ("SECRET", r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", 0, None),
    ("SECRET", r"\b(?:sk-[A-Za-z0-9_-]{20,}|ghp_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}"
               r"|glpat-[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}|xox[abprs]-[A-Za-z0-9-]{10,}"
               r"|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})", 0, None),
    ("SECRET", r"(?i)" + SECRET_KEYS + r"\w*[\"']?\s*[:=]\s*[\"']?([^\s\"',;]{6,})", 1,
     secret_value_ok),
    ("EMAIL", r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", 0, None),
    ("IBAN", r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b", 0, iban_ok),
    ("NIR", r"(?<!\d)[12] ?\d{2} ?(?:0[1-9]|1[0-2]) ?(?:\d{2}|2[AB]) ?\d{3} ?\d{3}(?: ?\d{2})?(?!\d)",
     0, None),
    ("CARD", r"(?<![\d_])\d(?:[ -]?\d){12,18}(?![\d_])", 0, luhn_ok),
    ("PHONE", r"(?<![\w+])(?:\+33[ .]?|0)[1-9](?:[ .-]?\d{2}){4}(?!\d)", 0, None),
    ("USER", r"(?i)\b[A-Z]:[\\/]+Users[\\/]+([^\\/\s\"'<>|:]+)", 1,
     lambda v: v.lower() not in ("public", "default", "all users")),
    ("USER", r"(?<![\w.])/(?:home|Users)/([^/\s\"'<>:]+)", 1,
     lambda v: v.lower() not in ("shared", "public")),
]
RULES = [(c, re.compile(p, re.S), g, chk) for c, p, g, chk in RULES]

URL_RE = re.compile(r"\b([a-z][a-z0-9+.-]*://)(?:([^\s/@\"'<>]+)@)?(\[[0-9a-fA-F:]+\]|[A-Za-z0-9.-]+)")
UNC_RE = re.compile(r"(?<!\\)\\\\([A-Za-z0-9._-]+)(?=\\)")
IP_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")


def mask_text(text, vault, cfg, stats):
    def put(cat, value):
        if PLACEHOLDER_RE.search(value) or value.lower() in cfg.allow:
            return value
        stats[cat] += 1
        return vault.token(cat, value)

    def group_sub(cat, group, check):
        def repl(m):
            value = m.group(group)
            if check and not check(value):
                return m.group(0)
            start, end = m.start(group) - m.start(), m.end(group) - m.start()
            whole = m.group(0)
            return whole[:start] + put(cat, value) + whole[end:]
        return repl

    # termes fournis par l'utilisateur (noms de projet, de client, de machine...)
    for term in cfg.terms:
        text = re.sub(re.escape(term), lambda m: put("TERM", m.group(0)), text, flags=re.I)

    for cat, rx, group, check in RULES[:3]:            # secrets d'abord
        text = rx.sub(group_sub(cat, group, check), text)

    def url_repl(m):
        scheme, userinfo, host = m.groups()
        out = scheme
        if userinfo:
            out += put("SECRET", userinfo) + "@"
        return out + (put("HOST", host) if is_internal_host(host, cfg) else host)
    text = URL_RE.sub(url_repl, text)
    text = UNC_RE.sub(lambda m: "\\\\" + put("HOST", m.group(1)), text)

    for cat, rx, group, check in RULES[3:]:
        text = rx.sub(group_sub(cat, group, check), text)

    suffixes = "|".join(re.escape(s) for s in INTERNAL_SUFFIXES + tuple(cfg.domains))
    text = re.sub(r"(?i)(?<![\w.@-])[a-z0-9-]+(?:\.[a-z0-9-]+)*(?:" + suffixes + r")(?![\w-])",
                  lambda m: put("HOST", m.group(0)), text)
    text = IP_RE.sub(lambda m: put("IP", m.group(0)) if is_private_ip(m.group(0)) else m.group(0),
                     text)
    return text


# -------------------------------------------------------------------- fichiers
def iter_files(root):
    root = Path(root)
    if root.is_file():
        yield root, Path(root.name)
        return
    for p in sorted(root.rglob("*")):
        if p.is_file() and not SKIP_DIRS.intersection(p.relative_to(root).parts):
            yield p, p.relative_to(root)


def read_text(path):
    if path.stat().st_size > MAX_BYTES:
        return None
    data = path.read_bytes()
    if b"\0" in data[:8192]:
        return None                       # binaire
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("cp1252", errors="replace")


def report(stats, label):
    detail = ", ".join(f"{c}={n}" for c, n in sorted(stats.items())) or "rien a masquer"
    print(f"{label}: {detail}", file=sys.stderr)


def cmd_mask(args, write=True):
    cfg = Config(args.terms, args.vault)
    vault = Vault(args.vault, persist=write)
    total = Counter()
    if args.path == "-":
        text = sys.stdin.buffer.read().decode("utf-8", errors="replace")
        out = mask_text(text, vault, cfg, total)
        if write:
            sys.stdout.buffer.write(out.encode("utf-8"))
        vault.save()
        report(total, "stdin")
        return 0
    src = Path(args.path)
    if not src.exists():
        print(f"introuvable: {src}", file=sys.stderr)
        return 2
    out_root = Path(args.output) if getattr(args, "output", None) else Path(args.vault) / "masked"
    skipped = 0
    for path, rel in iter_files(src):
        text = read_text(path)
        if text is None:
            skipped += 1
            continue
        stats = Counter()
        masked = mask_text(text, vault, cfg, stats)
        total.update(stats)
        if write:
            dest = out_root if (src.is_file() and getattr(args, "output", None)) else out_root / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(masked, encoding="utf-8", newline="")
            report(stats, f"{rel} -> {dest}")
        elif stats:
            report(stats, str(rel))
    vault.save()
    report(total, "TOTAL")
    if skipped:
        print(f"{skipped} fichier(s) binaire(s) ou trop volumineux ignore(s)", file=sys.stderr)
    return 0


def cmd_restore(args):
    vault = Vault(args.vault)
    src = Path(args.path)
    if not src.exists():
        print(f"introuvable: {src}", file=sys.stderr)
        return 2
    if not args.in_place and not args.output:
        print("preciser --in-place ou -o <sortie>", file=sys.stderr)
        return 2
    restored = unknown = 0
    for path, rel in iter_files(src):
        text = read_text(path)
        if text is None:
            continue
        if args.in_place and not PLACEHOLDER_RE.search(text):
            continue

        def repl(m):
            nonlocal restored, unknown
            if m.group(0) in vault.entries:
                restored += 1
                return vault.entries[m.group(0)]
            unknown += 1
            return m.group(0)
        result = PLACEHOLDER_RE.sub(repl, text)
        if args.in_place:
            dest = path
        else:
            dest = Path(args.output) if src.is_file() else Path(args.output) / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(result, encoding="utf-8", newline="")
    print(f"restaure: {restored} jeton(s), inconnus: {unknown}", file=sys.stderr)
    return 1 if unknown else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--vault", default=".anonymizer",
                        help="dossier de la table de correspondance (defaut: ./.anonymizer)")
    sub = parser.add_subparsers(dest="cmd", required=True)
    m = sub.add_parser("mask")
    m.add_argument("path")
    m.add_argument("-o", "--output")
    m.add_argument("--terms", help="fichier de termes/domaines propres au contexte")
    s = sub.add_parser("scan")
    s.add_argument("path")
    s.add_argument("--terms")
    r = sub.add_parser("restore")
    r.add_argument("path")
    r.add_argument("-o", "--output")
    r.add_argument("--in-place", action="store_true")
    a = sub.add_parser("alias", help="enregistre une valeur et affiche son alias")
    a.add_argument("value")
    a.add_argument("--cat", default="TERM")
    args = parser.parse_args()
    if args.cmd == "alias":
        vault = Vault(args.vault)
        print(vault.token(args.cat.upper(), args.value))
        vault.save()
        return 0
    if args.cmd == "mask":
        return cmd_mask(args)
    if args.cmd == "scan":
        return cmd_mask(args, write=False)
    return cmd_restore(args)


if __name__ == "__main__":
    sys.exit(main())
