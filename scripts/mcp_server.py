#!/usr/bin/env python3
"""Serveur MCP (stdio, sans dépendance) : pseudonymisation locale pour Claude Code.

Outils :
  scan     compte les valeurs sensibles par catégorie, sans rien écrire ni rien afficher
  mask     écrit une copie masquée (alias __ANON_…__) dans .anonymizer/masked/
  restore  réinjecte les vraies valeurs dans un fichier local ; le contenu n'est jamais renvoyé
  alias    crée ou retrouve l'alias d'une valeur (seul l'alias est renvoyé)
  guard_status   indique si le garde est actif sur le projet
  guard_enable   active le garde sur le projet

Volontairement absent : une désactivation du garde par l'agent. Un outil de ce type
permettrait au modèle de contourner la protection. Désactiver se fait avec
scripts/toggle.py ou le lanceur, depuis le poste.

Tous les chemins doivent rester dans le projet. La table d'alias n'est jamais renvoyée.
"""
import json
import os
import sys
import traceback
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import anonymize as A  # noqa: E402
import toggle  # noqa: E402

PROTOCOL = "2024-11-05"
ROOT = Path(os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd()).resolve()
VAULT = ROOT / ".anonymizer"
MASKED = VAULT / "masked"


def inside(path, parent):
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def safe(raw):
    p = Path(raw)
    p = (p if p.is_absolute() else ROOT / p).resolve()
    if not inside(p, ROOT):
        raise ValueError("chemin hors du projet : refusé")
    return p


def summary(stats):
    return ", ".join(f"{c}={n}" for c, n in sorted(stats.items())) or "aucune"


def tool_scan(args):
    src = safe(args["path"])
    stats = Counter()
    vault = A.Vault(VAULT, persist=False)
    cfg = A.Config(None, VAULT)
    for p, _ in A.iter_files(src):
        text = A.read_text(p)
        if text is not None:
            A.mask_text(text, vault, cfg, stats)
    return f"Valeurs détectées : {summary(stats)}. Aucun contenu affiché."


def tool_mask(args):
    src = safe(args["path"])
    explicit = bool(args.get("output"))
    out_root = safe(args["output"]) if explicit else MASKED
    vault = A.Vault(VAULT)
    cfg = A.Config(None, VAULT)
    total, written = Counter(), []
    for p, rel in A.iter_files(src):
        text = A.read_text(p)
        if text is None:
            continue
        if src.is_file():
            dest = out_root if explicit else out_root / src.relative_to(ROOT)
        else:
            dest = out_root / rel
        if dest.resolve() == p.resolve():
            raise ValueError("la sortie ne peut pas écraser la source : elle perdrait les vraies valeurs")
        stats = Counter()
        masked = A.mask_text(text, vault, cfg, stats)
        total.update(stats)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(masked, encoding="utf-8", newline="")
        written.append(dest)
    vault.save()
    listing = "\n".join(f"- {w.relative_to(ROOT).as_posix()}" for w in written) or "- aucun fichier"
    return (f"Copies masquées ({summary(total)}) :\n{listing}\n"
            "Lire ces copies avec Read ; ne jamais lire la source.")


def tool_restore(args):
    src = safe(args["path"])
    out = safe(args["output"])
    vault = A.Vault(VAULT)                       # lecture seule : pas de save()
    restored = unknown = 0
    for p, rel in A.iter_files(src):
        text = A.read_text(p)
        if text is None:
            continue

        def repl(m):
            nonlocal restored, unknown
            if m.group(0) in vault.entries:
                restored += 1
                return vault.entries[m.group(0)]
            unknown += 1
            return m.group(0)

        result = A.PLACEHOLDER_RE.sub(repl, text)
        dest = out if src.is_file() else out / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(result, encoding="utf-8", newline="")
    return (f"Restauré : {restored} alias réinjecté(s), {unknown} inconnu(s). "
            "Contenu non affiché.")


def tool_alias(args):
    category = (args.get("category") or "TERM").upper()
    vault = A.Vault(VAULT)
    token = vault.token(category, args["value"])
    vault.save()
    return f"Alias : {token}"


def tool_guard_status(args):
    state = "ACTIF" if toggle.is_active(ROOT) else "INACTIF"
    return f"Garde : {state} (projet : {ROOT})"


def tool_guard_enable(args):
    created = toggle.enable(ROOT)
    extra = " Fichier .anonymizer/terms.txt créé : à remplir." if created else ""
    return ("Garde : ACTIF." + extra +
            " Redémarrer la session Claude Code pour appliquer ce changement.")


PATH = {"type": "string", "description": "fichier ou dossier, relatif au projet"}
TOOLS = {
    "scan": (tool_scan, "Compte les valeurs sensibles d'un fichier ou dossier, sans rien afficher.",
             {"type": "object", "properties": {"path": PATH}, "required": ["path"]}),
    "mask": (tool_mask, "Écrit une copie masquée dans .anonymizer/masked/ (ou dans output).",
             {"type": "object", "properties": {"path": PATH, "output": PATH}, "required": ["path"]}),
    "restore": (tool_restore, "Réinjecte les vraies valeurs dans output, sur le poste. Ne renvoie pas le contenu.",
                {"type": "object", "properties": {"path": PATH, "output": PATH},
                 "required": ["path", "output"]}),
    "alias": (tool_alias, "Crée ou retrouve l'alias d'une valeur. Renvoie seulement l'alias.",
              {"type": "object", "properties": {
                  "value": {"type": "string"},
                  "category": {"type": "string", "description": "EMAIL, HOST, TERM, SECRET…"}},
               "required": ["value"]}),
    "guard_status": (tool_guard_status, "Indique si le garde data-anonymizer est actif sur le projet.",
                     {"type": "object", "properties": {}}),
    "guard_enable": (tool_guard_enable, "Active le garde sur le projet (hooks dans .claude/settings.local.json).",
                     {"type": "object", "properties": {}}),
}


def reply(mid, result=None, error=None):
    msg = {"jsonrpc": "2.0", "id": mid}
    if error is not None:
        msg["error"] = error
    else:
        msg["result"] = result
    return msg


def handle(msg):
    method, mid = msg.get("method"), msg.get("id")
    if method == "initialize":
        return reply(mid, {"protocolVersion": PROTOCOL, "capabilities": {"tools": {}},
                           "serverInfo": {"name": "data-anonymizer", "version": "1.0.0"}})
    if mid is None:                              # notifications : aucune réponse
        return None
    if method == "ping":
        return reply(mid, {})
    if method == "tools/list":
        return reply(mid, {"tools": [{"name": n, "description": d, "inputSchema": s}
                                     for n, (_, d, s) in TOOLS.items()]})
    if method == "tools/call":
        params = msg.get("params") or {}
        name, args = params.get("name"), params.get("arguments") or {}
        if name not in TOOLS:
            return reply(mid, error={"code": -32602, "message": f"outil inconnu : {name}"})
        try:
            text = TOOLS[name][0](args)
            return reply(mid, {"content": [{"type": "text", "text": text}], "isError": False})
        except (Exception, SystemExit) as exc:   # SystemExit : erreurs de toggle.py, sans arrêter le serveur
            if not isinstance(exc, (SystemExit, ValueError)):   # erreurs attendues : pas de trace
                traceback.print_exc(file=sys.stderr)
            return reply(mid, {"content": [{"type": "text", "text": f"Erreur : {exc}"}],
                               "isError": True})
    return reply(mid, error={"code": -32601, "message": f"méthode non gérée : {method}"})


def main():
    sys.stdin.reconfigure(encoding="utf-8")
    sys.stdout.reconfigure(encoding="utf-8", newline="\n")   # JSON-RPC : une ligne par message, LF
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            resp = handle(json.loads(line))
        except json.JSONDecodeError:
            resp = reply(None, error={"code": -32700, "message": "JSON invalide"})
        if resp is not None:
            print(json.dumps(resp, ensure_ascii=False), flush=True)


if __name__ == "__main__":
    main()
