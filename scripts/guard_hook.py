#!/usr/bin/env python3
"""Garde local pour Claude Code : empêche les valeurs sensibles de quitter le poste.

Appelé par les hooks (voir assets/settings.hooks.example.json) :
  guard_hook.py prompt   UserPromptSubmit : bloque un message contenant des valeurs sensibles
                         et propose sa version anonymisée
  guard_hook.py pre      PreToolUse : refuse la lecture en clair d'un fichier sensible
                         (une copie anonymisée est préparée), les commandes qui affichent
                         des fichiers sans masquage, et les envois externes contenant
                         des valeurs sensibles

Tout se passe en local. Les messages produits ne contiennent jamais de valeur réelle.
"""
import fnmatch
import json
import os
import re
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import anonymize as A  # noqa: E402

# Commandes Unix : sensibles à la casse (sinon « HEAD » de git serait pris pour « head »).
# Cmdlets PowerShell : insensibles à la casse.
READERS = re.compile(
    r"(?<![\w-])(cat|bat|type|more|less|head|tail|grep|egrep|rg|findstr|sed|awk|strings|xxd|od"
    r"|gc|sls|sqlite3|psql|mysql|sqlcmd|mongosh"
    r"|(?i:get-content|select-string|import-csv)"
    r"|git\s+(?:show|diff|blame|grep|log\s+-p))(?![\w-])")
EXTERNAL = {"WebSearch", "WebFetch", "Artifact"}
# Fichiers qui lisent réellement le contenu (évalués sur la commande nettoyée des chaînes)
INTERPRETER_READ = re.compile(
    r"(?i)open\(|read_text|readallText|get-content|import-csv|readfilesync|sqlite3\.connect")
SKILL_DIR = Path(__file__).resolve().parent.parent   # la skill ne contient que des exemples fictifs


def strip_text(command):
    """Retire heredocs, here-strings et chaînes : leur contenu est du texte, pas une lecture."""
    command = re.sub(r"<<-?\s*['\"]?(\w+)['\"]?.*?\n\1\b", "", command, flags=re.S)
    command = re.sub(r"@'.*?'@|@\".*?\"@", "", command, flags=re.S)
    return re.sub(r"\"(?:[^\"\\]|\\.)*\"|'[^']*'", "\"\"", command)


def summary(stats):
    return ", ".join(f"{c}={n}" for c, n in sorted(stats.items()))


def deny(reason):
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": "[data-anonymizer] " + reason}}))
    sys.exit(0)


class Guard:
    def __init__(self, payload):
        self.root = Path(os.environ.get("CLAUDE_PROJECT_DIR") or payload.get("cwd") or ".").resolve()
        self.cwd = Path(payload.get("cwd") or self.root)
        self.vault_dir = self.root / ".anonymizer"
        self.mirror_dir = self.vault_dir / "masked"
        self.cfg = A.Config(None, self.vault_dir)

    def detect(self, text):
        stats = Counter()
        A.mask_text(text, A.Vault(self.vault_dir, persist=False), self.cfg, stats)
        return stats

    def resolve(self, raw):
        p = Path(raw)
        return (p if p.is_absolute() else self.cwd / p).resolve()

    def inside(self, path, parent):
        try:
            path.relative_to(parent)
            return True
        except ValueError:
            return False

    def rel(self, path):
        if self.inside(path, self.root):
            return path.relative_to(self.root).as_posix()
        return "_ext/" + re.sub(r"[:\\/]+", "/", str(path)).strip("/")

    def matches(self, path, patterns):
        rel = self.rel(path)
        return any(fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(path.as_posix(), pat)
                   for pat in patterns)

    def mirror(self, path, text):
        """Crée ou rafraîchit la copie anonymisée, sans écraser un miroir plus récent."""
        dest = self.mirror_dir / self.rel(path)
        if not dest.exists() or dest.stat().st_mtime < path.stat().st_mtime:
            vault = A.Vault(self.vault_dir)
            masked = A.mask_text(text, vault, self.cfg, Counter())
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(masked, encoding="utf-8", newline="")
            vault.save()
        return dest

    # ------------------------------------------------------------- contrôles
    def check_file(self, raw):
        path = self.resolve(raw)
        if self.inside(path, SKILL_DIR):
            return
        if self.inside(path, self.vault_dir) and not self.inside(path, self.mirror_dir):
            deny("la table d'alias et le fichier de termes restent sur le poste : lecture refusée.")
        if self.inside(path, self.mirror_dir) or not path.is_file():
            return
        if self.matches(path, self.cfg.deny_paths):
            deny("ce chemin est déclaré deny-path : son contenu ne quitte pas le poste.")
        if self.matches(path, self.cfg.allow_paths):
            return
        text = A.read_text(path)
        if text is None:
            deny("fichier binaire ou trop volumineux : impossible de vérifier son contenu. "
                 "Le convertir en texte en local, ou l'autoriser avec allow-path: dans "
                 ".anonymizer/terms.txt.")
        stats = self.detect(text)
        if not stats:
            return
        dest = self.mirror(path, text)
        deny(f"ce fichier contient des valeurs sensibles ({summary(stats)}). Lire la copie "
             f"anonymisée : {dest} . Pour modifier le fichier, éditer cette copie puis lancer "
             f"anonymize.py restore \"{dest}\" -o \"{path}\".")

    def check_grep(self, tool_input):
        if tool_input.get("output_mode") != "content":
            return
        target = self.resolve(tool_input.get("path") or str(self.cwd))
        if self.inside(target, self.mirror_dir) or self.inside(target, SKILL_DIR):
            return
        if target.is_file():
            return self.check_file(str(target))
        deny("une recherche affichant le contenu d'un dossier non anonymisé peut exposer des "
             "valeurs sensibles. Utiliser output_mode files_with_matches puis Read, ou chercher "
             f"dans {self.mirror_dir}.")

    def check_shell(self, command):
        code = strip_text(command)
        secret_path = re.search(r"(?i)\.anonymizer[\\/]+(mapping\.json|terms\.txt)", command)
        if secret_path and (READERS.search(code) or INTERPRETER_READ.search(command)):
            deny("la table d'alias et le fichier de termes restent sur le poste.")
        if READERS.search(code) and not re.search(r"anonymize\.py\"?\s+(--vault\s+\S+\s+)?mask\b",
                                                  command):
            deny("cette commande affiche du contenu de fichier ou de base sans masquage. "
                 "Utiliser Read (contrôlé), ou terminer la commande par "
                 "`| python <skill>/scripts/anonymize.py mask -`.")

    def check_external(self, tool_name, tool_input):
        stats = self.detect(json.dumps(tool_input, ensure_ascii=False))
        if stats:
            deny(f"l'envoi vers {tool_name} contient des valeurs sensibles ({summary(stats)}). "
                 "Les remplacer par leurs alias ou une formulation générique.")


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "pre"
    payload = json.loads(sys.stdin.buffer.read().decode("utf-8") or "{}")
    guard = Guard(payload)

    if mode == "prompt":
        prompt = payload.get("prompt") or ""
        vault = A.Vault(guard.vault_dir)
        stats = Counter()
        masked = A.mask_text(prompt, vault, guard.cfg, stats)
        if stats:
            vault.save()
            print(json.dumps({"decision": "block", "reason": (
                f"[data-anonymizer] Message bloqué avant envoi : {summary(stats)}.\n"
                "Version anonymisée à renvoyer :\n\n" + masked)}))
        return 0

    tool = payload.get("tool_name", "")
    tool_input = payload.get("tool_input") or {}
    if tool in ("Read", "NotebookRead"):
        guard.check_file(tool_input.get("file_path") or tool_input.get("notebook_path") or "")
    elif tool == "Grep":
        guard.check_grep(tool_input)
    elif tool in ("Bash", "PowerShell"):
        guard.check_shell(tool_input.get("command") or "")
    elif tool in EXTERNAL or tool.startswith("mcp__"):
        guard.check_external(tool, tool_input)
    return 0


if __name__ == "__main__":
    sys.exit(main())
