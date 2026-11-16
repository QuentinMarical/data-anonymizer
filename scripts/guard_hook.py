#!/usr/bin/env python3
"""Garde local pour Claude Code : empêche les valeurs sensibles de quitter le poste.

Appelé par les hooks (voir assets/settings.hooks.example.json) :
  guard_hook.py prompt   UserPromptSubmit : bloque un message contenant des valeurs sensibles
                         et propose sa version anonymisée
  guard_hook.py pre      PreToolUse : Read/Grep/Glob/Write/Edit/Bash/PowerShell et envois externes

Limite connue : un hook PreToolUse ne voit pas la sortie d'une commande. Un contrôle
de sortie n'est possible qu'après coup (PostToolUse), trop tard pour empêcher l'envoi.
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

SKILL_DIR = Path(__file__).resolve().parent.parent   # la skill ne contient que des exemples fictifs

# Commandes Unix : sensibles à la casse (sinon « HEAD » de git serait pris pour « head »).
# Cmdlets PowerShell : insensibles à la casse.
READERS = re.compile(
    r"(?<![\w-])(cat|bat|type|more|less|head|tail|grep|egrep|rg|findstr|sed|awk|strings|xxd|od"
    r"|gc|sls|sqlite3|psql|mysql|sqlcmd|mongosh"
    r"|(?i:get-content|select-string|import-csv)"
    r"|git\s+(?:show|diff|blame|grep|log\s+-p))(?![\w-])")
# Lecture de fichier par un interpréteur ou un outil de données, hors masquage
INTERPRETER_READ = re.compile(
    r"(?i)open\(|read_text|readallText|get-content|import-csv|readfilesync|sqlite3\.connect"
    r"|(?<![\w-])(?:jq|yq)\s+(?!-)\S")
CHAIN = re.compile(r"&&|\|\||;")
# Sortie entièrement masquée : le masquage doit être le dernier maillon du pipe
MASK_TAIL = re.compile(r"\|\s*python3?\s+\S*anonymize\.py\"?\s+(?:--vault\s+\S+\s+)?mask\s+-\s*$")
SECRET_PATH = re.compile(r"(?i)\.anonymizer[\\/]+(mapping\.json|terms\.txt)")


def summary(stats):
    return ", ".join(f"{c}={n}" for c, n in sorted(stats.items()))


def deny(reason):
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": "[data-anonymizer] " + reason}}))
    sys.exit(0)


def strip_heredoc(command):
    """Retire le contenu des heredocs : c'est du texte, pas une commande."""
    return re.sub(r"<<-?\s*['\"]?(\w+)['\"]?.*?\n\1\b", "", command, flags=re.S)


def strip_text(command):
    """Retire heredocs, here-strings et chaînes : il ne reste que les commandes."""
    command = strip_heredoc(command)
    command = re.sub(r"@'.*?'@|@\".*?\"@", "", command, flags=re.S)
    return re.sub(r"\"(?:[^\"\\]|\\.)*\"|'[^']*'", "\"\"", command)


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

    # ------------------------------------------------------------- lecture
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

    def check_glob(self, tool_input):
        """Les noms de fichiers aussi peuvent contenir des noms de clients : on les contrôle."""
        base = self.resolve(tool_input.get("path") or str(self.cwd))
        if not base.is_dir() or self.inside(base, SKILL_DIR):
            return
        try:
            hits = [p for _, p in zip(range(20001), base.glob(tool_input.get("pattern") or "*"))]
        except (ValueError, NotImplementedError):
            return
        if len(hits) > 20000:
            deny("plus de 20 000 résultats : le contrôle des noms ne serait pas complet. "
                 "Préciser le motif.")
        sample, count = Counter(), 0
        for p in hits:
            stats = self.detect(p.relative_to(base).as_posix())
            if self.matches(p, self.cfg.deny_paths):
                stats["DENY-PATH"] += 1
            if stats:
                count += 1
                sample.update(stats)
        if count:
            deny(f"{count} chemin(s) contiennent des valeurs sensibles dans leur nom "
                 f"({summary(sample)}) ; la liste n'est pas affichée. Préciser un motif plus "
                 "restreint qui ne les concerne pas.")

    # ------------------------------------------------------------- écriture
    def check_write(self, tool, tool_input):
        """Écrire des alias est permis. Écrire des valeurs en clair, ou écraser un fichier
        qui contient des valeurs réelles, ne l'est pas."""
        path = self.resolve(tool_input.get("file_path") or "")
        if self.inside(path, self.vault_dir) and not self.inside(path, self.mirror_dir):
            deny("la table d'alias et le fichier de termes ne sont pas modifiables par l'agent.")
        if self.inside(path, self.mirror_dir) or self.inside(path, SKILL_DIR):
            return
        if tool == "Edit":
            new_text = tool_input.get("new_string") or ""
        else:
            new_text = tool_input.get("content") or ""
        stats = self.detect(new_text)
        if stats:
            deny(f"le texte écrit contient des valeurs sensibles en clair ({summary(stats)}). "
                 "Écrire les alias __ANON_…__ : les vraies valeurs seront réinjectées par restore.")
        if path.is_file():
            text = A.read_text(path)
            if text is None or self.detect(text):
                deny("ce fichier contient des valeurs réelles : ne pas le modifier directement. "
                     "Éditer la copie anonymisée dans .anonymizer/masked/, puis lancer "
                     f"anonymize.py restore \"{self.mirror_dir}\\…\" -o \"{path}\".")

    # ------------------------------------------------------------- shell
    def check_shell(self, command):
        body = strip_heredoc(command)      # texte d'un heredoc : pas une lecture
        code = strip_text(command)         # sans chaînes : seules les commandes restent
        if SECRET_PATH.search(command) and (READERS.search(code) or INTERPRETER_READ.search(body)):
            deny("la table d'alias et le fichier de termes restent sur le poste.")
        chained = CHAIN.search(code) is not None
        if MASK_TAIL.search(command.strip()) and not chained:
            return                         # la sortie est masquée avant de revenir
        if READERS.search(code):
            if chained:
                deny("une commande de lecture est chaînée avec d'autres : chaque lecture doit "
                     "être seule, ou terminée par `| python <skill>/scripts/anonymize.py mask -`.")
            deny("cette commande affiche du contenu de fichier ou de base sans masquage. "
                 "Utiliser Read (contrôlé), ou terminer la commande par "
                 "`| python <skill>/scripts/anonymize.py mask -`.")
        if INTERPRETER_READ.search(body):
            deny("lecture de fichier par un interpréteur ou un outil de données sans masquage. "
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
    elif tool == "Glob":
        guard.check_glob(tool_input)
    elif tool in ("Write", "Edit"):
        guard.check_write(tool, tool_input)
    elif tool in ("Bash", "PowerShell"):
        guard.check_shell(tool_input.get("command") or "")
    elif tool in ("WebSearch", "WebFetch", "Artifact") or tool.startswith("mcp__"):
        guard.check_external(tool, tool_input)
    return 0


if __name__ == "__main__":
    sys.exit(main())
