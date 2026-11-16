#!/usr/bin/env python3
"""Active ou désactive le garde data-anonymizer dans un projet, sans dépendance externe.

  toggle.py [--project DOSSIER] on | off | status | toggle

Ne modifie que les hooks pointant vers guard_hook.py dans .claude/settings.local.json.
Les autres hooks, permissions et réglages sont conservés. Les fichiers .anonymizer/ ne
sont jamais supprimés. Après on ou off, redémarrer la session Claude Code (/exit puis claude)
pour que le fichier soit rechargé.
"""
import argparse
import json
import os
import shutil
import sys
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
SKILL = SCRIPTS.parent
GUARD = SCRIPTS / "guard_hook.py"
TEMPLATE = SKILL / "assets" / "settings.hooks.example.json"
TERMS_EXAMPLE = SKILL / "assets" / "terms.example.txt"
MARKER = "guard_hook.py"
RESTART = "Redémarrer la session Claude Code (/exit puis claude) pour appliquer ce changement."


def python_command():
    """python sous Windows, python3 sous Linux et macOS (python si python3 est absent)."""
    if sys.platform == "win32":
        return "python"
    return "python3" if shutil.which("python3") else "python"


def settings_path(project):
    return Path(project) / ".claude" / "settings.local.json"


def load(path):
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8") or "{}")
    except json.JSONDecodeError as exc:
        raise SystemExit(f"settings.local.json invalide, rien n'a été modifié : {exc}")
    if not isinstance(data, dict):
        raise SystemExit("settings.local.json n'est pas un objet JSON, rien n'a été modifié.")
    return data


def save(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def is_guard_hook(hook):
    return isinstance(hook, dict) and MARKER in str(hook.get("command", ""))


def strip_guard(hooks):
    """Retire les hooks du garde. Supprime les groupes et événements devenus vides,
    et seulement ceux-là : les autres entrées sont reprises telles quelles."""
    cleaned = {}
    for event, groups in hooks.items():
        if not isinstance(groups, list):
            cleaned[event] = groups
            continue
        kept_groups = []
        for group in groups:
            inner = group.get("hooks") if isinstance(group, dict) else None
            if not isinstance(inner, list):
                kept_groups.append(group)
                continue
            kept = [h for h in inner if not is_guard_hook(h)]
            if inner and not kept:
                continue                      # groupe qui ne contenait que le garde
            kept_groups.append({**group, "hooks": kept} if len(kept) != len(inner) else group)
        if kept_groups:
            cleaned[event] = kept_groups
    return cleaned


def build_guard_hooks():
    """Hooks du modèle, avec la commande réelle (interpréteur et chemin absolu)."""
    template = json.loads(TEMPLATE.read_text(encoding="utf-8"))["hooks"]
    interpreter = python_command()
    guard = GUARD.resolve().as_posix()
    result = {}
    for event, groups in template.items():
        new_groups = json.loads(json.dumps(groups))
        for group in new_groups:
            for hook in group.get("hooks", []):
                mode = hook["command"].split()[-1]     # « prompt » ou « pre »
                hook["command"] = f'{interpreter} "{guard}" {mode}'
        result[event] = new_groups
    return result


def is_active(project):
    data = load(settings_path(Path(project)))
    return MARKER in json.dumps(data.get("hooks") or {}, ensure_ascii=False)


def enable(project):
    project = Path(project)
    path = settings_path(project)
    data = load(path)
    hooks = data.get("hooks", {})
    if not isinstance(hooks, dict):
        raise SystemExit("« hooks » de settings.local.json n'est pas un objet, rien n'a été modifié.")
    hooks = strip_guard(hooks)                 # idempotent : on ne duplique jamais le garde
    for event, groups in build_guard_hooks().items():
        current = hooks.get(event, [])
        if not isinstance(current, list):
            raise SystemExit(f"hooks.{event} n'est pas une liste, rien n'a été modifié.")
        hooks[event] = current + groups
    data["hooks"] = hooks
    save(path, data)

    vault = project / ".anonymizer"
    vault.mkdir(parents=True, exist_ok=True)
    if not (vault / ".gitignore").exists():
        (vault / ".gitignore").write_text("*\n", encoding="utf-8")
    terms = vault / "terms.txt"
    created = False
    if not terms.exists():
        shutil.copyfile(TERMS_EXAMPLE, terms)
        created = True
    return created


def disable(project):
    path = settings_path(Path(project))
    if not path.exists() or not is_active(project):
        return False
    data = load(path)
    cleaned = strip_guard(data.get("hooks") or {})
    if cleaned:
        data["hooks"] = cleaned
    else:
        data.pop("hooks", None)
    save(path, data)
    return True


def toggle(project):
    if is_active(project):
        disable(project)
        return "off"
    enable(project)
    return "on"


def main(argv=None):
    parser = argparse.ArgumentParser(description="Active ou désactive le garde data-anonymizer.")
    parser.add_argument("--project", default=os.getcwd(), help="dossier du projet (défaut : ici)")
    parser.add_argument("action", choices=["on", "off", "status", "toggle"])
    args = parser.parse_args(argv)
    project = Path(args.project).resolve()

    if args.action == "status":
        print("Garde : ACTIF" if is_active(project) else "Garde : INACTIF")
        print(f"Projet : {project}")
        return 0

    if args.action == "on":
        created = enable(project)
        print("Garde : ACTIF")
        if created:
            print("Fichier de termes créé : .anonymizer/terms.txt (à remplir)")
    elif args.action == "off":
        changed = disable(project)
        print("Garde : INACTIF" if changed else "Garde : déjà inactif")
    else:
        result = toggle(project)
        print("Garde : ACTIF" if result == "on" else "Garde : INACTIF")
    print(f"Projet : {project}")
    print(RESTART)
    return 0


if __name__ == "__main__":
    sys.exit(main())
