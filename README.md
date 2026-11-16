# data-anonymizer

Skill Claude Code qui empêche les données personnelles, professionnelles et sensibles (données client, e-mails, téléphones, IBAN, secrets, hôtes intranet, noms de clients ou de projets) de quitter le poste.

- Les valeurs réelles restent sur le poste ; l'agent ne voit que des alias.
- Une table d'alias locale (dans le dossier `.anonymizer/` du projet, jamais lue par l'agent) permet de réinjecter les vraies valeurs en local avec `restore`.
- Un garde local (hooks `UserPromptSubmit` et `PreToolUse`) bloque réellement les messages, lectures et envois contenant des valeurs sensibles.

## Installation

1. Copier ce dossier dans le projet, par exemple `.claude/skills/data-anonymizer/`, ou dans un dossier de votre choix.
2. Fusionner `assets/settings.hooks.example.json` dans `.claude/settings.local.json` du projet, en remplaçant le chemin par celui de la skill.
3. Créer le fichier de termes du dossier `.anonymizer/` à partir de `assets/terms.example.txt` et le remplir (noms de clients, de projets, domaines internes).
4. Exclure le dossier `.anonymizer/` de git (le dossier contient déjà son propre `.gitignore`).

## Commandes

```bash
python scripts/anonymize.py scan <chemin>
python scripts/anonymize.py mask <chemin> --terms termes.txt
python scripts/anonymize.py restore <fichier> -o <sortie>
python scripts/anonymize.py alias "Nom du client"
```

Python 3, sans dépendance.

## Limites

La détection repose sur des motifs et sur le fichier de termes : une donnée ni reconnue ni déclarée passe en clair. Le garde protège contre les fuites accidentelles, ce n'est pas un pare-feu. Voir `SKILL.md` et `references/categories.md`.
