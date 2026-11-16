---
name: data-anonymizer
description: Empêche les données personnelles, professionnelles et sensibles (données client, e-mails, téléphones, IBAN, secrets, adresses et hôtes intranet, noms de clients ou de projets) de quitter le poste de l'utilisateur. Les valeurs réelles restent en local ; l'agent IA ne voit et n'envoie que des alias tenus dans une table locale, puis les vraies valeurs sont réinjectées sur le poste, ce qui permet de créer un programme ou un fichier qui les contient. À activer dès qu'un projet contient des données réelles ou confidentielles, avant de lire des exports, logs, CSV, configurations ou dumps, avant toute recherche web, appel d'API ou de connecteur, publication ou partage, et quand l'utilisateur parle d'anonymiser, masquer, pseudonymiser, alias, RGPD, confidentialité, données client ou fuite de données.
---

# Data Anonymizer

## Principe

Tout ce que l'agent lit ou écrit transite par le serveur du modèle. Une donnée sensible lue en clair a donc déjà quitté le poste. La règle est par conséquent :

- **Sur le poste** : les fichiers contiennent les vraies valeurs.
- **Côté agent IA** (contexte, réponses, recherches, appels d'outils externes) : uniquement des alias du type `__ANON_HOST_001__`.
- **Entre les deux** : une table d'alias locale, `.anonymizer/mapping.json`, que l'agent ne lit jamais. « Cette donnée, en local, a pour alias ce jeton côté serveur. »

Cela ne bloque pas le travail : l'agent écrit le programme avec les alias, et la commande `restore` réinjecte les vraies valeurs sur le poste.

## Deux niveaux de protection

1. **Le garde local (hooks)** : un script exécuté par Claude Code sur le poste, avant chaque message et chaque appel d'outil. Il bloque réellement, indépendamment de la bonne volonté de l'agent. C'est le niveau à activer pour un projet contenant des données client. Voir « Activer le garde ».
2. **La discipline de l'agent** (ce document) : utile partout, y compris sans hooks, mais ce n'est qu'une consigne.

## Ce que fait le garde

| Événement | Comportement |
|---|---|
| Message de l'utilisateur contenant une valeur sensible | Bloqué avant envoi. La version anonymisée du message est affichée pour être renvoyée, et les alias sont enregistrés dans la table. |
| Lecture (`Read`) d'un fichier contenant des valeurs sensibles | Refusée. Une copie anonymisée est créée dans `.anonymizer/masked/` et son chemin est indiqué. |
| Lecture de la table d'alias ou du fichier de termes | Toujours refusée. |
| Lecture d'un chemin déclaré `deny-path:` | Toujours refusée, sans copie. |
| Fichier binaire ou trop volumineux | Refusé, sauf chemin déclaré `allow-path:`. |
| `Grep` affichant le contenu d'un dossier non anonymisé | Refusé. Utiliser `files_with_matches` puis `Read`, ou chercher dans le miroir. |
| Commande shell qui affiche du contenu (`cat`, `grep`, `Get-Content`, `git diff`, client SQL…) | Refusée, sauf si elle se termine par `| python …/anonymize.py mask -` (sans chaînage `&&`, `;`, `||`). |
| Lecture de fichier par un interpréteur ou un outil de données (`python -c "open(…)"`, `jq . fichier`) | Refusée, sauf pipe final vers `mask -`. Les tests, builds et `git status` ne sont pas concernés. |
| `Glob` dont des noms de fichiers contiennent des valeurs sensibles | Refusé ; la liste n'est pas affichée. |
| `Write` / `Edit` contenant des valeurs en clair | Refusé. Écrire les alias `__ANON_…__` est autorisé. |
| `Write` / `Edit` sur un fichier qui contient déjà des valeurs réelles | Refusé. Passer par la copie dans `.anonymizer/masked/` puis `restore`. |
| Recherche web, récupération d'URL, connecteur MCP, publication contenant une valeur sensible | Refusé. |

Quand le garde refuse une action, suivre l'indication donnée dans le message de refus. Ne jamais chercher à le contourner par un autre outil.

## Workflow de l'agent

### Lire

Lire la copie anonymisée indiquée par le garde. Sans garde actif, la créer soi-même avant toute lecture :

```bash
python <dossier-de-la-skill>/scripts/anonymize.py mask <fichier-ou-dossier>
```

Le script n'affiche que des compteurs. La même valeur reçoit toujours le même alias : jointures, dédoublonnages et comptages restent justes. La structure (chemins d'URL, ports, noms de colonnes) est conservée.

### Modifier un fichier existant qui contient des valeurs sensibles

Éditer la copie anonymisée dans `.anonymizer/masked/`, puis réinjecter vers le fichier d'origine :

```bash
python <dossier-de-la-skill>/scripts/anonymize.py restore <copie> -o <fichier-d-origine>
```

### Créer un fichier qui doit contenir de vraies valeurs

L'écrire avec les alias, puis :

```bash
python <dossier-de-la-skill>/scripts/anonymize.py restore <fichier> --in-place
```

Un code de sortie 1 signale des alias inconnus : le dire à l'utilisateur. Après restauration, ne pas relire le fichier en clair.

### Exécuter une commande dont la sortie peut contenir des données

```bash
<commande> | python <dossier-de-la-skill>/scripts/anonymize.py mask -
```

### Parler à l'utilisateur, chercher sur le web, mémoriser

Toujours avec les alias ou une formulation générique (« l'hôte de l'API interne »). Jamais de valeur réelle dans une réponse, une requête, un titre, un message de commit ou la mémoire persistante.

## Ce que fait l'utilisateur

- **Déclarer ce que les motifs ne devinent pas** dans `.anonymizer/terms.txt` (modèle : `assets/terms.example.txt`) : noms de clients, de projets, de personnes, domaines internes, dossiers interdits. C'est indispensable pour les données client en texte libre.
- **Obtenir un alias sans rien envoyer**, depuis son propre terminal (pas depuis la conversation) :

```bash
python <dossier-de-la-skill>/scripts/anonymize.py alias "Nom du client"
```

- **Consulter la table** : ouvrir `.anonymizer/mapping.json` dans son éditeur.

## Activer le garde

À faire par projet, sur demande de l'utilisateur uniquement :

1. Copier le contenu de `assets/settings.hooks.example.json` dans `.claude/settings.local.json` du projet, en le fusionnant avec les hooks existants et en remplaçant le chemin par celui de la skill.
2. Créer `.anonymizer/terms.txt` avec l'utilisateur.
3. Démarrer une nouvelle session pour que les hooks soient chargés.
4. Vérifier : demander la lecture d'un fichier contenant une valeur déclarée ; elle doit être refusée avec le chemin d'une copie anonymisée.

`"onFailure": "block"` fait échouer fermé : si le script plante ou si Python est absent, l'action est bloquée plutôt qu'autorisée. Il ne protège que contre un hook qui ne démarre pas, pas contre une décision de l'agent.

**Commande Python** : les hooks appellent `python`. Sous Windows, c'est généralement la bonne commande. Sous Linux et macOS, il faut souvent `python3` : remplacer `python` par `python3` dans le fichier de hooks avant de l'activer. Si la commande est introuvable, l'action est bloquée.

## Limites à annoncer à l'utilisateur

- La détection repose sur des motifs et sur le fichier de termes. Une donnée ni reconnue ni déclarée passe en clair. Pour un dossier entier de données client, utiliser `deny-path:`.
- Le contrôle des commandes shell est une liste de commandes et de lectures connues, pas une analyse complète : un programme qui affiche lui-même des données (script, test, serveur) n'est pas filtré. Rediriger sa sortie vers `mask -`.
- Un hook `PreToolUse` ne voit pas la sortie d'une commande. Un contrôle de sortie (`PostToolUse`) arriverait trop tard : le résultat est déjà renvoyé au modèle. Seule une interdiction a priori protège réellement.
- Le garde protège contre les fuites accidentelles d'un agent coopératif. Ce n'est pas une barrière contre un programme malveillant ni un pare-feu réseau.
- Ce qui a été envoyé avant l'activation du garde est déjà parti.
- Images et PDF ne peuvent pas être anonymisés : ils sont refusés par défaut.

## Ressources

- `scripts/anonymize.py` : `mask`, `scan`, `restore`, `alias` (Python 3, sans dépendance).
- `scripts/guard_hook.py` : garde local appelé par les hooks.
- `assets/settings.hooks.example.json` : configuration des hooks à fusionner.
- `assets/terms.example.txt` : modèle de fichier de termes.
- `references/categories.md` : catégories détectées, faux positifs connus, ajout d'une catégorie.
