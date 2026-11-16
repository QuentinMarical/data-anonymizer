# Catégories détectées

Jeton : `__ANON_<CATÉGORIE>_<numéro>__`. Le format reste valide dans une chaîne, une URL, un chemin ou un identifiant.

| Catégorie | Ce qui est masqué | Ce qui reste en clair |
|---|---|---|
| `SECRET` | Blocs de clé privée, jetons à préfixe connu (`sk-`, `ghp_`, `github_pat_`, `glpat-`, `AKIA`, `xox?-`, JWT), valeur affectée à une clé nommée password, pwd, mdp, secret, token, api_key…, identifiants `user:motdepasse@` dans une URL | Appels de fonction, variables, identifiants de code purement alphabétiques (`self.password = password`) |
| `HOST` | Hôte d'une URL s'il est interne : IP privée, nom court sans point, suffixe `.local` `.lan` `.intranet` `.corp` `.internal` `.home` `.priv`, ou domaine déclaré par `domain:` ; nom d'hôte interne isolé ; serveur d'un chemin UNC | Hôtes publics, `localhost`, schéma, port, chemin et paramètres de l'URL |
| `IP` | IPv4 privées (10/8, 172.16/12, 192.168/16, lien local) | IP publiques, `127.0.0.1`, `0.0.0.0`, numéros de version |
| `EMAIL` | Toute adresse e-mail | Adresses listées par `allow:` |
| `PHONE` | Numéros français (`0X XX XX XX XX`, `+33…`) | Autres formats internationaux |
| `IBAN` | IBAN dont la clé modulo 97 est valide | Suites ressemblantes invalides |
| `CARD` | Numéros de 13 à 19 chiffres valides selon Luhn | Autres suites de chiffres |
| `NIR` | Numéro de sécurité sociale français (13 ou 15 chiffres) | |
| `USER` | Nom de compte dans `C:\Users\<nom>`, `/home/<nom>`, `/Users/<nom>` | `Public`, `Default`, `Shared` |
| `TERM` | Termes littéraux du fichier de termes, sans tenir compte de la casse | |

## Où vit chaque forme de la donnée

1. Fichier sur le poste : vraie valeur, obtenue par `restore`, jamais par écriture directe de l'agent.
2. Contexte de l'agent, réponses, mémoire, résumés : alias ou description.
3. Recherche web, API, connecteur, publication : alias ou formulation générique.

## Directives du fichier de termes

| Ligne | Effet |
|---|---|
| `Un terme` | Remplacé par un alias `TERM` partout où il apparaît |
| `domain:societe.fr` | Tout hôte de ce domaine est traité comme interne |
| `allow:valeur` | Valeur jamais masquée |
| `deny-path:motif` | Le garde refuse toute lecture de ces chemins |
| `allow-path:motif` | Le garde laisse lire ces chemins sans contrôle |

Les motifs de chemin suivent la syntaxe `fnmatch` (`*`, `?`) et s'appliquent au chemin relatif à la racine du projet.

## Faux positifs et faux négatifs connus

- Un mot de passe non entouré de guillemets et composé uniquement de lettres n'est pas reconnu comme secret.
- Seul l'hôte d'une URL est masqué : un chemin qui contient un nom de client ou un identifiant doit être couvert par le fichier de termes.
- Noms de personnes, adresses postales, dates de naissance et texte libre ne sont pas détectés.
- Les téléphones hors format français ne sont pas détectés.
- Un nom court dans une URL (`http://redis:6379`) est considéré comme interne, y compris pour un nom de service Docker. Utiliser `allow:redis` si cela gêne.

## Ajouter une catégorie

Ajouter une entrée à la liste `RULES` de `scripts/anonymize.py` : catégorie en majuscules, expression régulière, numéro du groupe à masquer, validateur facultatif. Les trois premières règles sont les secrets et passent avant les URL ; les suivantes passent après. Tester avec `scan`, puis vérifier qu'un cycle `mask` puis `restore` redonne le fichier d'origine.
