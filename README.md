# PhishCase

**Des emails suspects aux dossiers résolus.**

PhishCase transforme [eml_analyzer](https://github.com/ninoseki/eml_analyzer) en espace d’investigation pour une équipe : dossiers, comptes, analyses persistantes et corrélation des IOC. Interface en français, backend FastAPI, frontend Vue et SQLite en mode WAL.

## Fonctionnalités de cette première version

- Connexion par session serveur de 8 heures, mots de passe scrypt, protection CSRF, limitation des tentatives de connexion et révocation des sessions.
- Trois rôles : administrateur (gestion des comptes), analyste (investigation) et lecture seule.
- Dossiers avec description, statut, priorité, responsable, notes et journal d’activité.
- Import EML / MSG limité à 20 Mo par fichier. Conservation du fichier original, SHA-256, résultat du moteur et état de traitement.
- Consultation des en-têtes, corps en texte inerte, verdicts et métadonnées des pièces jointes ; export JSON et téléchargement de l’original.
- Extraction des URL, domaines, IP, adresses email et SHA-256 des pièces jointes. Déduplication et liens vers les dossiers où chaque IOC a été rencontré.
- Qualification manuelle des IOC : à qualifier, bénin, suspect ou malveillant.
- Tableau de bord et journal des modifications.

## Démarrage avec l’image locale existante

Prérequis : Docker Compose et l’image locale `eml_analyzer:latest`.

```sh
docker compose -p phishcase -f compose.phishcase.yml up -d --build
docker compose -p phishcase -f compose.phishcase.yml exec phishcase python -m backend.investigation.store
```

La seconde commande crée un administrateur avec un mot de passe saisi interactivement (12 caractères minimum). Aucun compte ou mot de passe par défaut n’est livré dans le dépôt.

Ouvrir **http://localhost:8088**. Les données sont conservées dans le volume `phishcase_phishcase-data`. Un `down` conserve ce volume ; ne pas utiliser `down -v` si les données doivent être gardées.

Le Dockerfile `Dockerfile.phishcase` réutilise le moteur de l’image locale et reconstruit l’interface. Pour reconstruire entièrement la base depuis les sources :

```sh
docker build -t eml_analyzer:latest -f Dockerfile .
docker compose -p phishcase -f compose.phishcase.yml up -d --build
```

## Configuration et fonctionnement

| Variable | Usage |
| --- | --- |
| `INVESTIGATION_DB` | Fichier SQLite, `/data/phishcase.sqlite3` dans Compose |
| `PHISHCASE_PORT` | Port local publié, `8088` par défaut |
| `COOKIE_SECURE` | `true` par défaut dans le code ; `false` dans le Compose lié à `127.0.0.1` pour HTTP local |

Pour un déploiement partagé, fournir HTTPS et `COOKIE_SECURE=true`. L’instance représente **une seule équipe** : tous les comptes actifs peuvent consulter tous les dossiers, originaux et rapports. Les rôles contrôlent les modifications, pas la visibilité par dossier. Il n’y a pas encore d’isolation multi-organisation, de SSO/MFA, de politique de rétention ou de chiffrement applicatif des preuves.

Le traitement utilise le moteur existant dans la requête HTTP, avec une échéance de 180 secondes. Les états sont persistants et la liste des analyses se rafraîchit toutes les cinq secondes. Une interruption au redémarrage est marquée en échec ; relancer en important l’original. Le déploiement fourni lance un seul processus API. Une file de travaux durable et plusieurs workers ne sont pas encore implémentés.

Les sources HTML des emails sont affichées comme texte : les liens et ressources de l’email ne sont pas chargés dans l’interface. Un résultat « terminé » indique la fin du traitement, pas l’innocuité du message. Les moteurs d’enrichissement facultatifs peuvent être absents ; leurs résultats dépendent des services configurés. Les réglages historiques sont documentés dans [docs/UPSTREAM.md](docs/UPSTREAM.md). Aucun service tiers n’est configuré avec une clé dans ce fork.

Les listes sont plafonnées à 500 dossiers / analyses, 1 000 IOC et 200 événements par dossier. Pagination complète, recherche avancée, pièces jointes téléchargeables séparément et exports STIX sont des suites possibles.

## Tests

```sh
# Dans un environnement avec les dépendances backend du projet :
python -m unittest discover -s tests_workspace -v

cd frontend
npm ci
npm run build
```

Les tests PhishCase couvrent authentification/CSRF, rôles, révocation, protection des routes historiques, persistance, notes, analyse EML réelle, conservation de l’original, corrélation, échecs et limites d’import. Les tests historiques gardent leur fixture analyste authentifiée ; les contrôles de sécurité sont exercés séparément.

## Provenance

Fork de `ninoseki/eml_analyzer`, licence MIT conservée. Cette branche part du commit `093031e` correspondant au checkout local retrouvé avec l’image `eml_analyzer` SHA-256 `3d4535b1be5efe8045b8bcf4323b5ea105ccc16c5c3165e1435f627505113423`. Elle ne reprend pas automatiquement toutes les évolutions plus récentes de l’amont. Le workflow de déploiement Heroku historique est limité au dépôt d’origine.
